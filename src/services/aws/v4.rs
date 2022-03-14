use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use std::time::SystemTime;

use anyhow::Result;
use http::header::HeaderName;
use http::{HeaderMap, HeaderValue};
use log::debug;

use crate::hash::{hex_hmac_sha256, hex_sha256, hmac_sha256};
use crate::request::SignableRequest;
use crate::time::{self, DATE, ISO8601};

#[derive(Default)]
pub struct Builder {
    access_key: String,
    secret_key: String,
    #[allow(dead_code)]
    security_token: Option<String>,

    region: String,
    service: String,

    time: Option<SystemTime>,
}

impl Builder {
    pub fn access_key(&mut self, access_key: &str) -> &mut Self {
        self.access_key = access_key.to_string();
        self
    }

    pub fn secret_key(&mut self, secret_key: &str) -> &mut Self {
        self.secret_key = secret_key.to_string();
        self
    }

    pub fn region(&mut self, region: &str) -> &mut Self {
        self.region = region.to_string();
        self
    }

    pub fn service(&mut self, service: &str) -> &mut Self {
        self.service = service.to_string();
        self
    }

    #[cfg(test)]
    pub fn time(&mut self, time: SystemTime) -> &mut Self {
        self.time = Some(time);
        self
    }

    pub fn build(&mut self) -> Signer {
        Signer {
            access_key: self.access_key.clone(),
            secret_key: self.secret_key.clone(),
            security_token: None,
            region: self.region.clone(),
            service: self.service.clone(),
            time: self.time,
        }
    }
}

#[derive(Clone)]
pub struct Signer {
    access_key: String,
    secret_key: String,
    #[allow(dead_code)]
    security_token: Option<String>,

    region: String,
    service: String,

    time: Option<SystemTime>,
}

impl Signer {
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn calculate(&self, req: &impl SignableRequest) -> Result<SignedOutput> {
        let canonical_req = CanonicalRequest::from(self, req)?;

        let encoded_req = hex_sha256(canonical_req.to_string().as_bytes());

        // Scope: "20220313/<region>/<service>/aws4_request"
        let scope = format!(
            "{}/{}/{}/aws4_request",
            time::format(canonical_req.time, DATE),
            self.region,
            self.service
        );
        debug!("scope: {scope}");

        // StringToSign:
        //
        // AWS4-HMAC-SHA256
        // 20220313T072004Z
        // 20220313/<region>/<service>/aws4_request
        // <hashed_canonical_request>
        let string_to_sign = {
            use std::fmt::Write;

            let mut f = String::new();
            writeln!(f, "AWS4-HMAC-SHA256")?;
            writeln!(f, "{}", time::format(canonical_req.time, ISO8601))?;
            writeln!(f, "{}", &scope)?;
            write!(f, "{}", &encoded_req)?;
            f
        };
        debug!("string to sign: {string_to_sign}");

        let signing_key = generate_signing_key(
            &self.secret_key,
            canonical_req.time,
            &self.region,
            &self.service,
        );
        let signature = hex_hmac_sha256(&signing_key, string_to_sign.as_bytes());

        Ok(SignedOutput {
            signed_time: canonical_req.time,
            signed_scope: scope,
            signed_headers: canonical_req.signed_headers,
            signature,
        })
    }

    pub fn apply(&self, sig: &SignedOutput, req: &mut impl SignableRequest) -> Result<()> {
        req.apply_header(
            HeaderName::from_static(super::header::X_AMZ_DATE),
            &time::format(sig.signed_time, ISO8601),
        )?;
        req.apply_header(
            HeaderName::from_str(super::header::X_AMZ_CONTENT_SHA_256)
                .expect("x_amz_content_sha_256 header name must be valid"),
            "UNSIGNED-PAYLOAD",
        )?;
        req.apply_header(
            http::header::AUTHORIZATION,
            &format!(
                "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
                self.access_key,
                sig.signed_scope,
                sig.signed_headers.join(";"),
                sig.signature
            ),
        )?;

        Ok(())
    }

    pub fn sign(&self, req: &mut impl SignableRequest) -> Result<()> {
        let sig = self.calculate(req)?;
        self.apply(&sig, req)
    }
}

impl Debug for Signer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Signer {{ region: {}, service: {} }}",
            self.region, self.service
        )
    }
}

#[derive(Clone)]
struct CanonicalRequest {
    method: http::Method,
    path: String,
    params: Option<String>,
    headers: http::HeaderMap,

    time: SystemTime,
    signed_headers: Vec<HeaderName>,
    content_sha256: String,
}

impl CanonicalRequest {
    pub fn from(signer: &Signer, req: &impl SignableRequest) -> Result<Self> {
        let uri = req.uri();
        let path = uri.path();

        let now = signer.time.unwrap_or_else(SystemTime::now);

        let (signed_headers, canonical_headers) = Self::headers(signer, req, now)?;

        Ok(CanonicalRequest {
            method: req.method(),
            path: path.to_string(),
            params: Self::params(),
            headers: canonical_headers,

            time: now,
            signed_headers,
            // ## TODO
            //
            // we need to support get payload hash. For now, we will implement
            // unsigned payload at first.
            content_sha256: "UNSIGNED-PAYLOAD".to_string(),
        })
    }

    pub fn headers(
        _signer: &Signer,
        req: &impl SignableRequest,
        now: SystemTime,
    ) -> Result<(Vec<HeaderName>, HeaderMap)> {
        let mut canonical_headers = HeaderMap::with_capacity(req.headers().len());
        for (name, value) in req.headers().iter() {
            // Header names and values need to be normalized according to Step 4 of https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
            // Using append instead of insert means this will not clobber headers that have the same lowercased name
            canonical_headers.append(
                HeaderName::from_str(&name.as_str().to_lowercase())?,
                normalize_header_value(value),
            );
        }

        // Insert HOST header if not present.
        if canonical_headers.get(&http::header::HOST).is_none() {
            let uri = req.uri();
            let authority = uri
                .authority()
                .expect("request uri authority must be set for signing");
            let header = HeaderValue::try_from(authority.as_str())
                .expect("endpoint must contain valid header characters");
            canonical_headers.insert(http::header::HOST, header);
        }

        // Insert DATE header if not present.
        if canonical_headers
            .get(HeaderName::from_static(super::header::X_AMZ_DATE))
            .is_none()
        {
            let date_header = HeaderValue::try_from(time::format(now, ISO8601))
                .expect("date is valid header value");
            canonical_headers.insert(
                HeaderName::from_static(super::header::X_AMZ_DATE),
                date_header,
            );
        }

        // Insert X_AMZ_CONTENT_SHA_256 header if not present.
        if canonical_headers
            .get(HeaderName::from_static(
                super::header::X_AMZ_CONTENT_SHA_256,
            ))
            .is_none()
        {
            canonical_headers.insert(
                HeaderName::from_static(super::header::X_AMZ_CONTENT_SHA_256),
                HeaderValue::from_static("UNSIGNED-PAYLOAD"),
            );
        }

        // TODO: handle X_AMZ_CONTENT_SHA_256 header here.

        let mut signed_headers = Vec::with_capacity(canonical_headers.len());
        for (name, _) in &canonical_headers {
            // The user agent header should not be signed because it may be altered by proxies
            if name == http::header::USER_AGENT {
                continue;
            }
            signed_headers.push(name.clone());
        }

        signed_headers.sort_by(|x, y| x.as_str().cmp(y.as_str()));

        Ok((signed_headers, canonical_headers))
    }

    pub fn params() -> Option<String> {
        None
    }
}

impl Display for CanonicalRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.method)?;
        writeln!(f, "{}", self.path)?;
        writeln!(f, "{}", self.params.as_ref().unwrap_or(&"".to_string()))?;
        for header in &self.signed_headers {
            let value = &self.headers[header];
            writeln!(
                f,
                "{}:{}",
                header.as_str(),
                value.to_str().expect("header value must be valid")
            )?;
        }
        writeln!(f)?;
        writeln!(
            f,
            "{}",
            self.signed_headers
                .iter()
                .map(|v| v.as_str())
                .collect::<Vec<&str>>()
                .join(";")
        )?;
        write!(f, "{}", self.content_sha256)?;

        Ok(())
    }
}

pub struct SignedOutput {
    signed_time: SystemTime,
    signed_scope: String,
    signed_headers: Vec<HeaderName>,
    signature: String,
}

impl SignedOutput {
    pub fn signature(&self) -> String {
        self.signature.clone()
    }
}

fn normalize_header_value(header_value: &HeaderValue) -> HeaderValue {
    let bs = header_value.as_bytes();

    let starting_index = bs.iter().position(|b| *b != b' ').unwrap_or(0);
    let ending_offset = bs.iter().rev().position(|b| *b != b' ').unwrap_or(0);
    let ending_index = bs.len() - ending_offset;

    // This can't fail because we started with a valid HeaderValue and then only trimmed spaces
    HeaderValue::from_bytes(&bs[starting_index..ending_index]).expect("invalid header value")
}

pub fn generate_signing_key(
    secret: &str,
    time: SystemTime,
    region: &str,
    service: &str,
) -> Vec<u8> {
    // Sign secret
    let secret = format!("AWS4{}", secret);
    // Sign date
    let sign_date = hmac_sha256(secret.as_bytes(), time::format(time, DATE).as_bytes());
    // Sign region
    let sign_region = hmac_sha256(sign_date.as_slice(), region.as_bytes());
    // Sign service
    let sign_service = hmac_sha256(sign_region.as_slice(), service.as_bytes());
    // Sign request
    let sign_request = hmac_sha256(sign_service.as_slice(), "aws4_request".as_bytes());

    sign_request
}
