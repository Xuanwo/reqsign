use std::fmt::{Debug, Display, Formatter};
use std::mem;
use std::str::FromStr;
use std::time::SystemTime;

use anyhow::{anyhow, Result};
use http::header::HeaderName;
use http::{HeaderMap, HeaderValue};
use log::debug;

use super::credential::Credential;
use super::loader::CredentialLoadChain;
use super::loader::RegionLoadChain;
use crate::hash::{hex_hmac_sha256, hex_sha256, hmac_sha256};
use crate::request::SignableRequest;
use crate::services::aws::loader::{CredentialLoad, RegionLoad};
use crate::time::{self, DATE, ISO8601};

#[derive(Default)]
pub struct Builder {
    service: String,
    region: String,
    credential: Credential,

    region_load: RegionLoadChain,
    credential_load: CredentialLoadChain,

    time: Option<SystemTime>,
}

impl Builder {
    pub fn service(&mut self, service: &str) -> &mut Self {
        self.service = service.to_string();
        self
    }

    pub fn region(&mut self, region: &str) -> &mut Self {
        self.region = region.to_string();
        self
    }

    pub fn region_loader(&mut self, region: RegionLoadChain) -> &mut Self {
        self.region_load = region;
        self
    }

    pub fn access_key(&mut self, access_key: &str) -> &mut Self {
        self.credential.set_access_key(access_key);
        self
    }

    pub fn secret_key(&mut self, secret_key: &str) -> &mut Self {
        self.credential.set_secret_key(secret_key);
        self
    }

    pub fn credential_loader(&mut self, credential: CredentialLoadChain) -> &mut Self {
        self.credential_load = credential;
        self
    }

    #[cfg(test)]
    pub fn time(&mut self, time: SystemTime) -> &mut Self {
        self.time = Some(time);
        self
    }

    pub async fn build(&mut self) -> Result<Signer> {
        // Try load region from env
        if self.region.is_empty() {
            let region = self.region_load.load_region().await?;
            if region.is_none() {
                return Err(anyhow!("region is empty"));
            }
            self.region = region.unwrap();
        }

        // Try load credential from env.
        // TODO: refactor logic here.
        if !self.credential.is_valid() {
            let cred = self.credential_load.load_credential().await?;
            if cred.is_none() {
                return Err(anyhow!("credential is empty"));
            }
            self.credential = cred.unwrap();
        }

        Ok(Signer {
            service: mem::take(&mut self.service),
            region: mem::take(&mut self.region),
            credential: mem::take(&mut self.credential),
            credential_load: mem::take(&mut self.credential_load),
            time: self.time,
        })
    }
}

pub struct Signer {
    service: String,
    region: String,

    credential: Credential,
    credential_load: CredentialLoadChain,

    time: Option<SystemTime>,
}

impl Signer {
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub async fn load_credential(&mut self) -> Result<()> {
        if let Some(cred) = self.credential_load.load_credential().await? {
            self.credential = cred;
            Ok(())
        } else {
            Err(anyhow!("credential is empty"))
        }
    }

    async fn access_key_id(&mut self) -> Result<&str> {
        if self.credential.is_valid() {
            return Ok(self.credential.access_key());
        }

        self.load_credential().await?;

        // Credential must be valid after load.
        return Ok(self.credential.access_key());
    }

    async fn secret_access_key(&mut self) -> Result<&str> {
        if self.credential.is_valid() {
            return Ok(self.credential.secret_key());
        }

        self.load_credential().await?;

        // Credential must be valid after load.
        return Ok(self.credential.secret_key());
    }

    #[allow(dead_code)]
    async fn security_token(&mut self) -> Result<Option<&str>> {
        if self.credential.is_valid() {
            return Ok(self.credential.security_token());
        }

        self.load_credential().await?;

        // Credential must be valid after load.
        return Ok(self.credential.security_token());
    }

    pub async fn calculate(&mut self, req: &impl SignableRequest) -> Result<SignedOutput> {
        let canonical_req = CanonicalRequest::from(req, self.time)?;

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

        let region = self.region.clone();
        let service = self.service.clone();
        let secret_key = self.secret_access_key().await?;

        let signing_key = generate_signing_key(secret_key, canonical_req.time, &region, &service);
        let signature = hex_hmac_sha256(&signing_key, string_to_sign.as_bytes());

        Ok(SignedOutput {
            access_key_id: self.access_key_id().await?.to_string(),
            signed_time: canonical_req.time,
            signed_scope: scope,
            signed_headers: canonical_req.signed_headers,
            signature,
        })
    }

    pub fn apply(&mut self, sig: &SignedOutput, req: &mut impl SignableRequest) -> Result<()> {
        req.apply_header(
            HeaderName::from_static(super::constants::X_AMZ_DATE),
            &time::format(sig.signed_time, ISO8601),
        )?;
        req.apply_header(
            HeaderName::from_str(super::constants::X_AMZ_CONTENT_SHA_256)
                .expect("x_amz_content_sha_256 header name must be valid"),
            "UNSIGNED-PAYLOAD",
        )?;
        req.apply_header(
            http::header::AUTHORIZATION,
            &format!(
                "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
                sig.access_key_id,
                sig.signed_scope,
                sig.signed_headers.join(";"),
                sig.signature
            ),
        )?;

        Ok(())
    }

    pub async fn sign(&mut self, req: &mut impl SignableRequest) -> Result<()> {
        let sig = self.calculate(req).await?;
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
struct CanonicalRequest<'a> {
    method: &'a http::Method,
    path: &'a str,
    params: Option<String>,
    headers: http::HeaderMap,

    time: SystemTime,
    signed_headers: Vec<HeaderName>,
    content_sha256: &'a str,
}

impl<'a> CanonicalRequest<'a> {
    pub fn from(req: &impl SignableRequest, time: Option<SystemTime>) -> Result<CanonicalRequest> {
        let now = time.unwrap_or_else(SystemTime::now);

        let (signed_headers, canonical_headers) = Self::headers(req, now)?;

        Ok(CanonicalRequest {
            method: req.method(),
            path: req.path(),
            params: Self::params(),
            headers: canonical_headers,

            time: now,
            signed_headers,
            // ## TODO
            //
            // we need to support get payload hash. For now, we will implement
            // unsigned payload at first.
            content_sha256: "UNSIGNED-PAYLOAD",
        })
    }

    pub fn headers(
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
            let header = HeaderValue::try_from(req.authority())
                .expect("endpoint must contain valid header characters");
            canonical_headers.insert(http::header::HOST, header);
        }

        // Insert DATE header if not present.
        if canonical_headers
            .get(HeaderName::from_static(super::constants::X_AMZ_DATE))
            .is_none()
        {
            let date_header = HeaderValue::try_from(time::format(now, ISO8601))
                .expect("date is valid header value");
            canonical_headers.insert(
                HeaderName::from_static(super::constants::X_AMZ_DATE),
                date_header,
            );
        }

        // Insert X_AMZ_CONTENT_SHA_256 header if not present.
        if canonical_headers
            .get(HeaderName::from_static(
                super::constants::X_AMZ_CONTENT_SHA_256,
            ))
            .is_none()
        {
            canonical_headers.insert(
                HeaderName::from_static(super::constants::X_AMZ_CONTENT_SHA_256),
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

impl<'a> Display for CanonicalRequest<'a> {
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
    access_key_id: String,
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
