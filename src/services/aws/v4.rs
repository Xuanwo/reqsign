use std::fmt::{Debug, Display, Formatter};
use std::mem;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{anyhow, Result};
use http::header::HeaderName;
use http::{HeaderMap, HeaderValue};
use log::debug;
use tokio::sync::{OnceCell, RwLock};

use super::credential::Credential;
use super::loader::CredentialLoadChain;
use super::loader::RegionLoadChain;
use crate::hash::{hex_hmac_sha256, hex_sha256, hmac_sha256};
use crate::request::SignableRequest;
use crate::services::aws::loader::{
    CredentialLoad, EnvLoader, ProfileLoader, RegionLoad, WebIdentityTokenLoader,
};
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

    pub fn security_token(&mut self, security_token: &str) -> &mut Self {
        self.credential.set_security_token(Some(security_token));
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
        if self.region_load.is_empty() {
            self.region_load
                .push(EnvLoader::default())
                .push(ProfileLoader::default());
        }

        if self.credential_load.is_empty() {
            self.credential_load
                .push(EnvLoader::default())
                .push(ProfileLoader::default())
                .push(WebIdentityTokenLoader::default());
        }

        // Try load region from env
        if self.region.is_empty() {
            let region = self.region_load.load_region().await?;
            if region.is_none() {
                return Err(anyhow!("region is empty"));
            }
            self.region = region.unwrap();
        }

        Ok(Signer {
            service: mem::take(&mut self.service),
            region: mem::take(&mut self.region),
            credential: Arc::new(RwLock::new(OnceCell::new_with(Some(mem::take(
                &mut self.credential,
            ))))),
            credential_load: mem::take(&mut self.credential_load),
            time: self.time,
        })
    }
}

pub struct Signer {
    service: String,
    region: String,

    credential: Arc<RwLock<OnceCell<Credential>>>,
    credential_load: CredentialLoadChain,

    time: Option<SystemTime>,
}

impl Signer {
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Load credential via credential load chain specified while building.
    async fn credential(&self) -> Result<Credential> {
        // Return cached credential if it's valid.
        if let Some(cred) = self.credential.read().await.get() {
            if cred.is_valid() {
                return Ok(cred.clone());
            }
        }

        if let Some(cred) = self.credential_load.load_credential().await? {
            let mut lock = self.credential.write().await;
            // No matter the cell contains credential or not, we just take them
            // and drop them. So we can set the new value inside.
            let _ = lock.take();
            lock.set(cred.clone()).expect("cell must be empty");
            Ok(cred)
        } else {
            Err(anyhow!("credential is not found"))
        }
    }

    pub async fn calculate(&self, req: &impl SignableRequest) -> Result<SignedOutput> {
        let cred = self.credential().await?;

        let canonical_req = CanonicalRequest::from(req, self.time, &cred)?;
        debug!("canonical_req: {canonical_req}");

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
            cred.secret_key(),
            canonical_req.time,
            &self.region,
            &self.service,
        );
        let signature = hex_hmac_sha256(&signing_key, string_to_sign.as_bytes());

        Ok(SignedOutput {
            access_key_id: cred.access_key().to_string(),
            security_token: cred.security_token().map(|v| v.to_string()),
            signed_time: canonical_req.time,
            signed_scope: scope,
            signed_headers: canonical_req.signed_headers,
            signature,
        })
    }

    pub fn apply(&self, sig: &SignedOutput, req: &mut impl SignableRequest) -> Result<()> {
        req.apply_header(
            HeaderName::from_static(super::constants::X_AMZ_DATE),
            &time::format(sig.signed_time, ISO8601),
        )?;
        req.apply_header(
            HeaderName::from_static(super::constants::X_AMZ_CONTENT_SHA_256),
            "UNSIGNED-PAYLOAD",
        )?;

        // Set X_AMZ_SECURITY_TOKEN if we have security_token
        if let Some(token) = &sig.security_token {
            req.apply_header(
                HeaderName::from_static(super::constants::X_AMZ_SECURITY_TOKEN),
                token,
            )?;
        }

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

    pub async fn sign(&self, req: &mut impl SignableRequest) -> Result<()> {
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
    pub fn from<'b>(
        req: &'b impl SignableRequest,
        time: Option<SystemTime>,
        cred: &'b Credential,
    ) -> Result<CanonicalRequest<'b>> {
        let now = time.unwrap_or_else(SystemTime::now);

        let (signed_headers, canonical_headers) = Self::headers(req, now, cred)?;

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
        cred: &Credential,
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

        // Insert X_AMZ_SECURITY_TOKEN header if security token exists.
        if let Some(token) = cred.security_token() {
            let mut value = HeaderValue::from_str(token)?;
            // Set token value sensitive to valid leaking.
            value.set_sensitive(true);

            canonical_headers.insert(
                HeaderName::from_static(super::constants::X_AMZ_SECURITY_TOKEN),
                value,
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
    security_token: Option<String>,
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

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use anyhow::Result;
    use aws_sigv4;
    use aws_sigv4::http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
    };
    use aws_sigv4::SigningParams;

    use super::*;
    use crate::time::{PrimitiveDateTime, ISO8601};

    fn test_time() -> SystemTime {
        PrimitiveDateTime::parse("20220101T120000Z", ISO8601)
            .expect("test time must be valid")
            .assume_utc()
            .into()
    }

    fn test_request() -> http::Request<&'static str> {
        let mut req = http::Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "http://127.0.0.1:9000/hello"
            .parse()
            .expect("url must be valid");

        req
    }

    #[tokio::test]
    async fn test_calculate() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let mut req = test_request();

        let mut ss = SigningSettings::default();
        ss.percent_encoding_mode = PercentEncodingMode::Single;
        ss.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

        let sp = SigningParams::builder()
            .access_key("access_key_id")
            .secret_key("secret_access_key")
            .region("test")
            .service_name("s3")
            .time(test_time())
            .settings(ss)
            .build()
            .expect("signing params must be valid");

        let output = aws_sigv4::http_request::sign(
            SignableRequest::new(
                req.method(),
                req.uri(),
                req.headers(),
                SignableBody::UnsignedPayload,
            ),
            &sp,
        )
        .expect("signing must succeed");
        let (aws_sig, expect_sig) = output.into_parts();
        aws_sig.apply_to_request(&mut req);
        let expect_headers = req.headers();

        let mut req = test_request();

        let signer = Signer::builder()
            .access_key("access_key_id")
            .secret_key("secret_access_key")
            .region("test")
            .service("s3")
            .time(test_time())
            .build()
            .await?;

        let actual = signer.calculate(&req).await?;
        signer.apply(&actual, &mut req).expect("must apply success");

        assert_eq!(expect_sig, actual.signature());
        assert_eq!(expect_headers, req.headers());
        Ok(())
    }

    #[tokio::test]
    async fn test_calculate_with_token() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let mut req = test_request();

        let mut ss = SigningSettings::default();
        ss.percent_encoding_mode = PercentEncodingMode::Single;
        ss.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

        let sp = SigningParams::builder()
            .access_key("access_key_id")
            .secret_key("secret_access_key")
            .region("test")
            .security_token("security_token")
            .service_name("s3")
            .time(test_time())
            .settings(ss)
            .build()
            .expect("signing params must be valid");

        let output = aws_sigv4::http_request::sign(
            SignableRequest::new(
                req.method(),
                req.uri(),
                req.headers(),
                SignableBody::UnsignedPayload,
            ),
            &sp,
        )
        .expect("signing must succeed");
        let (aws_sig, expect_sig) = output.into_parts();
        aws_sig.apply_to_request(&mut req);
        let expect_headers = req.headers();

        let mut req = test_request();

        let signer = Signer::builder()
            .access_key("access_key_id")
            .secret_key("secret_access_key")
            .region("test")
            .security_token("security_token")
            .service("s3")
            .time(test_time())
            .build()
            .await?;

        let actual = signer.calculate(&req).await?;
        signer.apply(&actual, &mut req).expect("must apply success");

        assert_eq!(expect_sig, actual.signature());
        assert_eq!(expect_headers, req.headers());
        Ok(())
    }
}
