//! AWS service sigv4 signer

use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};
use std::mem;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::RwLock;

use anyhow::{anyhow, Result};
use http::header::HeaderName;
use http::{HeaderMap, HeaderValue};
use log::debug;
use percent_encoding::{percent_decode_str, utf8_percent_encode};

use super::constants::AWS_QUERY_ENCODE_SET;
use super::credential::Credential;
use super::loader::*;
use crate::hash::{hex_hmac_sha256, hex_sha256, hmac_sha256};
use crate::request::SignableRequest;
use crate::time::{self, format_date, format_iso8601, DateTime, Duration};

/// Builder for `Signer`.
#[derive(Default)]
pub struct Builder {
    service: Option<String>,
    region: Option<String>,
    credential: Credential,

    region_load: RegionLoadChain,
    credential_load: CredentialLoadChain,

    allow_anonymous: bool,

    time: Option<DateTime>,
}

impl Builder {
    /// Specify service like "s3".
    pub fn service(&mut self, service: &str) -> &mut Self {
        self.service = Some(service.to_string());
        self
    }

    /// Specify region.
    ///
    /// If not set, we will try to load via `region_loader`.
    pub fn region(&mut self, region: &str) -> &mut Self {
        self.region = Some(region.to_string());
        self
    }

    /// Specify region load behavior
    ///
    /// If not set, we will use the default region loader.
    pub fn region_loader(&mut self, region: RegionLoadChain) -> &mut Self {
        self.region_load = region;
        self
    }

    /// Specify access key id.
    ///
    /// If not set, we will try to load via `credential_loader`.
    pub fn access_key(&mut self, access_key: &str) -> &mut Self {
        self.credential.set_access_key(access_key);
        self
    }

    /// Specify secret access key.
    ///
    /// If not set, we will try to load via `credential_loader`.
    pub fn secret_key(&mut self, secret_key: &str) -> &mut Self {
        self.credential.set_secret_key(secret_key);
        self
    }

    /// Specify security token.
    ///
    /// # Note
    ///
    /// Security token always come with an expires in, we must load it from
    /// via credential loader. So this function should never be exported.
    #[cfg(test)]
    pub fn security_token(&mut self, security_token: &str) -> &mut Self {
        self.credential.set_security_token(Some(security_token));
        self
    }

    /// Specify credential load behavior
    ///
    /// If not set, we will use the default credential loader.
    pub fn credential_loader(&mut self, credential: CredentialLoadChain) -> &mut Self {
        self.credential_load = credential;
        self
    }

    /// Allow anonymous request if credential is not loaded.
    pub fn allow_anonymous(&mut self) -> &mut Self {
        self.allow_anonymous = true;
        self
    }

    /// Specify the signing time.
    ///
    /// # Note
    ///
    /// We should always take current time to sign requests.
    /// Only use this function for testing.
    #[cfg(test)]
    pub fn time(&mut self, time: DateTime) -> &mut Self {
        self.time = Some(time);
        self
    }

    /// Use exising information to build a new signer.
    ///
    /// The builder should not be used anymore.
    pub fn build(&mut self) -> Result<Signer> {
        let service = self
            .service
            .as_ref()
            .ok_or_else(|| anyhow!("service is required"))?;
        debug!("signer: service: {:?}", service);

        let credential = if self.credential.is_valid() {
            Some(self.credential.clone())
        } else {
            // Make sure credential load chain has been set before checking.
            if self.credential_load.is_empty() {
                self.credential_load
                    .push(EnvLoader::default())
                    .push(ProfileLoader::default())
                    .push(WebIdentityTokenLoader::default());
            }

            self.credential_load.load_credential()?
        };
        debug!("signer credential: {:?}", &credential);

        let region = match &self.region {
            Some(region) => region.to_string(),
            None => {
                // Make sure region load chain has been set before checking.
                if self.region_load.is_empty() {
                    self.region_load
                        .push(EnvLoader::default())
                        .push(ProfileLoader::default());
                }

                self.region_load
                    .load_region()?
                    .ok_or_else(|| anyhow!("region is required"))?
            }
        };
        debug!("signer region: {}", &region);

        Ok(Signer {
            service: service.to_string(),
            region,
            credential: Arc::new(RwLock::new(credential)),
            credential_load: mem::take(&mut self.credential_load),
            allow_anonymous: self.allow_anonymous,
            time: self.time,
        })
    }
}

/// Singer that implement AWS SigV4.
///
/// - [Signature Version 4 signing process](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
pub struct Signer {
    service: String,
    region: String,
    credential: Arc<RwLock<Option<Credential>>>,
    credential_load: CredentialLoadChain,

    /// Allow anonymous request if credential is not loaded.
    allow_anonymous: bool,

    time: Option<DateTime>,
}

impl Signer {
    /// Create a builder.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Load credential via credential load chain specified while building.
    ///
    /// # Note
    ///
    /// This function should never be exported to avoid credential leaking by
    /// mistake.
    fn credential(&self) -> Result<Option<Credential>> {
        // Return cached credential if it's valid.
        match self.credential.read().expect("lock poisoned").clone() {
            None => return Ok(None),
            Some(cred) => {
                if cred.is_valid() {
                    return Ok(Some(cred));
                }
            }
        }

        if let Some(cred) = self.credential_load.load_credential()? {
            let mut lock = self.credential.write().expect("lock poisoned");
            *lock = Some(cred.clone());
            Ok(Some(cred))
        } else {
            // We used to get credential correctly, but now we can't.
            // Something must happened in the running environment.
            Err(anyhow!("credential should be loaded but not"))
        }
    }

    /// Calculate signing requests via SignableRequest.
    pub fn calculate(
        &self,
        req: &impl SignableRequest,
        cred: &Credential,
        method: SigningMethod,
    ) -> Result<SignedOutput> {
        let canonical_req =
            CanonicalRequest::from(req, method, self.time, cred, &self.region, &self.service)?;
        debug!("calculated canonical_req: {canonical_req}");

        let encoded_req = hex_sha256(canonical_req.to_string().as_bytes());

        // Scope: "20220313/<region>/<service>/aws4_request"
        let scope = format!(
            "{}/{}/{}/aws4_request",
            format_date(canonical_req.time),
            self.region,
            self.service
        );
        debug!("calculated scope: {scope}");

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
            writeln!(f, "{}", format_iso8601(canonical_req.time))?;
            writeln!(f, "{}", &scope)?;
            write!(f, "{}", &encoded_req)?;
            f
        };
        debug!("calculated string to sign: {string_to_sign}");

        let signing_key = generate_signing_key(
            cred.secret_key(),
            canonical_req.time,
            &self.region,
            &self.service,
        );
        let signature = hex_hmac_sha256(&signing_key, string_to_sign.as_bytes());

        Ok(SignedOutput {
            method,
            access_key_id: cred.access_key().to_string(),
            security_token: cred.security_token().map(|v| v.to_string()),
            signed_time: canonical_req.time,
            signed_scope: scope,
            signed_query: canonical_req.params.unwrap_or_default(),
            signed_headers: canonical_req.signed_headers,
            signature,
        })
    }

    /// Apply signed results to requests.
    pub fn apply(&self, req: &mut impl SignableRequest, sig: &SignedOutput) -> Result<()> {
        match sig.method {
            SigningMethod::Header => {
                req.insert_header(
                    HeaderName::from_static(super::constants::X_AMZ_DATE),
                    &format_iso8601(sig.signed_time),
                )?;
                req.insert_header(
                    HeaderName::from_static(super::constants::X_AMZ_CONTENT_SHA_256),
                    "UNSIGNED-PAYLOAD",
                )?;

                // Set X_AMZ_SECURITY_TOKEN if we have security_token
                if let Some(token) = &sig.security_token {
                    req.insert_header(
                        HeaderName::from_static(super::constants::X_AMZ_SECURITY_TOKEN),
                        token,
                    )?;
                }

                req.insert_header(
                    http::header::AUTHORIZATION,
                    &format!(
                        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
                        sig.access_key_id,
                        sig.signed_scope,
                        sig.signed_headers.join(";"),
                        sig.signature
                    ),
                )?;
            }
            SigningMethod::Query(_) => {
                debug_assert!(!sig.signed_query.is_empty());
                req.set_query(&format!(
                    "{}&X-Amz-Signature={}",
                    sig.signed_query, sig.signature
                ))?
            }
        }

        Ok(())
    }

    /// Signing request with header.
    ///
    /// # Example
    ///
    /// ```rust
    /// use reqsign::services::aws::v4::Signer;
    /// use reqwest::{Client, Request, Url};
    /// use anyhow::Result;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()>{
    ///     // Signer will load region and credentials from environment by default.
    ///     let signer = Signer::builder()
    ///         .service("s3")
    ///         .region("test")
    ///         .allow_anonymous()
    ///         .build()?;
    ///     // Construct request
    ///     let url = Url::parse("https://s3.amazonaws.com/testbucket")?;
    ///     let mut req = reqwest::Request::new(http::Method::GET, url);
    ///     // Signing request with Signer
    ///     signer.sign(&mut req)?;
    ///     // Sending already signed request.
    ///     let resp = Client::new().execute(req).await?;
    ///     println!("resp got status: {}", resp.status());
    ///     Ok(())
    /// }
    /// ```
    pub fn sign(&self, req: &mut impl SignableRequest) -> Result<()> {
        if let Some(cred) = self.credential()? {
            let sig = self.calculate(req, &cred, SigningMethod::Header)?;
            return self.apply(req, &sig);
        }

        if self.allow_anonymous {
            debug!("credential not found and anonymous is allowed, skipping signing.");
            return Ok(());
        }

        Err(anyhow!("credential not found"))
    }

    /// Signing request with query.
    ///
    /// # Example
    ///
    /// ```rust
    /// use reqsign::services::aws::v4::Signer;
    /// use reqwest::{Client, Request, Url};
    /// use anyhow::Result;
    /// use time::Duration;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()>{
    ///     // Signer will load region and credentials from environment by default.
    ///     let signer = Signer::builder()
    ///         .service("s3")
    ///         .region("test")
    ///         .allow_anonymous()
    ///         .build()?;
    ///     // Construct request
    ///     let url = Url::parse("https://s3.amazonaws.com/testbucket")?;
    ///     let mut req = reqwest::Request::new(http::Method::GET, url);
    ///     // Signing request with Signer
    ///     signer.sign_query(&mut req, Duration::hours(1))?;
    ///     // Sending already signed request.
    ///     let resp = Client::new().execute(req).await?;
    ///     println!("resp got status: {}", resp.status());
    ///     Ok(())
    /// }
    /// ```
    pub fn sign_query(&self, req: &mut impl SignableRequest, expire: Duration) -> Result<()> {
        if let Some(cred) = self.credential()? {
            let sig = self.calculate(req, &cred, SigningMethod::Query(expire))?;
            return self.apply(req, &sig);
        }

        if self.allow_anonymous {
            debug!("credential not found and anonymous is allowed, skipping signing.");
            return Ok(());
        }

        Err(anyhow!("credential not found"))
    }
}

impl Debug for Signer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Signer {{ region: {}, service: {}, allow_anonymous: {} }}",
            self.region, self.service, self.allow_anonymous
        )
    }
}

/// SigningMethod is the method that used in signing.
#[derive(Copy, Clone)]
pub enum SigningMethod {
    /// Signing with header.
    Header,
    /// Signing with query.
    Query(Duration),
}

#[derive(Clone)]
struct CanonicalRequest<'a> {
    method: http::Method,
    path: String,
    params: Option<String>,
    headers: http::HeaderMap,

    time: DateTime,
    signed_headers: Vec<HeaderName>,
    content_sha256: &'a str,
}

impl<'a> CanonicalRequest<'a> {
    pub fn from<'b>(
        req: &'b impl SignableRequest,
        method: SigningMethod,
        time: Option<DateTime>,
        cred: &'b Credential,
        region: &str,
        service: &str,
    ) -> Result<CanonicalRequest<'b>> {
        let now = time.unwrap_or_else(time::now);

        let (signed_headers, canonical_headers) = Self::headers(req, now, cred, method)?;

        let canonical_queries = Self::params(req, method, now, cred, region, service);

        let path = percent_decode_str(req.path()).decode_utf8()?.to_string();

        Ok(CanonicalRequest {
            method: req.method(),
            path,
            params: canonical_queries,
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
        now: DateTime,
        cred: &Credential,
        method: SigningMethod,
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
            let header = HeaderValue::try_from(req.host_port())
                .expect("endpoint must contain valid header characters");
            canonical_headers.insert(http::header::HOST, header);
        }

        if matches!(method, SigningMethod::Header) {
            // Insert DATE header if not present.
            if canonical_headers
                .get(HeaderName::from_static(super::constants::X_AMZ_DATE))
                .is_none()
            {
                let date_header =
                    HeaderValue::try_from(format_iso8601(now)).expect("date is valid header value");
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
        }

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

    pub fn params(
        req: &impl SignableRequest,
        method: SigningMethod,
        now: DateTime,
        cred: &Credential,
        region: &str,
        service: &str,
    ) -> Option<String> {
        let mut params: Vec<_> =
            form_urlencoded::parse(req.query().unwrap_or_default().as_bytes()).collect();

        if let SigningMethod::Query(expire) = method {
            params.push(("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()));
            params.push((
                "X-Amz-Credential".into(),
                Cow::Owned(format!(
                    "{}/{}/{}/{}/aws4_request",
                    cred.access_key(),
                    format_date(now),
                    region,
                    service
                )),
            ));
            params.push(("X-Amz-Date".into(), Cow::Owned(format_iso8601(now))));
            params.push((
                "X-Amz-Expires".into(),
                Cow::Owned(expire.whole_seconds().to_string()),
            ));
            params.push(("X-Amz-SignedHeaders".into(), "host".into()));
        }
        // Sort by param name
        params.sort();

        if params.is_empty() {
            return None;
        }

        let param = params
            .iter()
            .map(|(k, v)| {
                (
                    utf8_percent_encode(k, &AWS_QUERY_ENCODE_SET),
                    utf8_percent_encode(v, &AWS_QUERY_ENCODE_SET),
                )
            })
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<String>>()
            .join("&");
        Some(param)
    }
}

impl<'a> Display for CanonicalRequest<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.method)?;
        writeln!(
            f,
            "{}",
            utf8_percent_encode(&self.path, &super::constants::AWS_URI_ENCODE_SET)
        )?;
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

/// Signed resulted that calculated by `Signer`.
pub struct SignedOutput {
    method: SigningMethod,

    access_key_id: String,
    security_token: Option<String>,
    signed_time: DateTime,
    signed_scope: String,
    signed_query: String,
    signed_headers: Vec<HeaderName>,
    signature: String,
}

impl SignedOutput {
    #[cfg(test)]
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

fn generate_signing_key(secret: &str, time: DateTime, region: &str, service: &str) -> Vec<u8> {
    // Sign secret
    let secret = format!("AWS4{}", secret);
    // Sign date
    let sign_date = hmac_sha256(secret.as_bytes(), format_date(time).as_bytes());
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
    use anyhow::Result;
    use aws_sigv4;
    use aws_sigv4::http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
    };
    use aws_sigv4::SigningParams;
    use std::time::SystemTime;

    use super::*;

    fn test_get_request() -> http::Request<&'static str> {
        let mut req = http::Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "http://127.0.0.1:9000/hello"
            .parse()
            .expect("url must be valid");

        req
    }

    fn test_get_request_with_query() -> http::Request<&'static str> {
        let mut req = http::Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "http://127.0.0.1:9000/hello?list-type=2&max-keys=3&prefix=CI/&start-after=ExampleGuide.pdf"
            .parse()
            .expect("url must be valid");

        req
    }

    fn test_put_request() -> http::Request<&'static str> {
        let content = "Hello,World!";
        let mut req = http::Request::new(content);
        *req.method_mut() = http::Method::PUT;
        *req.uri_mut() = "http://127.0.0.1:9000/hello"
            .parse()
            .expect("url must be valid");

        req.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&content.len().to_string()).expect("must be valid"),
        );

        req
    }

    #[tokio::test]
    async fn test_calculate() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        for req_fn in [
            test_get_request,
            test_get_request_with_query,
            test_put_request,
        ] {
            let mut req = req_fn();
            let now = time::now();

            let mut ss = SigningSettings::default();
            ss.percent_encoding_mode = PercentEncodingMode::Double;
            ss.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

            let sp = SigningParams::builder()
                .access_key("access_key_id")
                .secret_key("secret_access_key")
                .region("test")
                .service_name("s3")
                .time(SystemTime::from(now))
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

            let mut req = req_fn();

            let signer = Signer::builder()
                .access_key("access_key_id")
                .secret_key("secret_access_key")
                .region("test")
                .service("s3")
                .time(now)
                .build()?;

            let cred = signer.credential()?.expect("credential must be valid");
            let actual = signer.calculate(&req, &cred, SigningMethod::Header)?;
            signer.apply(&mut req, &actual).expect("must apply success");

            assert_eq!(expect_sig, actual.signature());
            assert_eq!(expect_headers, req.headers());
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_calculate_with_token() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        for req_fn in [test_get_request, test_put_request] {
            let mut req = req_fn();
            let now = time::now();

            let mut ss = SigningSettings::default();
            ss.percent_encoding_mode = PercentEncodingMode::Double;
            ss.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

            let sp = SigningParams::builder()
                .access_key("access_key_id")
                .secret_key("secret_access_key")
                .region("test")
                .security_token("security_token")
                .service_name("s3")
                .time(SystemTime::from(now))
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

            let mut req = req_fn();

            let signer = Signer::builder()
                .access_key("access_key_id")
                .secret_key("secret_access_key")
                .region("test")
                .security_token("security_token")
                .service("s3")
                .time(now)
                .build()?;

            let cred = signer.credential()?.expect("credential must be valid");
            let actual = signer.calculate(&req, &cred, SigningMethod::Header)?;
            signer.apply(&mut req, &actual).expect("must apply success");

            assert_eq!(expect_sig, actual.signature());
            assert_eq!(expect_headers, req.headers());
        }

        Ok(())
    }

    fn test_get_request_virtual_host() -> http::Request<&'static str> {
        let mut req = http::Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "http://hello.s3.test.example.com"
            .parse()
            .expect("url must be valid");

        req
    }

    fn test_get_request_with_query_virtual_host() -> http::Request<&'static str> {
        let mut req = http::Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "http://hello.s3.test.example.com?list-type=2&max-keys=3&prefix=CI/&start-after=ExampleGuide.pdf"
            .parse()
            .expect("url must be valid");

        req
    }

    fn test_put_request_virtual_host() -> http::Request<&'static str> {
        let content = "Hello,World!";
        let mut req = http::Request::new(content);
        *req.method_mut() = http::Method::PUT;
        *req.uri_mut() = "http://hello.s3.test.example.com"
            .parse()
            .expect("url must be valid");

        req.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&content.len().to_string()).expect("must be valid"),
        );

        req
    }

    #[tokio::test]
    async fn test_calculate_virtual_host() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        for req_fn in [
            test_get_request_virtual_host,
            test_get_request_with_query_virtual_host,
            test_put_request_virtual_host,
        ] {
            let mut req = req_fn();
            let now = time::now();

            let mut ss = SigningSettings::default();
            ss.percent_encoding_mode = PercentEncodingMode::Double;
            ss.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

            let sp = SigningParams::builder()
                .access_key("access_key_id")
                .secret_key("secret_access_key")
                .region("test")
                .service_name("s3")
                .time(SystemTime::from(now))
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

            let mut req = req_fn();

            let signer = Signer::builder()
                .access_key("access_key_id")
                .secret_key("secret_access_key")
                .region("test")
                .service("s3")
                .time(now)
                .build()?;

            let cred = signer.credential()?.expect("credential must be valid");
            let actual = signer.calculate(&req, &cred, SigningMethod::Header)?;
            signer.apply(&mut req, &actual).expect("must apply success");

            assert_eq!(expect_sig, actual.signature());
            assert_eq!(expect_headers, req.headers());
        }

        Ok(())
    }
}
