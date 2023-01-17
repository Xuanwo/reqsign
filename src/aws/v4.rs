//! AWS service sigv4 signer

use std::borrow::Cow;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Write;

use anyhow::anyhow;
use anyhow::Result;
use http::HeaderMap;
use http::HeaderValue;
use log::debug;
use percent_encoding::percent_decode_str;
use percent_encoding::utf8_percent_encode;

use super::config::ConfigLoader;
use super::constants::AWS_QUERY_ENCODE_SET;
use super::constants::X_AMZ_CONTENT_SHA_256;
use super::constants::X_AMZ_DATE;
use super::constants::X_AMZ_SECURITY_TOKEN;
use super::credential::CredentialLoader;
use super::region::RegionLoader;
use crate::credential::Credential;
use crate::hash::hex_hmac_sha256;
use crate::hash::hex_sha256;
use crate::hash::hmac_sha256;
use crate::request::SignableRequest;
use crate::time::format_date;
use crate::time::format_iso8601;
use crate::time::DateTime;
use crate::time::Duration;
use crate::time::{self};

/// Builder for `Signer`.
#[derive(Default)]
pub struct Builder {
    service: Option<String>,

    config_loader: ConfigLoader,
    credential_loader: Option<CredentialLoader>,
    allow_anonymous: bool,

    time: Option<DateTime>,
}

impl Builder {
    /// Specify service like "s3".
    pub fn service(&mut self, service: &str) -> &mut Self {
        self.service = Some(service.to_string());
        self
    }

    /// Set the config loader used by builder.
    ///
    /// # Notes
    ///
    /// Signer will only read data from it, it's your responsible to decide
    /// whether or not to call `ConfigLoader::load()`.
    ///
    /// If `load` is called, ConfigLoader will load config from current env.
    /// If not, ConfigLoader will only use static config that set by users.
    pub fn config_loader(&mut self, cfg: ConfigLoader) -> &mut Self {
        self.config_loader = cfg;
        self
    }

    /// Allow anonymous request if credential is not loaded.
    pub fn allow_anonymous(&mut self) -> &mut Self {
        self.allow_anonymous = true;
        self
    }

    /// Set credential loader
    pub fn credential_loader(&mut self, cred: CredentialLoader) -> &mut Self {
        self.credential_loader = Some(cred);
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

        let cred_loader = match self.credential_loader.take() {
            Some(cred) => cred,
            None => {
                let mut loader = CredentialLoader::new(self.config_loader.clone());
                if self.allow_anonymous {
                    loader = loader.with_allow_anonymous();
                }
                loader
            }
        };

        let region_loader = RegionLoader::new(self.config_loader.clone());

        let region = region_loader
            .load()
            .ok_or_else(|| anyhow!("region is missing"))?;
        debug!("signer region: {}", &region);

        Ok(Signer {
            service: service.to_string(),
            region,
            credential_loader: cred_loader,
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
    credential_loader: CredentialLoader,

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
    fn credential(&self) -> Option<Credential> {
        self.credential_loader.load()
    }

    fn canonicalize(
        &self,
        req: &impl SignableRequest,
        method: SigningMethod,
        cred: &Credential,
    ) -> Result<CanonicalRequest> {
        let mut creq = CanonicalRequest::new(req, method, self.time)?;
        creq.build_headers(cred)?;
        creq.build_query(cred, &self.service, &self.region)?;

        debug!("calculated canonical request: {creq}");
        Ok(creq)
    }

    /// Calculate signing requests via SignableRequest.
    fn calculate(&self, mut creq: CanonicalRequest, cred: &Credential) -> Result<CanonicalRequest> {
        let encoded_req = hex_sha256(creq.to_string().as_bytes());

        // Scope: "20220313/<region>/<service>/aws4_request"
        let scope = format!(
            "{}/{}/{}/aws4_request",
            format_date(creq.signing_time),
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
            let mut f = String::new();
            writeln!(f, "AWS4-HMAC-SHA256")?;
            writeln!(f, "{}", format_iso8601(creq.signing_time))?;
            writeln!(f, "{}", &scope)?;
            write!(f, "{}", &encoded_req)?;
            f
        };
        debug!("calculated string to sign: {string_to_sign}");

        let signing_key = generate_signing_key(
            cred.secret_key(),
            creq.signing_time,
            &self.region,
            &self.service,
        );
        let signature = hex_hmac_sha256(&signing_key, string_to_sign.as_bytes());

        match creq.signing_method {
            SigningMethod::Header => {
                let mut authorization = HeaderValue::from_str(&format!(
                    "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
                    cred.access_key(),
                    scope,
                    creq.signed_headers().join(";"),
                    signature
                ))?;
                authorization.set_sensitive(true);

                creq.headers
                    .insert(http::header::AUTHORIZATION, authorization);
            }
            SigningMethod::Query(_) => {
                let mut query = creq
                    .query
                    .take()
                    .expect("query must be valid in query signing");
                write!(query, "&X-Amz-Signature={signature}")?;

                creq.query = Some(query);
            }
        }

        Ok(creq)
    }

    /// Get the region of this signer.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Apply signed results to requests.
    fn apply(&self, req: &mut impl SignableRequest, creq: CanonicalRequest) -> Result<()> {
        for (header, value) in creq.headers.into_iter() {
            req.insert_header(
                header.expect("header must contain only once"),
                value.clone(),
            )?;
        }

        if let Some(query) = creq.query {
            req.set_query(&query)?;
        }

        Ok(())
    }

    /// Signing request with header.
    ///
    /// # Example
    ///
    /// ```rust
    /// use anyhow::Result;
    /// use reqsign::AwsV4Signer;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     // Signer will load region and credentials from environment by default.
    ///     let signer = AwsV4Signer::builder()
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
        if let Some(cred) = self.credential() {
            let creq = self.canonicalize(req, SigningMethod::Header, &cred)?;
            let creq = self.calculate(creq, &cred)?;
            return self.apply(req, creq);
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
    /// use anyhow::Result;
    /// use reqsign::AwsV4Signer;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
    /// use time::Duration;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     // Signer will load region and credentials from environment by default.
    ///     let signer = AwsV4Signer::builder()
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
        if let Some(cred) = self.credential() {
            let creq = self.canonicalize(req, SigningMethod::Query(expire), &cred)?;
            let creq = self.calculate(creq, &cred)?;
            return self.apply(req, creq);
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
struct CanonicalRequest {
    method: http::Method,
    path: String,
    query: Option<String>,
    headers: HeaderMap,

    signing_host: String,
    signing_method: SigningMethod,
    signing_time: DateTime,
}

impl CanonicalRequest {
    fn new(
        req: &impl SignableRequest,
        method: SigningMethod,
        now: Option<DateTime>,
    ) -> Result<Self> {
        let mut canonical_headers = HeaderMap::with_capacity(req.headers().len());
        // Header names and values need to be normalized according to Step 4 of https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        // Using append instead of insert means this will not clobber headers that have the same lowercase name
        for (name, value) in req.headers().iter() {
            // The user agent header should not be canonical because it may be altered by proxies
            if name == http::header::USER_AGENT {
                continue;
            }
            canonical_headers.append(name, normalize_header_value(value));
        }

        Ok(CanonicalRequest {
            method: req.method(),
            path: percent_decode_str(req.path()).decode_utf8()?.to_string(),
            query: req.query().map(|v| v.to_string()),
            headers: req.headers(),

            signing_host: req.host_port(),
            signing_method: method,
            signing_time: now.unwrap_or_else(time::now),
        })
    }

    fn build_headers(&mut self, cred: &Credential) -> Result<()> {
        // Insert HOST header if not present.
        if self.headers.get(&http::header::HOST).is_none() {
            let header = HeaderValue::try_from(self.signing_host.to_string())?;
            self.headers.insert(http::header::HOST, header);
        }

        if matches!(self.signing_method, SigningMethod::Header) {
            // Insert DATE header if not present.
            if self.headers.get(X_AMZ_DATE).is_none() {
                let date_header = HeaderValue::try_from(format_iso8601(self.signing_time))?;
                self.headers.insert(X_AMZ_DATE, date_header);
            }

            // Insert X_AMZ_CONTENT_SHA_256 header if not present.
            if self.headers.get(X_AMZ_CONTENT_SHA_256).is_none() {
                self.headers.insert(
                    X_AMZ_CONTENT_SHA_256,
                    HeaderValue::from_static("UNSIGNED-PAYLOAD"),
                );
            }

            // Insert X_AMZ_SECURITY_TOKEN header if security token exists.
            if let Some(token) = cred.security_token() {
                let mut value = HeaderValue::from_str(token)?;
                // Set token value sensitive to valid leaking.
                value.set_sensitive(true);

                self.headers.insert(X_AMZ_SECURITY_TOKEN, value);
            }
        }

        Ok(())
    }

    fn signed_headers(&self) -> Vec<&str> {
        let mut signed_headers = self.headers.keys().map(|v| v.as_str()).collect::<Vec<_>>();
        signed_headers.sort_unstable();

        signed_headers
    }

    fn build_query(&mut self, cred: &Credential, service: &str, region: &str) -> Result<()> {
        let query = self.query.take().unwrap_or_default();
        let mut params: Vec<_> = form_urlencoded::parse(query.as_bytes()).collect();

        if let SigningMethod::Query(expire) = self.signing_method {
            params.push(("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()));
            params.push((
                "X-Amz-Credential".into(),
                Cow::Owned(format!(
                    "{}/{}/{}/{}/aws4_request",
                    cred.access_key(),
                    format_date(self.signing_time),
                    region,
                    service
                )),
            ));
            params.push((
                "X-Amz-Date".into(),
                Cow::Owned(format_iso8601(self.signing_time)),
            ));
            params.push((
                "X-Amz-Expires".into(),
                Cow::Owned(expire.whole_seconds().to_string()),
            ));
            params.push((
                "X-Amz-SignedHeaders".into(),
                self.signed_headers().join(";").into(),
            ));

            if let Some(token) = cred.security_token() {
                params.push(("X-Amz-Security-Token".into(), token.into()));
            }
        }
        // Sort by param name
        params.sort();

        if params.is_empty() {
            return Ok(());
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
        self.query = Some(param);

        Ok(())
    }
}

impl Display for CanonicalRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.method)?;
        writeln!(
            f,
            "{}",
            utf8_percent_encode(&self.path, &super::constants::AWS_URI_ENCODE_SET)
        )?;
        writeln!(f, "{}", self.query.as_ref().unwrap_or(&"".to_string()))?;

        let signed_headers = self.signed_headers();
        for header in signed_headers.iter() {
            let value = &self.headers[*header];
            writeln!(
                f,
                "{}:{}",
                header,
                value.to_str().expect("header value must be valid")
            )?;
        }
        writeln!(f)?;
        writeln!(f, "{}", signed_headers.join(";"))?;
        // TODO: we should support user specify payload hash.
        write!(f, "UNSIGNED-PAYLOAD")?;

        Ok(())
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
    use std::time::SystemTime;

    use anyhow::Result;
    use aws_sigv4;
    use aws_sigv4::http_request::PayloadChecksumKind;
    use aws_sigv4::http_request::PercentEncodingMode;
    use aws_sigv4::http_request::SignableBody;
    use aws_sigv4::http_request::SignableRequest;
    use aws_sigv4::http_request::SignatureLocation;
    use aws_sigv4::http_request::SigningSettings;
    use aws_sigv4::SigningParams;
    use http::header;

    use super::*;

    fn test_get_request() -> http::Request<&'static str> {
        let mut req = http::Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "http://127.0.0.1:9000/hello"
            .parse()
            .expect("url must be valid");

        req
    }

    fn test_get_request_with_sse() -> http::Request<&'static str> {
        let mut req = http::Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "http://127.0.0.1:9000/hello"
            .parse()
            .expect("url must be valid");
        req.headers_mut().insert(
            "x-amz-server-side-encryption",
            "a".parse().expect("must be valid"),
        );
        req.headers_mut().insert(
            "x-amz-server-side-encryption-customer-algorithm",
            "b".parse().expect("must be valid"),
        );
        req.headers_mut().insert(
            "x-amz-server-side-encryption-customer-key",
            "c".parse().expect("must be valid"),
        );
        req.headers_mut().insert(
            "x-amz-server-side-encryption-customer-key-md5",
            "d".parse().expect("must be valid"),
        );
        req.headers_mut().insert(
            "x-amz-server-side-encryption-aws-kms-key-id",
            "e".parse().expect("must be valid"),
        );

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

    fn test_put_request_virtual_host() -> http::Request<&'static str> {
        let content = "Hello,World!";
        let mut req = http::Request::new(content);
        *req.method_mut() = http::Method::PUT;
        *req.uri_mut() = "http://hello.s3.test.example.com"
            .parse()
            .expect("url must be valid");

        req.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&content.len().to_string()).expect("must be valid"),
        );

        req
    }

    fn test_cases() -> &'static [fn() -> http::Request<&'static str>] {
        &[
            test_get_request,
            test_get_request_with_sse,
            test_get_request_with_query,
            test_get_request_virtual_host,
            test_get_request_with_query_virtual_host,
            test_put_request,
            test_put_request_virtual_host,
        ]
    }

    fn compare_request(name: &str, l: &http::Request<&str>, r: &http::Request<&str>) {
        fn format_headers(req: &http::Request<&str>) -> Vec<String> {
            use crate::request::SignableRequest;

            let mut hs = req
                .headers()
                .iter()
                .map(|(k, v)| format!("{}:{}", k, v.to_str().expect("must be valid")))
                .collect::<Vec<_>>();

            // Insert host if original request doesn't have it.
            if !hs.contains(&format!("host:{}", req.host_port())) {
                hs.push(format!("host:{}", req.host_port()))
            }

            hs.sort();
            hs
        }

        assert_eq!(
            format_headers(l),
            format_headers(r),
            "{name} header mismatch"
        );

        fn format_query(req: &http::Request<&str>) -> Vec<String> {
            let query = req.uri().query().unwrap_or_default();
            let mut query = form_urlencoded::parse(query.as_bytes())
                .map(|(k, v)| format!("{}={}", &k, &v))
                .collect::<Vec<_>>();
            query.sort();
            query
        }

        assert_eq!(format_query(l), format_query(r), "{name} query mismatch");
    }

    #[tokio::test]
    async fn test_calculate() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        for req_fn in test_cases() {
            let mut req = req_fn();
            let name = format!(
                "{} {} {:?}",
                req.method(),
                req.uri().path(),
                req.uri().query(),
            );
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
            let (aws_sig, _) = output.into_parts();
            aws_sig.apply_to_request(&mut req);
            let expected_req = req;

            let mut req = req_fn();

            let signer = Signer::builder()
                .config_loader({
                    let cfg = ConfigLoader::default();
                    cfg.set_region("test");
                    cfg.set_access_key_id("access_key_id");
                    cfg.set_secret_access_key("secret_access_key");
                    cfg
                })
                .service("s3")
                .time(now)
                .build()?;

            let cred = signer.credential().expect("credential must be valid");
            let creq = signer.canonicalize(&req, SigningMethod::Header, &cred)?;
            let actual = signer.calculate(creq, &cred)?;
            signer.apply(&mut req, actual).expect("must apply success");
            let actual_req = req;

            compare_request(&name, &expected_req, &actual_req);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_calculate_in_query() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        for req_fn in test_cases() {
            let mut req = req_fn();
            let name = format!(
                "{} {} {:?}",
                req.method(),
                req.uri().path(),
                req.uri().query(),
            );
            let now = time::now();

            let mut ss = SigningSettings::default();
            ss.percent_encoding_mode = PercentEncodingMode::Double;
            ss.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
            ss.signature_location = SignatureLocation::QueryParams;
            ss.expires_in = Some(std::time::Duration::from_secs(3600));

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
            let (aws_sig, _) = output.into_parts();
            aws_sig.apply_to_request(&mut req);
            let expected_req = req;

            let mut req = req_fn();

            let signer = Signer::builder()
                .config_loader({
                    let cfg = ConfigLoader::default();
                    cfg.set_region("test");
                    cfg.set_access_key_id("access_key_id");
                    cfg.set_secret_access_key("secret_access_key");
                    cfg
                })
                .service("s3")
                .time(now)
                .build()?;

            let cred = signer.credential().expect("credential must be valid");
            let creq =
                signer.canonicalize(&req, SigningMethod::Query(Duration::hours(1)), &cred)?;
            let actual = signer.calculate(creq, &cred)?;
            signer.apply(&mut req, actual)?;
            let actual_req = req;

            compare_request(&name, &expected_req, &actual_req);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_calculate_with_token() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        for req_fn in test_cases() {
            let mut req = req_fn();
            let name = format!(
                "{} {} {:?}",
                req.method(),
                req.uri().path(),
                req.uri().query(),
            );
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
            let (aws_sig, _) = output.into_parts();
            aws_sig.apply_to_request(&mut req);
            let expected_req = req;

            let mut req = req_fn();

            let signer = Signer::builder()
                .config_loader({
                    let cfg = ConfigLoader::default();
                    cfg.set_region("test");
                    cfg.set_access_key_id("access_key_id");
                    cfg.set_secret_access_key("secret_access_key");
                    cfg.set_session_token("security_token");
                    cfg
                })
                .service("s3")
                .time(now)
                .build()?;

            let cred = signer.credential().expect("credential must be valid");
            let creq = signer.canonicalize(&req, SigningMethod::Header, &cred)?;
            let actual = signer.calculate(creq, &cred)?;
            signer.apply(&mut req, actual).expect("must apply success");
            let actual_req = req;

            compare_request(&name, &expected_req, &actual_req);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_calculate_with_token_in_query() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        for req_fn in test_cases() {
            let mut req = req_fn();
            let name = format!(
                "{} {} {:?}",
                req.method(),
                req.uri().path(),
                req.uri().query(),
            );
            let now = time::now();

            let mut ss = SigningSettings::default();
            ss.percent_encoding_mode = PercentEncodingMode::Double;
            ss.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
            ss.signature_location = SignatureLocation::QueryParams;
            ss.expires_in = Some(std::time::Duration::from_secs(3600));

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
            let (aws_sig, _) = output.into_parts();
            aws_sig.apply_to_request(&mut req);
            let expected_req = req;

            let mut req = req_fn();

            let signer = Signer::builder()
                .config_loader({
                    let cfg = ConfigLoader::default();
                    cfg.set_region("test");
                    cfg.set_access_key_id("access_key_id");
                    cfg.set_secret_access_key("secret_access_key");
                    cfg.set_session_token("security_token");
                    cfg
                })
                .service("s3")
                .time(now)
                .build()?;

            let cred = signer.credential().expect("credential must be valid");
            let creq =
                signer.canonicalize(&req, SigningMethod::Query(Duration::hours(1)), &cred)?;
            let actual = signer.calculate(creq, &cred)?;
            signer.apply(&mut req, actual).expect("must apply success");
            let actual_req = req;

            compare_request(&name, &expected_req, &actual_req);
        }

        Ok(())
    }
}
