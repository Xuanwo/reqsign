//! AWS service sigv4 signer

use std::fmt::Debug;
use std::fmt::Write;
use std::time::Duration;

use anyhow::Result;
use http::header;
use http::HeaderValue;
use log::debug;
use percent_encoding::percent_decode_str;
use percent_encoding::utf8_percent_encode;

use super::constants::AWS_QUERY_ENCODE_SET;
use super::constants::X_AMZ_CONTENT_SHA_256;
use super::constants::X_AMZ_DATE;
use super::constants::X_AMZ_SECURITY_TOKEN;
use super::credential::Credential;
use crate::ctx::SigningContext;
use crate::ctx::SigningMethod;
use crate::hash::hex_hmac_sha256;
use crate::hash::hex_sha256;
use crate::hash::hmac_sha256;
use crate::request::SignableRequest;
use crate::time::format_date;
use crate::time::format_iso8601;
use crate::time::now;
use crate::time::DateTime;

/// Singer that implement AWS SigV4.
///
/// - [Signature Version 4 signing process](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
#[derive(Debug)]
pub struct Signer {
    service: String,
    region: String,

    time: Option<DateTime>,
}

impl Signer {
    /// Create a builder.
    pub fn new(service: &str, region: &str) -> Self {
        Self {
            service: service.to_string(),
            region: region.to_string(),
            time: None,
        }
    }

    /// Specify the signing time.
    ///
    /// # Note
    ///
    /// We should always take current time to sign requests.
    /// Only use this function for testing.
    #[cfg(test)]
    pub fn time(mut self, time: DateTime) -> Self {
        self.time = Some(time);
        self
    }

    fn build(
        &self,
        req: &mut impl SignableRequest,
        method: SigningMethod,
        cred: &Credential,
    ) -> Result<SigningContext> {
        let now = self.time.unwrap_or_else(now);
        let mut ctx = req.build()?;

        // canonicalize context
        canonicalize_header(&mut ctx, method, cred, now)?;
        canonicalize_query(&mut ctx, method, cred, now, &self.service, &self.region)?;

        // build canonical request and string to sign.
        let creq = canonical_request_string(&mut ctx)?;
        let encoded_req = hex_sha256(creq.as_bytes());

        // Scope: "20220313/<region>/<service>/aws4_request"
        let scope = format!(
            "{}/{}/{}/aws4_request",
            format_date(now),
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
            writeln!(f, "{}", format_iso8601(now))?;
            writeln!(f, "{}", &scope)?;
            write!(f, "{}", &encoded_req)?;
            f
        };
        debug!("calculated string to sign: {string_to_sign}");

        let signing_key =
            generate_signing_key(&cred.secret_access_key, now, &self.region, &self.service);
        let signature = hex_hmac_sha256(&signing_key, string_to_sign.as_bytes());

        match method {
            SigningMethod::Header => {
                let mut authorization = HeaderValue::from_str(&format!(
                    "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
                    cred.access_key_id,
                    scope,
                    ctx.header_name_to_vec_sorted().join(";"),
                    signature
                ))?;
                authorization.set_sensitive(true);

                ctx.headers
                    .insert(http::header::AUTHORIZATION, authorization);
            }
            SigningMethod::Query(_) => {
                ctx.query.push(("X-Amz-Signature".into(), signature));
            }
        }

        Ok(ctx)
    }

    /// Get the region of this signer.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Signing request with header.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use anyhow::Result;
    /// use reqsign::AwsConfig;
    /// use reqsign::AwsDefaultLoader;
    /// use reqsign::AwsV4Signer;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let client = Client::new();
    ///     let config = AwsConfig::default().from_profile().from_env();
    ///     let loader = AwsDefaultLoader::new(client.clone(), config);
    ///     let signer = AwsV4Signer::new("s3", "us-east-1");
    ///     // Construct request
    ///     let url = Url::parse("https://s3.amazonaws.com/testbucket")?;
    ///     let mut req = reqwest::Request::new(http::Method::GET, url);
    ///     // Signing request with Signer
    ///     let credential = loader.load().await?.unwrap();
    ///     signer.sign(&mut req, &credential)?;
    ///     // Sending already signed request.
    ///     let resp = client.execute(req).await?;
    ///     println!("resp got status: {}", resp.status());
    ///     Ok(())
    /// }
    /// ```
    pub fn sign(&self, req: &mut impl SignableRequest, cred: &Credential) -> Result<()> {
        let ctx = self.build(req, SigningMethod::Header, cred)?;
        req.apply(ctx)
    }

    /// Signing request with query.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::time::Duration;
    ///
    /// use anyhow::Result;
    /// use reqsign::AwsConfig;
    /// use reqsign::AwsDefaultLoader;
    /// use reqsign::AwsV4Signer;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let client = Client::new();
    ///     let config = AwsConfig::default().from_profile().from_env();
    ///     let loader = AwsDefaultLoader::new(client.clone(), config);
    ///     let signer = AwsV4Signer::new("s3", "us-east-1");
    ///     // Construct request
    ///     let url = Url::parse("https://s3.amazonaws.com/testbucket")?;
    ///     let mut req = reqwest::Request::new(http::Method::GET, url);
    ///     // Signing request with Signer
    ///     let credential = loader.load().await?.unwrap();
    ///     signer.sign_query(&mut req, Duration::from_secs(3600), &credential)?;
    ///     // Sending already signed request.
    ///     let resp = client.execute(req).await?;
    ///     println!("resp got status: {}", resp.status());
    ///     Ok(())
    /// }
    /// ```
    pub fn sign_query(
        &self,
        req: &mut impl SignableRequest,
        expire: Duration,
        cred: &Credential,
    ) -> Result<()> {
        let ctx = self.build(req, SigningMethod::Query(expire), cred)?;
        req.apply(ctx)
    }
}

fn canonical_request_string(ctx: &mut SigningContext) -> Result<String> {
    // 256 is specially chosen to avoid reallocation for most requests.
    let mut f = String::with_capacity(256);

    // Insert method
    writeln!(f, "{}", ctx.method)?;
    // Insert encoded path
    let path = percent_decode_str(&ctx.path).decode_utf8()?;
    writeln!(
        f,
        "{}",
        utf8_percent_encode(&path, &super::constants::AWS_URI_ENCODE_SET)
    )?;
    // Insert query
    writeln!(
        f,
        "{}",
        ctx.query
            .iter()
            .map(|(k, v)| { format!("{k}={v}") })
            .collect::<Vec<_>>()
            .join("&")
    )?;
    // Insert signed headers
    let signed_headers = ctx.header_name_to_vec_sorted();
    for header in signed_headers.iter() {
        let value = &ctx.headers[*header];
        writeln!(
            f,
            "{}:{}",
            header,
            value.to_str().expect("header value must be valid")
        )?;
    }
    writeln!(f)?;
    writeln!(f, "{}", signed_headers.join(";"))?;

    if ctx.headers.get(X_AMZ_CONTENT_SHA_256).is_none() {
        write!(f, "UNSIGNED-PAYLOAD")?;
    } else {
        write!(f, "{}", ctx.headers[X_AMZ_CONTENT_SHA_256].to_str()?)?;
    }

    Ok(f)
}

fn canonicalize_header(
    ctx: &mut SigningContext,
    method: SigningMethod,
    cred: &Credential,
    now: DateTime,
) -> Result<()> {
    // Header names and values need to be normalized according to Step 4 of https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    for (_, value) in ctx.headers.iter_mut() {
        SigningContext::header_value_normalize(value)
    }

    // Insert HOST header if not present.
    if ctx.headers.get(header::HOST).is_none() {
        ctx.headers
            .insert(header::HOST, ctx.authority.as_str().parse()?);
    }

    if method == SigningMethod::Header {
        // Insert DATE header if not present.
        if ctx.headers.get(X_AMZ_DATE).is_none() {
            let date_header = HeaderValue::try_from(format_iso8601(now))?;
            ctx.headers.insert(X_AMZ_DATE, date_header);
        }

        // Insert X_AMZ_CONTENT_SHA_256 header if not present.
        if ctx.headers.get(X_AMZ_CONTENT_SHA_256).is_none() {
            ctx.headers.insert(
                X_AMZ_CONTENT_SHA_256,
                HeaderValue::from_static("UNSIGNED-PAYLOAD"),
            );
        }

        // Insert X_AMZ_SECURITY_TOKEN header if security token exists.
        if let Some(token) = &cred.session_token {
            let mut value = HeaderValue::from_str(token)?;
            // Set token value sensitive to valid leaking.
            value.set_sensitive(true);

            ctx.headers.insert(X_AMZ_SECURITY_TOKEN, value);
        }
    }

    Ok(())
}

fn canonicalize_query(
    ctx: &mut SigningContext,
    method: SigningMethod,
    cred: &Credential,
    now: DateTime,
    service: &str,
    region: &str,
) -> Result<()> {
    if let SigningMethod::Query(expire) = method {
        ctx.query
            .push(("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()));
        ctx.query.push((
            "X-Amz-Credential".into(),
            format!(
                "{}/{}/{}/{}/aws4_request",
                cred.access_key_id,
                format_date(now),
                region,
                service
            ),
        ));
        ctx.query.push(("X-Amz-Date".into(), format_iso8601(now)));
        ctx.query
            .push(("X-Amz-Expires".into(), expire.as_secs().to_string()));
        ctx.query.push((
            "X-Amz-SignedHeaders".into(),
            ctx.header_name_to_vec_sorted().join(";"),
        ));

        if let Some(token) = &cred.session_token {
            ctx.query
                .push(("X-Amz-Security-Token".into(), token.into()));
        }
    }

    // Return if query is empty.
    if ctx.query.is_empty() {
        return Ok(());
    }

    // Sort by param name
    ctx.query.sort();

    ctx.query = ctx
        .query
        .iter()
        .map(|(k, v)| {
            (
                utf8_percent_encode(k, &AWS_QUERY_ENCODE_SET).to_string(),
                utf8_percent_encode(v, &AWS_QUERY_ENCODE_SET).to_string(),
            )
        })
        .collect();

    Ok(())
}

fn generate_signing_key(secret: &str, time: DateTime, region: &str, service: &str) -> Vec<u8> {
    // Sign secret
    let secret = format!("AWS4{secret}");
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
    use aws_sigv4::http_request::PayloadChecksumKind;
    use aws_sigv4::http_request::PercentEncodingMode;
    use aws_sigv4::http_request::SignableBody;
    use aws_sigv4::http_request::SignableRequest;
    use aws_sigv4::http_request::SignatureLocation;
    use aws_sigv4::http_request::SigningSettings;
    use aws_sigv4::SigningParams;
    use http::header;
    use reqwest::Client;

    use super::super::AwsDefaultLoader;
    use super::*;
    use crate::aws::AwsConfig;

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

    fn test_put_request_with_body_digest() -> http::Request<&'static str> {
        let content = "Hello,World!";
        let mut req = http::Request::new(content);
        *req.method_mut() = http::Method::PUT;
        *req.uri_mut() = "http://127.0.0.1:9000/hello"
            .parse()
            .expect("url must be valid");

        req.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&content.len().to_string()).expect("must be valid"),
        );

        let body = hex_sha256(content.as_bytes());
        req.headers_mut().insert(
            "x-amz-content-sha256",
            HeaderValue::from_str(&body).expect("must be valid"),
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
            test_put_request_with_body_digest,
        ]
    }

    fn compare_request(name: &str, l: &http::Request<&str>, r: &http::Request<&str>) {
        fn format_headers(req: &http::Request<&str>) -> Vec<String> {
            let mut hs = req
                .headers()
                .iter()
                .map(|(k, v)| format!("{}:{}", k, v.to_str().expect("must be valid")))
                .collect::<Vec<_>>();

            // Insert host if original request doesn't have it.
            if !hs.contains(&format!("host:{}", req.uri().authority().unwrap())) {
                hs.push(format!("host:{}", req.uri().authority().unwrap()))
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
            let now = now();

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

            let mut body = SignableBody::UnsignedPayload;
            if req.headers().get(X_AMZ_CONTENT_SHA_256).is_some() {
                body = SignableBody::Bytes(req.body().as_bytes());
            }

            let output = aws_sigv4::http_request::sign(
                SignableRequest::new(req.method(), req.uri(), req.headers(), body),
                &sp,
            )
            .expect("signing must succeed");
            let (aws_sig, _) = output.into_parts();
            aws_sig.apply_to_request(&mut req);
            let expected_req = req;

            let mut req = req_fn();

            let loader = AwsDefaultLoader::new(
                Client::new(),
                AwsConfig {
                    access_key_id: Some("access_key_id".to_string()),
                    secret_access_key: Some("secret_access_key".to_string()),
                    ..Default::default()
                },
            );
            let cred = loader.load().await?.unwrap();

            let signer = Signer::new("s3", "test").time(now);
            signer.sign(&mut req, &cred).expect("must apply success");

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
            let now = now();

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

            let mut body = SignableBody::UnsignedPayload;
            if req.headers().get(X_AMZ_CONTENT_SHA_256).is_some() {
                body = SignableBody::Bytes(req.body().as_bytes());
            }

            let output = aws_sigv4::http_request::sign(
                SignableRequest::new(req.method(), req.uri(), req.headers(), body),
                &sp,
            )
            .expect("signing must succeed");
            let (aws_sig, _) = output.into_parts();
            aws_sig.apply_to_request(&mut req);
            let expected_req = req;

            let mut req = req_fn();

            let loader = AwsDefaultLoader::new(
                Client::new(),
                AwsConfig {
                    access_key_id: Some("access_key_id".to_string()),
                    secret_access_key: Some("secret_access_key".to_string()),
                    ..Default::default()
                },
            );
            let cred = loader.load().await?.unwrap();

            let signer = Signer::new("s3", "test").time(now);

            signer.sign_query(&mut req, Duration::from_secs(3600), &cred)?;
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
            let now = now();

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

            let mut body = SignableBody::UnsignedPayload;
            if req.headers().get(X_AMZ_CONTENT_SHA_256).is_some() {
                body = SignableBody::Bytes(req.body().as_bytes());
            }

            let output = aws_sigv4::http_request::sign(
                SignableRequest::new(req.method(), req.uri(), req.headers(), body),
                &sp,
            )
            .expect("signing must succeed");
            let (aws_sig, _) = output.into_parts();
            aws_sig.apply_to_request(&mut req);
            let expected_req = req;

            let mut req = req_fn();

            let loader = AwsDefaultLoader::new(
                Client::new(),
                AwsConfig {
                    access_key_id: Some("access_key_id".to_string()),
                    secret_access_key: Some("secret_access_key".to_string()),
                    session_token: Some("security_token".to_string()),
                    ..Default::default()
                },
            );
            let cred = loader.load().await?.unwrap();

            let signer = Signer::new("s3", "test").time(now);

            signer.sign(&mut req, &cred).expect("must apply success");
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
            let now = now();

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

            let mut body = SignableBody::UnsignedPayload;
            if req.headers().get(X_AMZ_CONTENT_SHA_256).is_some() {
                body = SignableBody::Bytes(req.body().as_bytes());
            }

            let output = aws_sigv4::http_request::sign(
                SignableRequest::new(req.method(), req.uri(), req.headers(), body),
                &sp,
            )
            .expect("signing must succeed");
            let (aws_sig, _) = output.into_parts();
            aws_sig.apply_to_request(&mut req);
            let expected_req = req;

            let mut req = req_fn();

            let loader = AwsDefaultLoader::new(
                Client::new(),
                AwsConfig {
                    access_key_id: Some("access_key_id".to_string()),
                    secret_access_key: Some("secret_access_key".to_string()),
                    session_token: Some("security_token".to_string()),
                    ..Default::default()
                },
            );
            let cred = loader.load().await?.unwrap();

            let signer = Signer::new("s3", "test").time(now);
            signer
                .sign_query(&mut req, Duration::from_secs(3600), &cred)
                .expect("must apply success");
            let actual_req = req;

            compare_request(&name, &expected_req, &actual_req);
        }

        Ok(())
    }
}
