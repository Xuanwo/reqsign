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

use super::constants::GOOG_QUERY_ENCODE_SET;

use crate::google::credential::Credential;
use crate::hash::hex_sha256;
use crate::request::SignableRequest;
use crate::time::format_date;
use crate::time::format_iso8601;
use crate::time::DateTime;
use crate::time::Duration;
use crate::time::{self};

use rsa::pkcs1v15::SigningKey;
use rsa::signature::RandomizedSigner;

/// Builder for `Signer`.
#[derive(Default)]
pub struct Builder {
    service: Option<String>,
    region: Option<String>,
    // config_loader: ConfigLoader,
    // credential_loader: Option<CredentialLoader>,
    credential: Option<Credential>,
    allow_anonymous: bool,

    time: Option<DateTime>,
}

impl Builder {
    /// Specify service like "s3".
    pub fn service(&mut self, service: &str) -> &mut Self {
        self.service = Some(service.to_string());
        self
    }

    /// Specify region like "us-east-1".
    /// If not set, use "auto" instead.
    pub fn region(&mut self, region: &str) -> &mut Self {
        self.region = Some(region.to_string());
        self
    }

    /// Allow anonymous request if credential is not loaded.
    #[allow(dead_code)]
    pub fn allow_anonymous(&mut self) -> &mut Self {
        self.allow_anonymous = true;
        self
    }

    /// Specify the credential
    pub fn credential(&mut self, cred: Credential) -> &mut Self {
        self.credential = Some(cred);
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

        let region = self.region.take().unwrap_or_else(|| "auto".to_string());
        let credential = self.credential.take();

        Ok(Signer {
            service: service.to_string(),
            region,
            credential,
            allow_anonymous: self.allow_anonymous,
            time: self.time,
        })
    }
}

/// Singer that implement Google     SigV4.
///
/// - [Signature Version 4 signing process](https://cloud.google.com/storage/docs/access-control/signing-urls-manually)
pub struct Signer {
    service: String,
    region: String,
    credential: Option<Credential>,

    /// Allow anonymous request if credential is not loaded.
    allow_anonymous: bool,

    time: Option<DateTime>,
}

impl Signer {
    /// Create a builder.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Get credential
    ///
    /// # Note
    ///
    /// This function should never be exported to avoid credential leaking by
    /// mistake.
    fn credential(&self) -> &Option<Credential> {
        &self.credential
    }

    fn canonicalize(
        &self,
        req: &impl SignableRequest,
        method: SigningMethod,
        cred: &Credential,
    ) -> Result<CanonicalRequest> {
        let mut creq = CanonicalRequest::new(req, method, self.time)?;
        creq.build_headers()?;
        creq.build_query(cred, &self.service, &self.region)?;

        debug!("calculated canonical request: {creq}");
        Ok(creq)
    }

    /// Calculate signing requests via SignableRequest.
    fn calculate(&self, mut creq: CanonicalRequest, cred: &Credential) -> Result<CanonicalRequest> {
        let encoded_req = hex_sha256(creq.to_string().as_bytes());

        // Scope: "20220313/<region>/<service>/goog4_request"
        let scope = format!(
            "{}/{}/{}/goog4_request",
            format_date(creq.signing_time),
            self.region,
            self.service
        );
        debug!("calculated scope: {scope}");

        // StringToSign:
        //
        // GOOG4-RSA-SHA256
        // 20220313T072004Z
        // 20220313/<region>/<service>/goog4_request
        // <hashed_canonical_request>
        let string_to_sign = {
            let mut f = String::new();
            writeln!(f, "GOOG4-RSA-SHA256")?;
            writeln!(f, "{}", format_iso8601(creq.signing_time))?;
            writeln!(f, "{}", &scope)?;
            write!(f, "{}", &encoded_req)?;
            f
        };
        debug!("calculated string to sign: {string_to_sign}");

        use rsa::pkcs8::DecodePrivateKey;

        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(cred.private_key())?;
        let signing_key = SigningKey::<rsa::sha2::Sha256>::new_with_prefix(private_key);
        let signature = signing_key.sign_with_rng(&mut rng, string_to_sign.as_bytes());
        let signature = signature.to_string();

        let mut query = creq
            .query
            .take()
            .expect("query must be valid in query signing");
        write!(query, "&X-Goog-Signature={signature}")?;

        creq.query = Some(query);

        Ok(creq)
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

    /// Signing request with query.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use anyhow::Result;
    /// use reqsign::AwsConfigLoader;
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
    ///         .config_loader(AwsConfigLoader::with_loaded())
    ///         .service("s3")
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
        let credential = self.credential().as_ref().unwrap();
        let creq = self.canonicalize(req, SigningMethod::Query(expire), credential)?;
        let creq = self.calculate(creq, credential)?;
        self.apply(req, creq)
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

    fn build_headers(&mut self) -> Result<()> {
        // Insert HOST header if not present.
        if self.headers.get(&http::header::HOST).is_none() {
            let header = HeaderValue::try_from(self.signing_host.to_string())?;
            self.headers.insert(http::header::HOST, header);
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

        let SigningMethod::Query(expire) = self.signing_method;
        params.push(("X-Goog-Algorithm".into(), "GOOG4-RSA-SHA256".into()));
        params.push((
            "X-Goog-Credential".into(),
            Cow::Owned(format!(
                "{}/{}/{}/{}/goog4_request",
                cred.client_email(),
                format_date(self.signing_time),
                region,
                service
            )),
        ));
        params.push((
            "X-Goog-Date".into(),
            Cow::Owned(format_iso8601(self.signing_time)),
        ));
        params.push((
            "X-Goog-Expires".into(),
            Cow::Owned(expire.whole_seconds().to_string()),
        ));
        params.push((
            "X-Goog-SignedHeaders".into(),
            self.signed_headers().join(";").into(),
        ));
        // Sort by param name
        params.sort();

        if params.is_empty() {
            return Ok(());
        }

        let param = params
            .iter()
            .map(|(k, v)| {
                (
                    utf8_percent_encode(k, &GOOG_QUERY_ENCODE_SET),
                    utf8_percent_encode(v, &GOOG_QUERY_ENCODE_SET),
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
            utf8_percent_encode(&self.path, &super::constants::GOOG_URI_ENCODE_SET)
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
