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
use rsa::pkcs1v15::SigningKey;
use super::constants::GOOG_QUERY_ENCODE_SET;
use super::constants::GOOG_URI_ENCODE_SET;
use super::constants::X_GOOG_DATE;
use super::constants::X_GOOG_CONTENT_SHA_256;
use super::constants::X_GOOG_SECURITY_TOKEN;

// use super::config::ConfigLoader;
use super::credential::CredentialLoader;
// use super::region::RegionLoader;
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

use rsa;
use serde::Deserialize;

// implement serde deserialization for rsa::RsaPrivateKey
mod rsa_deserialize {
    use rsa::pkcs8::DecodePrivateKey;
    use serde::{Deserialize, Deserializer};
    use rsa;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<rsa::RsaPrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(rsa::RsaPrivateKey::from_pkcs8_pem(&s)
            .map_err(serde::de::Error::custom)?
            .into())
    }    
}

#[derive(Debug, Clone, Deserialize)]
pub struct GoogleAuthentication {
    #[serde(rename = "type")]
    type_: String,
    project_id: String,
    #[serde(deserialize_with = "rsa_deserialize::deserialize")]
    private_key: rsa::RsaPrivateKey,
    private_key_id: String,
    client_email: String,
    client_id: String,
    auth_uri: String,
    token_uri: String,
    auth_provider_x509_cert_url: String,
    client_x509_cert_url: String,
}

#[derive(Debug, Clone)]
pub struct GoogleHmac {
    access_key: String,
    secret_key: String,
}

#[derive(Debug, Clone)]
pub enum Authentication {
    Rsa(GoogleAuthentication),
    Hmac(GoogleHmac)
}

impl Authentication {
    pub fn access_key(&self) -> &str {
        match self {
            Authentication::Rsa(auth) => &auth.client_email,
            Authentication::Hmac(auth) => &auth.access_key,
        }
    }

    pub fn secret_key(&self) -> &str {
        match self {
            Authentication::Rsa(auth) => &auth.private_key_id,
            Authentication::Hmac(auth) => &auth.secret_key,
        }
    }

    pub fn rsa_key(&self) -> Option<&rsa::RsaPrivateKey> {
        match self {
            Authentication::Rsa(auth) => Some(&auth.private_key),
            Authentication::Hmac(_) => None,
        }
    }

    pub fn from_filename(filename: &str) -> Result<Self> {
        let file = std::fs::File::open(filename)?;
        let auth: GoogleAuthentication = serde_json::from_reader(file)?;
        Ok(Authentication::Rsa(auth))
    }

    pub fn from_hmac(access_key: &str, secret_key: &str) -> Self {
        Authentication::Hmac(GoogleHmac {
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
        })
    }
}

#[derive(Clone)]
pub struct Config {
    pub authentication: Authentication,
    pub region: String,
}

/// Builder for `Signer`.
#[derive(Default)]
pub struct Builder {
    service: Option<String>,

    // config_loader: ConfigLoaderV4,
    // credential_loader: Option<CredentialLoader>,
    config: Option<Config>,
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
    // pub fn config_loader(&mut self, cfg: ConfigLoaderV4) -> &mut Self {
    //     self.config_loader = cfg;
    //     self
    // }

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

    pub fn config(&mut self, config: Config) -> &mut Self {
        self.config = Some(config);
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

        // let cred_loader = match self.credential_loader.take() {
        //     Some(cred) => cred,
        //     None => {
        //         let mut loader = CredentialLoader::new(self.config_loader.clone());
        //         if self.allow_anonymous {
        //             loader = loader.with_allow_anonymous();
        //         }
        //         loader
        //     }
        // };

        // let region_loader = RegionLoader::new(self.config_loader.clone());
        // let region = "us-east-1";
        // let region = region_loader
        //     .load()
        //     .ok_or_else(|| anyhow!("region is missing"))?;
        // debug!("signer region: {}", &region);
        let config = self.config.as_ref().expect("No config available");
        Ok(Signer {
            region: config.region.to_string(),
            service: service.to_string(),
            config: config.clone(),
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
    config: Config,
    // credential_loader: CredentialLoader,

    /// Allow anonymous request if credential is not loaded.
    allow_anonymous: bool,

    time: Option<DateTime>,
}

impl Signer {
    /// Create a builder.
    pub fn builder() -> Builder {
        Builder::default()
    }

    fn algorithm_string(&self) -> &str {
        match self.config.authentication {
            Authentication::Rsa(_) => "GOOG4-RSA-SHA256",
            Authentication::Hmac(_) => "GOOG4-HMAC-SHA256",
        }
    }

    /// Load credential via credential load chain specified while building.
    ///
    /// # Note
    ///
    /// This function should never be exported to avoid credential leaking by
    /// mistake.
    fn canonicalize(
        &self,
        req: &impl SignableRequest,
        method: SigningMethod,
        cred: &Credential,
    ) -> Result<CanonicalRequest> {
        let mut creq = CanonicalRequest::new(req, method, self.time)?;
        creq.build_headers(cred)?;
        creq.build_query(cred, &self.service, &self.region, &self.algorithm_string())?;

        debug!("calculated canonical request: {creq}");
        Ok(creq)
    }

    /// Calculate signing requests via SignableRequest.
    fn calculate(&self, mut creq: CanonicalRequest, cred: &Credential) -> Result<CanonicalRequest> {
        let encoded_req = hex_sha256(creq.to_string().as_bytes());

        // NOTE: google also allows /auto/storage/ ... (no region)
        // Scope: "20220313/<region>/<service>/aws4_request"
        let scope = format!(
            "{}/{}/{}/goog4_request",
            format_date(creq.signing_time),
            self.region,
            self.service
        );
        debug!("calculated scope: {scope}");

        // StringToSign:
        //
        // GOOG4-HMAC-SHA256
        // 20220313T072004Z
        // 20220313/<region>/<service>/aws4_request
        // <hashed_canonical_request>
        let string_to_sign = {
            let mut f = String::new();
            writeln!(f, "{}", self.algorithm_string())?;
            writeln!(f, "{}", format_iso8601(creq.signing_time))?;
            writeln!(f, "{}", &scope)?;
            write!(f, "{}", &encoded_req)?;
            f
        };
        debug!("calculated string to sign: {string_to_sign}");

        let signature = match &self.config.authentication {
            Authentication::Rsa(rsa) => {
                use rsa::signature::RandomizedSigner;
                let mut rng = rand::thread_rng();
                let signing_key = SigningKey::<rsa::sha2::Sha256>::new_with_prefix(rsa.private_key.clone());
                let signature = signing_key.sign_with_rng(&mut rng, string_to_sign.as_bytes());
                signature.to_string()   
            }
            Authentication::Hmac(hmac) => {
                let signing_key = generate_signing_key(
                    hmac.secret_key.as_str(),
                    creq.signing_time,
                    &self.region,
                    &self.service,
                    SigningKeyFlavor::Google
                );
                hex_hmac_sha256(&signing_key, string_to_sign.as_bytes())
            }
        };

        println!("calculated signature: {signature} (len: {})", signature.len());

        match creq.signing_method {
            SigningMethod::Header => {
                let mut authorization = HeaderValue::from_str(&format!(
                    "{} Credential={}/{}, SignedHeaders={}, Signature={}",
                    self.algorithm_string(),
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
                write!(query, "&X-Goog-Signature={signature}")?;

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
    /// ```no_run
    /// use anyhow::Result;
    /// use reqsign::AwsConfigLoader;
    /// use reqsign::AwsV4Signer;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
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

    fn credential(&self) -> Option<Credential> {
        Some(Credential::new(
            self.config.authentication.access_key(),
            ""
        ))
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
            if self.headers.get(X_GOOG_DATE).is_none() {
                let date_header = HeaderValue::try_from(format_iso8601(self.signing_time))?;
                self.headers.insert(X_GOOG_DATE, date_header);
            }

            // Insert X_GOOG_CONTENT_SHA_256 header if not present.
            if self.headers.get(X_GOOG_CONTENT_SHA_256).is_none() {
                self.headers.insert(
                    X_GOOG_CONTENT_SHA_256,
                    HeaderValue::from_static("UNSIGNED-PAYLOAD"),
                );
            }

            // Insert X_GOOG_SECURITY_TOKEN header if security token exists.
            if let Some(token) = cred.security_token() {
                let mut value = HeaderValue::from_str(token)?;
                // Set token value sensitive to valid leaking.
                value.set_sensitive(true);

                self.headers.insert(X_GOOG_SECURITY_TOKEN, value);
            }
        }

        Ok(())
    }

    fn signed_headers(&self) -> Vec<&str> {
        let mut signed_headers = self.headers.keys().map(|v| v.as_str()).collect::<Vec<_>>();
        signed_headers.sort_unstable();

        signed_headers
    }

    fn build_query(&mut self, cred: &Credential, service: &str, region: &str, algorithm_string: &str) -> Result<()> {
        let query = self.query.take().unwrap_or_default();
        let mut params: Vec<_> = form_urlencoded::parse(query.as_bytes()).collect();

        if let SigningMethod::Query(expire) = self.signing_method {
            params.push(("X-Goog-Algorithm".into(), algorithm_string.into()));
            params.push((
                "X-Goog-Credential".into(),
                Cow::Owned(format!(
                    "{}/{}/{}/{}/goog4_request",
                    cred.access_key(),
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

            // TOOD unsure if this is needed
            if let Some(token) = cred.security_token() {
                params.push(("X-Goog-Security-Token".into(), token.into()));
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
            utf8_percent_encode(&self.path, &GOOG_URI_ENCODE_SET)
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

enum SigningKeyFlavor {
    Aws, 
    Google
}

fn generate_signing_key(secret: &str, time: DateTime, region: &str, service: &str, signing_key_flavor: SigningKeyFlavor) -> Vec<u8> {
    // Sign secret
    let secret = match signing_key_flavor {
        SigningKeyFlavor::Aws => format!("AWS4{}", secret),
        SigningKeyFlavor::Google => format!("GOOG4{}", secret)
    };
    // Sign date
    let sign_date = hmac_sha256(secret.as_bytes(), format_date(time).as_bytes());
    // Sign region
    let sign_region = hmac_sha256(sign_date.as_slice(), region.as_bytes());
    // Sign service
    let sign_service = hmac_sha256(sign_region.as_slice(), service.as_bytes());
    // Sign request
    let sign_request = match signing_key_flavor {
        SigningKeyFlavor::Aws => hmac_sha256(sign_service.as_slice(), "aws4_request".as_bytes()),
        SigningKeyFlavor::Google => hmac_sha256(sign_service.as_slice(), "goog4_request".as_bytes())
    };

    sign_request
}