//! AWS service sigv4 signer


use std::fmt::Debug;

use std::fmt::Formatter;
use std::fmt::Write;

use anyhow::anyhow;
use anyhow::Result;
use http::HeaderValue;
use log::debug;



use crate::credential::Credential;


use crate::request::SignableRequest;


use crate::time::DateTime;
use crate::time::Duration;


use crate::utils::CanonicalRequest;
use crate::utils::SigningAlgorithm;
use crate::utils::SigningMethod;


use rsa;
use serde::Deserialize;

// implement serde deserialization for rsa::RsaPrivateKey
mod rsa_deserialize {
    use rsa;
    use rsa::pkcs8::DecodePrivateKey;
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<rsa::RsaPrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(rsa::RsaPrivateKey::from_pkcs8_pem(&s)
            .map_err(serde::de::Error::custom)?)
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
    Hmac(GoogleHmac),
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
        let mut creq = CanonicalRequest::new(
            req,
            method,
            self.time,
            SigningAlgorithm::Goog4Rsa,
            "europe-west3".to_string(),
            "storage".to_string(),
        )?;
        creq.build_headers(cred)?;
        creq.build_query(cred)?;

        debug!("calculated canonical request: {creq}");
        Ok(creq)
    }

    /// Calculate signing requests via SignableRequest.
    fn calculate(&self, mut creq: CanonicalRequest, cred: &Credential) -> Result<CanonicalRequest> {
        let signature = creq.calculate_signature(cred, &self.region, &self.service)?;

        println!(
            "calculated signature: {signature} (len: {})",
            signature.len()
        );

        // TODO fold into CanonicalRequest?
        match creq.signing_method {
            SigningMethod::Header => {
                let mut authorization = HeaderValue::from_str(&format!(
                    "{} Credential={}/{}, SignedHeaders={}, Signature={}",
                    self.algorithm_string(),
                    cred.access_key(),
                    creq.scope, // TODO refactor
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
        Some(Credential::new(self.config.authentication.access_key(), ""))
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
