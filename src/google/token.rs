use std::fmt::Debug;
use std::fmt::Formatter;
use std::ops::Add;
use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use http::header;
use http::StatusCode;
use jsonwebtoken::Algorithm;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use log::error;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;
use time::Duration;

use super::credential::Credential;
use crate::time::now;
use crate::time::DateTime;
use crate::Error;
use crate::ErrorKind;
use crate::Result;

/// Token is the authentication methods used by google services.
///
/// Most of the time, they will be exchanged via application credentials.
#[derive(Clone, Deserialize, Default)]
#[serde(default)]
pub struct Token {
    access_token: String,
    scope: String,
    token_type: String,
    expires_in: usize,
}

impl Token {
    /// Create a new token.
    ///
    /// scope will looks like: `https://www.googleapis.com/auth/devstorage.read_only`.
    pub fn new(access_token: &str, expires_in: usize, scope: &str) -> Self {
        Self {
            access_token: access_token.to_string(),
            scope: scope.to_string(),
            expires_in,
            token_type: "Bearer".to_string(),
        }
    }

    /// Notes: don't allow get token from reqsign.
    pub(crate) fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Notes: don't allow get expires_in from reqsign.
    pub(crate) fn expires_in(&self) -> usize {
        self.expires_in
    }
}

/// Make sure `access_token` is redacted for Token
impl Debug for Token {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("access_token", &"<redacted>")
            .field("scope", &self.scope)
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// Claims is used to build JWT for google cloud.
///
/// ```json
/// {
///   "iss": "761326798069-r5mljlln1rd4lrbhg75efgigp36m78j5@developer.gserviceaccount.com",
///   "scope": "https://www.googleapis.com/auth/devstorage.read_only",
///   "aud": "https://oauth2.googleapis.com/token",
///   "exp": 1328554385,
///   "iat": 1328550785
/// }
/// ```
#[derive(Debug, Serialize)]
pub struct Claims {
    iss: String,
    scope: String,
    aud: String,
    exp: u64,
    iat: u64,
}

impl Claims {
    pub fn new(client_email: &str, scope: &str) -> Claims {
        let current = DateTime::now_utc().unix_timestamp() as u64;

        Claims {
            iss: client_email.to_string(),
            scope: scope.to_string(),
            aud: "https://oauth2.googleapis.com/token".to_string(),
            exp: current.add(3600),
            iat: current,
        }
    }
}

/// Loader trait will try to load credential from different sources.
#[async_trait]
pub trait TokenLoad: 'static + Send + Sync + Debug {
    /// Load credential from sources.
    ///
    /// - If succeed, return `Ok(Some(cred))`
    /// - If not found, return `Ok(None)`
    /// - If unexpected errors happened, return `Err(err)`
    async fn load(&self, clinet: Client) -> Result<Option<Token>>;
}

/// TokenLoader will load token from different methods.
#[cfg_attr(test, derive(Debug))]
pub struct TokenLoader {
    scope: String,
    client: Client,

    credentials: Option<Credential>,
    disable_vm_metadata: bool,
    service_account: Option<String>,
    customed_token_loader: Option<Box<dyn TokenLoad>>,

    token: Arc<Mutex<Option<(Token, DateTime)>>>,
}

impl TokenLoader {
    /// Create a new token loader.
    ///
    /// ## Scope
    ///
    /// For example, valid scopes for google cloud services should be
    ///
    /// - read-only: `https://www.googleapis.com/auth/devstorage.read_only`
    /// - read-write: `https://www.googleapis.com/auth/devstorage.read_write`
    /// - full-control: `https://www.googleapis.com/auth/devstorage.full_control`
    ///
    /// Reference: [Cloud Storage authentication](https://cloud.google.com/storage/docs/authentication)
    pub fn new(scope: &str, client: Client) -> Self {
        Self {
            scope: scope.to_string(),
            client,

            credentials: None,
            disable_vm_metadata: false,
            service_account: None,
            customed_token_loader: None,

            token: Arc::default(),
        }
    }

    /// Set the credential for token loader.
    pub fn with_credentials(mut self, credentials: Credential) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Disable vm metadata.
    pub fn with_disable_vm_metadata(mut self, disable_vm_metadata: bool) -> Self {
        self.disable_vm_metadata = disable_vm_metadata;
        self
    }

    /// Set the service account for token loader.
    pub fn with_service_account(mut self, service_account: &str) -> Self {
        self.service_account = Some(service_account.to_string());
        self
    }

    /// Set the customed token loader for token loader.
    pub fn with_customed_token_loader<T: TokenLoad + 'static>(
        mut self,
        customed_token_loader: T,
    ) -> Self {
        self.customed_token_loader = Some(Box::new(customed_token_loader));
        self
    }

    /// Load token from different sources.
    pub async fn load(&self) -> Result<Token> {
        match self.token.lock().expect("lock poisoned").clone() {
            Some((token, expire_in)) if now() < expire_in - Duration::minutes(2) => {
                return Ok(token)
            }
            _ => (),
        }

        let token = self.load_inner().await?;

        let expire_in = now() + Duration::seconds(token.expires_in() as i64);

        let mut lock = self.token.lock().expect("lock poisoned");
        *lock = Some((token.clone(), expire_in));

        Ok(token)
    }

    async fn load_inner(&self) -> Result<Token> {
        if let Ok(Some(token)) = self.exchange_token_via_customed_token_loader().await {
            return Ok(token);
        }

        if let Ok(Some(token)) = self.exchange_token_via_credential().await {
            return Ok(token);
        }

        if let Ok(Some(token)) = self.exchange_token_via_vm_metadata().await {
            return Ok(token);
        }

        Err(Error::new(
            ErrorKind::NotFound,
            "no token found for google service",
        ))
    }

    async fn exchange_token_via_customed_token_loader(&self) -> Result<Option<Token>> {
        match &self.customed_token_loader {
            Some(f) => f.load(self.client.clone()).await,
            None => Ok(None),
        }
    }

    /// Exchange token via Google OAuth2 Service.
    ///
    /// Reference: [Using OAuth 2.0 for Server to Server Applications](https://developers.google.com/identity/protocols/oauth2/service-account#authorizingrequests)
    async fn exchange_token_via_credential(&self) -> Result<Option<Token>> {
        let cred = if let Some(cred) = &self.credentials {
            cred
        } else {
            return Ok(None);
        };

        let jwt = jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &Claims::new(&cred.client_email, &self.scope),
            &EncodingKey::from_rsa_pem(cred.private_key.as_bytes())?,
        )?;

        let resp = self
            .client
            .post("https://oauth2.googleapis.com/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await?;

        if resp.status() != StatusCode::OK {
            error!("exchange token got unexpected response: {:?}", resp);
            return Err(Error::new(
                ErrorKind::Unexpected,
                &format!("exchange token failed: {}", resp.text().await?),
            ));
        }

        let token: Token = serde_json::from_slice(&resp.bytes().await?)?;
        Ok(Some(token))
    }

    /// Exchange token via vm metadata
    async fn exchange_token_via_vm_metadata(&self) -> Result<Option<Token>> {
        if self.disable_vm_metadata {
            return Ok(None);
        }

        // Use `default` if service account not set by user.
        let service_account = self.service_account.as_deref().unwrap_or("default");

        let url = format!("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/{service_account}/token?scopes={}", self.scope);

        let resp = self
            .client
            .get(&url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await?;

        let token: Token = serde_json::from_slice(&resp.bytes().await?)?;
        Ok(Some(token))
    }
}
