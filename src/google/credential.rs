use std::env;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::ops::Add;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::RwLock;
use std::thread::sleep;

use anyhow::anyhow;
use anyhow::Result;
use backon::ExponentialBackoff;
use http::header;
use http::StatusCode;
use jsonwebtoken::Algorithm;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use log::error;
use log::info;
use log::warn;
use serde::Deserialize;
use serde::Serialize;
use time::Duration;

use crate::hash::base64_decode;
use crate::time::now;
use crate::time::DateTime;

use super::constants::GOOGLE_APPLICATION_CREDENTIALS;

#[derive(Clone, Deserialize, Default)]
#[serde(default)]
pub struct Token {
    access_token: String,
    scope: String,
    token_type: String,
    expires_in: usize,
}

impl Token {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn expires_in(&self) -> usize {
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

/// Credential is the file which stores service account's client_id and private key.
#[derive(Clone, Deserialize)]
#[cfg_attr(test, derive(Debug))]
pub struct Credential {
    private_key: String,
    client_email: String,
}

impl Credential {
    pub fn client_email(&self) -> &str {
        &self.client_email
    }

    pub fn private_key(&self) -> &str {
        &self.private_key
    }
}

/// CredentialLoader will load credential from different methods.
#[cfg_attr(test, derive(Debug))]
pub struct CredentialLoader {
    credential: Arc<RwLock<Option<Credential>>>,
    credential_loaded: AtomicBool,
    token: Arc<RwLock<Option<(Token, DateTime)>>>,
    token_loaded: AtomicBool,

    allow_anonymous: bool,
    disable_env: bool,
    disable_well_known_location: bool,
    disable_vm_metadata: bool,

    service_account: Option<String>,
    scope: String,

    client: ureq::Agent,
}

impl Default for CredentialLoader {
    fn default() -> Self {
        let client = ureq::AgentBuilder::new()
            // Set overall timeout per-request to 32s.
            //
            // TODO: make this a config while needed.
            .timeout(std::time::Duration::from_secs(32))
            .build();

        Self {
            credential: Arc::default(),
            credential_loaded: AtomicBool::default(),
            token: Arc::default(),
            token_loaded: AtomicBool::default(),
            allow_anonymous: false,
            disable_env: false,
            disable_well_known_location: false,
            disable_vm_metadata: false,
            service_account: None,
            // Default to read-only if not set.
            scope: "read-only".to_string(),
            client,
        }
    }
}

impl CredentialLoader {
    /// Allow anonymous.
    ///
    /// By enabling this option, CredentialLoader will not retry after
    /// loading credential failed.
    pub fn with_allow_anonymous(mut self) -> Self {
        self.allow_anonymous = true;
        self
    }

    /// Disable load from env.
    pub fn with_disable_env(mut self) -> Self {
        self.disable_env = true;
        self
    }

    /// Disable load from well known location.
    pub fn with_disable_well_known_location(mut self) -> Self {
        self.disable_well_known_location = true;
        self
    }

    /// Disable load from vm metadata.
    pub fn with_disable_vm_metadata(mut self) -> Self {
        self.disable_vm_metadata = true;
        self
    }

    /// Build credential loader with given scope.
    pub fn with_scope(mut self, scope: &str) -> Self {
        self.scope = scope.to_string();
        self
    }

    /// Build credential loader with given service account.
    pub fn with_service_account(mut self, service_account: &str) -> Self {
        self.service_account = Some(service_account.to_string());
        self
    }

    /// Build credential loader with given Credential.
    pub fn with_credential(self, cred: Credential) -> Self {
        self.credential_loaded.store(true, Ordering::Relaxed);
        *self.credential.write().expect("lock poisoned") = Some(cred);
        self
    }

    /// Build credential loader from given path.
    pub fn from_path(path: &str) -> Result<Self> {
        let cred = Self::load_from_file(path)?;
        Ok(CredentialLoader::default().with_credential(cred))
    }

    /// Build credential loader from given base64 content.
    pub fn from_base64(content: &str) -> Result<Self> {
        let content = base64_decode(content);

        let cred: Credential = serde_json::from_slice(&content)
            .map_err(|err| anyhow!("deserialize credential of base64 failed: {err:?}"))?;
        Ok(CredentialLoader::default().with_credential(cred))
    }

    /// Load token from CredentialLoader.
    pub fn load(&self) -> Option<Token> {
        // Return cached credential if it has been loaded at least once.
        if self.token_loaded.load(Ordering::Relaxed) {
            match self.token.read().expect("lock poisoned").clone() {
                Some((token, expire_in)) if now() < expire_in - Duration::minutes(2) => {
                    return Some(token)
                }
                None if self.allow_anonymous => return None,
                _ => (),
            }
        }

        let mut retry = ExponentialBackoff::default()
            .with_max_times(4)
            .with_jitter();

        let token = loop {
            let token = self
                .exchange_token_via_credential()
                .map_err(|err| {
                    warn!("exchange token via credential failed: {err:?}");
                    err
                })
                .unwrap_or_default()
                .or_else(|| {
                    self.exchange_token_via_vm_metadata()
                        .map_err(|err| {
                            warn!("exchange token via vm metadata failed: {err:?}");
                            err
                        })
                        .unwrap_or_default()
                });

            match token {
                Some(token) => {
                    self.token_loaded.store(true, Ordering::Relaxed);
                    break token;
                }
                None if self.allow_anonymous => {
                    info!("load token failed but we allowing anonymous access");

                    self.token_loaded.store(true, Ordering::Relaxed);
                    return None;
                }
                None => match retry.next() {
                    Some(dur) => {
                        sleep(dur);
                        continue;
                    }
                    None => {
                        warn!("load token still failed after retry");
                        return None;
                    }
                },
            }
        };

        let expire_in = now() + Duration::seconds(token.expires_in() as i64);

        let mut lock = self.token.write().expect("lock poisoned");
        *lock = Some((token.clone(), expire_in));

        Some(token)
    }

    /// Exchange token via Google OAuth2 Service.
    ///
    /// Reference: [Using OAuth 2.0 for Server to Server Applications](https://developers.google.com/identity/protocols/oauth2/service-account#authorizingrequests)
    fn exchange_token_via_credential(&self) -> Result<Option<Token>> {
        let cred = if let Some(cred) = self.load_credential() {
            cred
        } else {
            return Ok(None);
        };

        let jwt = jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &Claims::new(cred.client_email(), &self.scope),
            &EncodingKey::from_rsa_pem(cred.private_key().as_bytes())?,
        )?;

        let resp = self
            .client
            .post("https://oauth2.googleapis.com/token")
            .set(
                header::CONTENT_TYPE.as_str(),
                "application/x-www-form-urlencoded",
            )
            .send_form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])?;

        if resp.status() != StatusCode::OK {
            error!("exchange token got unexpected response: {:?}", resp);
            return Err(anyhow!("exchange token failed: {:?}", resp));
        }

        let token: Token = serde_json::from_reader(resp.into_reader())?;
        Ok(Some(token))
    }

    /// Exchange token via vm metadata
    fn exchange_token_via_vm_metadata(&self) -> Result<Option<Token>> {
        if self.disable_vm_metadata {
            return Ok(None);
        }

        // Use `default` if service account not set by user.
        let service_account = self
            .service_account
            .clone()
            .unwrap_or_else(|| "default".to_string());

        let url = format!("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/{service_account}/token?scopes={}", self.scope);

        let resp = self
            .client
            .get(&url)
            .set("Metadata-Flavor", "Google")
            .call()
            .map_err(|err| {
                error!("get token from compute metadata failed: {err:?}");
                err
            })?;

        let token: Token = serde_json::from_reader(resp.into_reader())?;
        Ok(Some(token))
    }

    fn load_credential(&self) -> Option<Credential> {
        // Return cached credential if it has been loaded at least once.
        if self.credential_loaded.load(Ordering::Relaxed) {
            if let Some(cred) = self.credential.read().expect("lock poisoned").clone() {
                return Some(cred);
            }
        }

        let cred = self
            .load_via_env()
            .map_err(|err| {
                warn!("load credential via env failed: {err:?}");
                err
            })
            .unwrap_or_default()
            .or_else(|| {
                self.load_via_well_known_location()
                    .map_err(|err| {
                        warn!("load credential via well known location failed: {err:?}");
                        err
                    })
                    .unwrap_or_default()
            });

        self.credential_loaded.store(true, Ordering::Relaxed);

        if let Some(cred) = &cred {
            let mut lock = self.credential.write().expect("lock poisoned");
            *lock = Some(cred.clone());
        }

        cred
    }

    /// Load from env GOOGLE_APPLICATION_CREDENTIALS.
    fn load_via_env(&self) -> Result<Option<Credential>> {
        if self.disable_env {
            return Ok(None);
        }

        if let Ok(cred_path) = env::var(GOOGLE_APPLICATION_CREDENTIALS) {
            let cred = Self::load_from_file(&cred_path)?;
            Ok(Some(cred))
        } else {
            Ok(None)
        }
    }

    /// Load from well known locations:
    ///
    /// - `$HOME/.config/gcloud/application_default_credentials.json`
    /// - `%APPDATA%\gcloud\application_default_credentials.json`
    fn load_via_well_known_location(&self) -> Result<Option<Credential>> {
        if self.disable_well_known_location {
            return Ok(None);
        }

        let config_dir = if let Ok(v) = env::var("APPDATA") {
            v
        } else if let Ok(v) = env::var("XDG_CONFIG_HOME") {
            v
        } else if let Ok(v) = env::var("HOME") {
            format!("{v}/.config")
        } else {
            // User's env doesn't have a config dir.
            return Ok(None);
        };

        let cred = Self::load_from_file(&format!(
            "{config_dir}/gcloud/application_default_credentials.json"
        ))?;
        Ok(Some(cred))
    }

    /// Load credential from given path.
    fn load_from_file(path: &str) -> Result<Credential> {
        let content = std::fs::read(path)
            .map_err(|err| anyhow!("load credential from file {path} failed: {err:?}"))?;

        let credential: Credential = serde_json::from_slice(&content)
            .map_err(|err| anyhow!("deserialize credential of file {path} failed: {err:?}"))?;

        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_loader() {
        temp_env::with_vars(
            vec![(
                GOOGLE_APPLICATION_CREDENTIALS,
                Some(format!(
                    "{}/testdata/services/google/test_credential.json",
                    env::current_dir()
                        .expect("current_dir must exist")
                        .to_string_lossy()
                )),
            )],
            || {
                let cred_loader = CredentialLoader::default();

                let cred = cred_loader
                    .load_credential()
                    .expect("credentail must be exist");

                assert_eq!("test-234@test.iam.gserviceaccount.com", cred.client_email());
                assert_eq!(
                    "-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDOy4jaJIcVlffi5ENtlNhJ0tsI1zt21BI3DMGtPq7n3Ymow24w
BV2Z73l4dsqwRo2QVSwnCQ2bVtM2DgckMNDShfWfKe3LRcl96nnn51AtAYIfRnc+
ogstzxZi4J64f7IR3KIAFxJnzo+a6FS6MmsYMAs8/Oj68fRmCD0AbAs5ZwIDAQAB
AoGAVpPkMeBFJgZph/alPEWq4A2FYogp/y/+iEmw9IVf2PdpYNyhTz2P2JjoNEUX
ywFe12SxXY5uwfBx8RmiZ8aARkIBWs7q9Sz6f/4fdCHAuu3GAv5hmMO4dLQsGcKl
XAQW4QxZM5/x5IXlDh4KdcUP65P0ZNS3deqDlsq/vVfY9EECQQD9I/6KNmlSrbnf
Fa/5ybF+IV8mOkEfkslQT4a9pWbA1FF53Vk4e7B+Faow3uUGHYs/HUwrd3vIVP84
S+4Jeuc3AkEA0SGF5l3BrWWTok1Wr/UE+oPOUp2L4AV6kH8co11ZyxSQkRloLdMd
bNzNXShuhwgvNjvgkseNSeQPJKxFRn73UQJACacMtrJ6c6eiNcp66lhxhzC4kxmX
kB+lw4U0yxh6gZHXBYGWPFwjD7u9wJ1POFt6Cs8QL3wf4TS0gq4KhpwEIwJACIA8
WSjmfo3qemZ6Z5ymHyjMcj9FOE4AtW71Uw6wX7juR3eo7HPwdkRjdK34EDUc9i9o
6Y6DB8Xld7ApALyYgQJBAPTMFpKpCRNvYH5VrdObid5+T7OwDrJFHGWdbDGiT++O
V08rl535r74rMilnQ37X1/zaKBYyxpfhnd2XXgoCgTM=
-----END RSA PRIVATE KEY-----
",
                    cred.private_key()
                );
            },
        );
    }
}
