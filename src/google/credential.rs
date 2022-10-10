use std::fmt::Debug;
use std::fmt::Formatter;
use std::ops::Add;

use serde::Deserialize;
use serde::Serialize;

use crate::time::DateTime;

/// Credential is the file which stores service account's client_id and private key.
#[derive(Clone, Deserialize)]
pub struct Credential {
    #[serde(rename = "type")]
    typ: String,
    project_id: String,
    private_key: String,
    client_email: String,
    #[allow(dead_code)]
    client_id: String,
}

impl Credential {
    pub fn client_email(&self) -> &str {
        &self.client_email
    }
    pub fn private_key(&self) -> &str {
        &self.private_key
    }
}

/// Make sure `client_id` and `private_key` is redacted for Credential
impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("type", &self.typ)
            .field("project_id", &self.project_id)
            .field("client_email", &self.client_email)
            .field("client_id", &"<redacted>")
            .field("private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

pub enum CredentialLoader {
    Path(String),
    Content(String),
    None,
}

impl Default for CredentialLoader {
    fn default() -> Self {
        CredentialLoader::None
    }
}

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
