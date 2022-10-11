use std::env;
use std::ops::Add;
use std::ops::Sub;
use std::sync::Arc;
use std::sync::RwLock;

use anyhow::anyhow;
use anyhow::Result;
use http::header;
use http::StatusCode;
use jsonwebtoken::Algorithm;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use log::error;

use super::constants::GOOGLE_APPLICATION_CREDENTIALS;
use super::credential::Claims;
use super::credential::Credential;
use super::credential::CredentialLoader;
use super::credential::Token;
use crate::hash::base64_decode;
use crate::request::SignableRequest;
use crate::time::DateTime;
use crate::time::Duration;
use crate::time::{self};

/// Builder for Signer.
#[derive(Default)]
pub struct Builder {
    scope: Option<String>,
    credential: CredentialLoader,
}

impl Builder {
    /// Specify scope url for Signer.
    ///
    /// For example, valid scopes for google cloud services should be
    ///
    /// - read-only: `https://www.googleapis.com/auth/devstorage.read_only`
    /// - read-write: `https://www.googleapis.com/auth/devstorage.read_write`
    /// - full-control: `https://www.googleapis.com/auth/devstorage.full_control`
    ///
    /// Reference: [Cloud Storage authentication](https://cloud.google.com/storage/docs/authentication)
    pub fn scope(&mut self, scope: &str) -> &mut Self {
        self.scope = Some(scope.to_string());
        self
    }

    /// Load credential from path.
    ///
    /// The credential should be generated by Google Cloud Platform.
    ///
    /// Read more in [Authenticating as a service account](https://cloud.google.com/docs/authentication/production)
    pub fn credential_from_path(&mut self, path: &str) -> &mut Self {
        self.credential = CredentialLoader::Path(path.to_string());
        self
    }

    /// Load credential from base64 content.
    ///
    /// The credential should be generated by Google Cloud Platform.
    ///
    /// Read more in [Authenticating as a service account](https://cloud.google.com/docs/authentication/production)
    pub fn credential_from_content(&mut self, credential: &str) -> &mut Self {
        self.credential = CredentialLoader::Content(credential.to_string());
        self
    }

    /// Use exising information to build a new signer.
    ///
    ///
    /// The builder should not be used anymore.
    pub fn build(&mut self) -> Result<Signer> {
        let scope = match &self.scope {
            Some(v) => v.clone(),
            None => return Err(anyhow!("google signer requires scope, but not set")),
        };

        let credential_content = match &self.credential {
            CredentialLoader::Path(v) => std::fs::read(&v)?,
            CredentialLoader::Content(v) => base64_decode(v),
            CredentialLoader::None => match env::var(GOOGLE_APPLICATION_CREDENTIALS) {
                Ok(v) => std::fs::read(&v)?,
                Err(err) => {
                    return Err(anyhow!(
                        "google signer requires credential file, but not found: {}",
                        err
                    ))
                }
            },
        };

        let credential: Credential = serde_json::from_slice(&credential_content)?;

        Ok(Signer {
            scope,
            credential,
            token: Arc::new(RwLock::new((Token::default(), DateTime::now_utc()))),
            client: ureq::Agent::new(),
        })
    }
}

/// Singer that implement Google OAuth2 Authentication.
///
/// ## Reference
///
/// -  [Authenticating as a service account](https://cloud.google.com/docs/authentication/production)
pub struct Signer {
    scope: String,
    credential: Credential,
    token: Arc<RwLock<(Token, DateTime)>>,

    client: ureq::Agent,
}

impl Signer {
    /// Create a builder of Signer.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Exchange token via Google OAuth2 Service.
    ///
    /// Reference: [Using OAuth 2.0 for Server to Server Applications](https://developers.google.com/identity/protocols/oauth2/service-account#authorizingrequests)
    fn exchange_token(&self) -> Result<Token> {
        let jwt = jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &Claims::new(self.credential.client_email(), &self.scope),
            &EncodingKey::from_rsa_pem(self.credential.private_key().as_bytes())?,
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
        Ok(token)
    }

    fn token(&self) -> Result<Token> {
        let (token, expire_in) = self.token.read().expect("lock poisoned").clone();
        if time::now() < expire_in.sub(Duration::minutes(2)) {
            return Ok(token);
        }

        let now = time::now();
        let token = self.exchange_token()?;
        let mut lock = self.token.write().expect("lock poisoned");
        *lock = (
            token.clone(),
            now.add(Duration::seconds(token.expires_in() as i64)),
        );
        Ok(token)
    }

    /// Signing request.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use anyhow::Result;
    /// use reqsign::GoogleSigner;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     // Signer will load region and credentials from environment by default.
    ///     let signer = GoogleSigner::builder()
    ///         .scope("https://www.googleapis.com/auth/devstorage.read_only")
    ///         .credential_from_path("/path/to/credential/file")
    ///         .build()?;
    ///
    ///     // Construct request
    ///     let url = Url::parse("https://storage.googleapis.com/storage/v1/b/test")?;
    ///     let mut req = reqwest::Request::new(http::Method::GET, url);
    ///
    ///     // Signing request with Signer
    ///     signer.sign(&mut req)?;
    ///
    ///     // Sending already signed request.
    ///     let resp = Client::new().execute(req).await?;
    ///     println!("resp got status: {}", resp.status());
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # TODO
    ///
    /// we can also send API via signed JWT: [Addendum: Service account authorization without OAuth](https://developers.google.com/identity/protocols/oauth2/service-account#jwt-auth)
    pub fn sign(&self, req: &mut impl SignableRequest) -> Result<()> {
        let token = self.token()?;
        req.insert_header(header::AUTHORIZATION, {
            let mut value: http::HeaderValue =
                format!("Bearer {}", token.access_token()).parse()?;
            value.set_sensitive(true);

            value
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder() {
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
                let signer = Signer::builder()
                    .scope("test")
                    .build()
                    .expect("signer must be valid");
                assert_eq!(
                    "test-234@test.iam.gserviceaccount.com",
                    signer.credential.client_email()
                );
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
                    signer.credential.private_key()
                );
            },
        );
    }
}
