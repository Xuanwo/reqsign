use std::env;
use std::ops::{Add, Sub};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use http::header;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::{Body, Request};
use tokio::sync::RwLock;

use super::constants::GOOGLE_APPLICATION_CREDENTIALS;
use super::credential::{Claims, Credential, Token};
use crate::request::SignableRequest;
use crate::time::{self, DateTime, Duration};

#[derive(Debug, Default)]
pub struct Builder {
    scope: Option<String>,
    credential: Option<String>,
}

impl Builder {
    pub fn scope(&mut self, scope: &str) -> &mut Self {
        self.scope = Some(scope.to_string());
        self
    }
    pub fn credential(&mut self, credential: &str) -> &mut Self {
        self.credential = Some(credential.to_string());
        self
    }

    pub async fn build(&mut self) -> Result<Signer> {
        let scope = match &self.scope {
            Some(v) => v.clone(),
            None => return Err(anyhow!("google signer requires scope, but not set")),
        };

        let credential = match &self.credential {
            Some(v) => v.clone(),
            None => match env::var(GOOGLE_APPLICATION_CREDENTIALS) {
                Ok(v) => v,
                Err(err) => {
                    return Err(anyhow!(
                        "google signer requires credential file, but not found: {}",
                        err
                    ))
                }
            },
        };

        let content = tokio::fs::read(&credential).await?;
        let credential: Credential = serde_json::from_slice(&content)?;

        Ok(Signer {
            scope,
            credential,
            token: Arc::new(Default::default()),
            client: reqwest::Client::new(),
        })
    }
}

pub struct Signer {
    scope: String,
    credential: Credential,
    token: Arc<RwLock<Option<(Token, DateTime)>>>,

    client: reqwest::Client,
}

impl Signer {
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Exchange token via Google OAuth2 Service.
    ///
    /// Reference: [Using OAuth 2.0 for Server to Server Applications](https://developers.google.com/identity/protocols/oauth2/service-account#authorizingrequests)
    async fn exchange_token(&self) -> Result<Token> {
        let jwt = jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &Claims::new(self.credential.client_email(), &self.scope),
            &EncodingKey::from_rsa_pem(self.credential.private_key().as_bytes())?,
        )?;

        let mut req = Request::new(
            http::Method::POST,
            "https://oauth2.googleapis.com/token".parse()?,
        );
        // Insert content_type in header
        req.headers_mut().insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse()?,
        );
        *req.body_mut() = Some(Body::from(
            form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
                .append_pair("assertion", &jwt)
                .finish(),
        ));

        let resp = self.client.execute(req).await?;
        let content = resp.bytes().await?;
        let token: Token = serde_json::from_slice(&content)?;

        Ok(token)
    }

    async fn token(&self) -> Result<Option<Token>> {
        match self.token.read().await.clone() {
            None => return Ok(None),
            Some((token, expire_in)) => {
                if time::now() < expire_in.sub(Duration::minutes(2)) {
                    return Ok(Some(token));
                }
            }
        }

        let now = time::now();
        let token = self.exchange_token().await?;
        let mut lock = self.token.write().await;
        *lock = Some((
            token.clone(),
            now.add(Duration::seconds(token.expires_in() as i64)),
        ));
        Ok(Some(token))
    }

    /// TODO: we can also send API via signed JWT: [Addendum: Service account authorization without OAuth](https://developers.google.com/identity/protocols/oauth2/service-account#jwt-auth)
    pub async fn sign(&self, req: &mut impl SignableRequest) -> Result<()> {
        if let Some(token) = self.token().await? {
            req.apply_header(
                header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token()),
            )?;
            return Ok(());
        }

        Err(anyhow!("token not found"))
    }
}

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;
    use tokio::runtime::Runtime;

    use super::*;

    static TOKIO: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("runtime must be valid"));

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
                TOKIO.block_on(async {
                    let signer = Signer::builder()
                        .scope("test")
                        .build()
                        .await
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
                });
            },
        );
    }
}
