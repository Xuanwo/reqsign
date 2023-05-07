use anyhow::{bail, Result};
use http::header;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use log::error;

use super::{Claims, Credential, Token, TokenLoader};

impl TokenLoader {
    /// Exchange token via Google OAuth2 Service.
    ///
    /// Reference: [Using OAuth 2.0 for Server to Server Applications](https://developers.google.com/identity/protocols/oauth2/service-account#authorizingrequests)
    pub(super) async fn load_via_service_account(&self) -> Result<Option<Token>> {
        let cred = if let Some(Credential::ServiceAccount(cred)) = &self.credential {
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

        if !resp.status().is_success() {
            error!("exchange token got unexpected response: {:?}", resp);
            bail!("exchange token failed: {}", resp.text().await?);
        }

        let token: Token = serde_json::from_slice(&resp.bytes().await?)?;
        Ok(Some(token))
    }
}
