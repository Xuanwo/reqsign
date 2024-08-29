use anyhow::bail;
use anyhow::Result;
use http::header;
use jsonwebtoken::Algorithm;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use log::error;

use super::Claims;
use super::Token;
use super::TokenLoader;

impl TokenLoader {
    /// Exchange token via Google OAuth2 Service.
    ///
    /// Reference: [Using OAuth 2.0 for Server to Server Applications](https://developers.google.com/identity/protocols/oauth2/service-account#authorizingrequests)
    pub(super) async fn load_via_service_account(&self) -> Result<Option<Token>> {
        let Some(cred) = self
            .credential
            .as_ref()
            .and_then(|cred| cred.service_account.as_ref())
        else {
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

        let token = serde_json::from_slice(&resp.bytes().await?)?;
        Ok(Some(token))
    }
}
