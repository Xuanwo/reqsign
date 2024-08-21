use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use http::header::CONTENT_TYPE;
use log::error;
use serde::Deserialize;

use crate::google::credential::impersonated_service_account::ImpersonatedServiceAccount;

use super::Token;
use super::TokenLoader;

#[derive(Clone, Deserialize, Default)]
#[cfg_attr(test, derive(Debug))]
#[serde(default, rename_all = "camelCase")]
struct ImpersonatedToken {
    access_token: String,
    expire_time: String,
}

/// The maximum impersonated token lifetime allowed, 1 hour.
const MAX_LIFETIME: Duration = Duration::from_secs(3600);

impl TokenLoader {
    pub(super) async fn load_via_impersonated_service_account(&self) -> Result<Option<Token>> {
        let Some(cred) = self
            .credential
            .as_ref()
            .and_then(|cred| cred.impersonated_service_account.as_ref())
        else {
            return Ok(None);
        };

        let bearer_auth_token = self.generate_bearer_auth_token(cred).await?;
        self.generate_access_token(cred, bearer_auth_token)
            .await
            .map(Some)
    }

    async fn generate_bearer_auth_token(&self, cred: &ImpersonatedServiceAccount) -> Result<Token> {
        let req = serde_json::json!({
            "grant_type": "refresh_token",
            "refresh_token": &cred.source_credentials.refresh_token,
            "client_id": &cred.source_credentials.client_id,
            "client_secret": &cred.source_credentials.client_secret,
        });

        let req = serde_json::to_vec(&req)?;

        let resp = self
            .client
            .post("https://oauth2.googleapis.com/token")
            .header(CONTENT_TYPE, "application/json")
            .body(req)
            .send()
            .await?;

        if !resp.status().is_success() {
            error!("bearer token loader for impersonated service account got unexpected response: {:?}", resp);
            bail!(
                "bearer token loader for impersonated service account failed: {}",
                resp.text().await?
            );
        }

        let token: Option<Token> = serde_json::from_slice(&resp.bytes().await?)?;
        let token = token.expect("couldn't parse bearer token response");

        Ok(token)
    }

    async fn generate_access_token(
        &self,
        cred: &ImpersonatedServiceAccount,
        temp_token: Token,
    ) -> Result<Token> {
        let req = serde_json::json!({
            "lifetime": format!("{}s", MAX_LIFETIME.as_secs()),
            "scope": &temp_token.scope.split(' ').collect::<Vec<&str>>(),
            "delegates": &cred.delegates,
        });

        let req = serde_json::to_vec(&req)?;

        let resp = self
            .client
            .post(&cred.service_account_impersonation_url)
            .header(CONTENT_TYPE, "application/json")
            .bearer_auth(temp_token.access_token)
            .body(req)
            .send()
            .await?;

        if !resp.status().is_success() {
            error!("access token loader for impersonated service account got unexpected response: {:?}", resp);
            bail!(
                "access token loader for impersonated service account failed: {}",
                resp.text().await?
            );
        }

        let token: Option<ImpersonatedToken> = serde_json::from_slice(&resp.bytes().await?)?;
        let token = token.expect("couldn't parse access token response");

        Ok(Token::new(&token.access_token, 3600, &temp_token.scope))
    }
}
