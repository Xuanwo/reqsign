use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use http::header::ACCEPT;
use http::header::CONTENT_TYPE;
use log::error;
use serde::Deserialize;

use super::Token;
use super::TokenLoader;
use crate::google::credential::external_account::CredentialSource;
use crate::google::credential::ExternalAccount;

/// The maximum impersonated token lifetime allowed, 1 hour.
const MAX_LIFETIME: Duration = Duration::from_secs(3600);

#[derive(Clone, Deserialize, Default)]
#[cfg_attr(test, derive(Debug))]
#[serde(default, rename_all = "camelCase")]
struct ImpersonatedToken {
    access_token: String,
    expire_time: String,
}

// As documented in https://google.aip.dev/auth/4117
async fn load_security_token(
    cred: &ExternalAccount,
    oidc_token: &str,
    client: &reqwest::Client,
) -> Result<Token> {
    // As documented in https://cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token.
    let req = serde_json::json!({
        "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",

        "audience": &cred.audience,
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "subjectToken": oidc_token,
        "subjectTokenType": &cred.subject_token_type,
    });

    let req = serde_json::to_vec(&req)?;

    let resp = client
        .post(&cred.token_url)
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .body(req)
        .send()
        .await?;

    if !resp.status().is_success() {
        error!("exchange token got unexpected response: {:?}", resp);
        bail!("exchange token failed: {}", resp.text().await?);
    }

    let token = serde_json::from_slice(&resp.bytes().await?)?;
    Ok(token)
}

async fn load_impersonated_token(
    cred: &ExternalAccount,
    access_token: &str,
    scope: &str,
    client: &reqwest::Client,
) -> Result<Option<Token>> {
    let Some(url) = &cred.service_account_impersonation_url else {
        return Ok(None);
    };

    let lifetime = cred
        .service_account_impersonation
        .as_ref()
        .and_then(|s| s.token_lifetime_seconds)
        .unwrap_or(MAX_LIFETIME.as_secs() as usize);

    let req = serde_json::json!({
        "scope": [scope],
        "lifetime": format!("{lifetime}s"),
    });

    let req = serde_json::to_vec(&req)?;

    let resp = client
        .post(url)
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .bearer_auth(access_token)
        .body(req)
        .send()
        .await?;

    if !resp.status().is_success() {
        error!("impersonated token got unexpected response: {:?}", resp);
        bail!("exchange impersonated token failed: {}", resp.text().await?);
    }

    let token: ImpersonatedToken = serde_json::from_slice(&resp.bytes().await?)?;
    Ok(Some(Token::new(&token.access_token, lifetime, scope)))
}

impl TokenLoader {
    /// Exchange token via Google's External Account Credentials.
    ///
    /// Reference: [External Account Credentials (Workload Identity Federation)](https://google.aip.dev/auth/4117)
    pub(super) async fn load_via_external_account(&self) -> Result<Option<Token>> {
        let Some(cred) = self
            .credential
            .as_ref()
            .and_then(|cred| cred.external_account.as_ref())
        else {
            return Ok(None);
        };

        let oidc_token =
            credential_source::load_oidc_token(&cred.credential_source, &self.client).await?;

        let sts = load_security_token(cred, &oidc_token, &self.client).await?;
        let token = load_impersonated_token(cred, sts.access_token(), &self.scope, &self.client)
            .await?
            .unwrap_or(sts);

        Ok(Some(token))
    }
}

mod credential_source {
    use std::io::Read;

    use http::header::HeaderName;
    use http::HeaderMap;
    use http::HeaderValue;

    use super::*;
    use crate::external_account::FileSourcedCredentials;
    use crate::external_account::UrlSourcedCredentials;

    pub(super) async fn load_oidc_token(
        source: &CredentialSource,
        client: &reqwest::Client,
    ) -> Result<String> {
        match source {
            CredentialSource::FileSourced(source) => load_file_sourced_oidc_token(source),
            CredentialSource::UrlSourced(source) => {
                load_url_sourced_oidc_token(source, client).await
            }
        }
    }

    async fn load_url_sourced_oidc_token(
        source: &UrlSourcedCredentials,
        client: &reqwest::Client,
    ) -> Result<String> {
        let headers: HeaderMap = source
            .headers
            .iter()
            .map(|(key, value)| Ok((HeaderName::try_from(key)?, HeaderValue::try_from(value)?)))
            .collect::<Result<_>>()?;

        let resp = client.get(&source.url).headers(headers).send().await?;
        if !resp.status().is_success() {
            error!("exchange token got unexpected response: {:?}", resp);
            bail!("exchange OIDC token failed: {}", resp.text().await?);
        }

        let body = resp.bytes().await?;
        source.format.parse(&body)
    }

    fn load_file_sourced_oidc_token(source: &FileSourcedCredentials) -> Result<String> {
        let mut file = std::fs::OpenOptions::new().read(true).open(&source.file)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        source.format.parse(&buf)
    }
}
