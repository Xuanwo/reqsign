use crate::load::utils::sts_endpoint;
use crate::{Config, Credential};
use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;
use quick_xml::de;
use reqsign_core::time::parse_rfc3339;
use reqsign_core::{utils::Redact, Context, ProvideCredential};
use serde::Deserialize;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

/// AssumeRoleLoader will load credential via assume role.
#[derive(Debug)]
pub struct AssumeRoleWithWebIdentityLoader {
    config: Arc<Config>,
}

impl AssumeRoleWithWebIdentityLoader {
    /// Create a new `AssumeRoleWithWebIdentityLoader` instance.
    pub fn new(cfg: Arc<Config>) -> Self {
        Self { config: cfg }
    }
}

#[async_trait]
impl ProvideCredential for AssumeRoleWithWebIdentityLoader {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> anyhow::Result<Option<Self::Credential>> {
        let (token_file, role_arn) =
            match (&self.config.web_identity_token_file, &self.config.role_arn) {
                (Some(token_file), Some(role_arn)) => (token_file, role_arn),
                _ => return Ok(None),
            };

        let token = ctx.file_read_as_string(token_file).await?;
        let role_session_name = &self.config.role_session_name;

        let endpoint = sts_endpoint(&self.config)?;

        // Construct request to AWS STS Service.
        let url = format!("https://{endpoint}/?Action=AssumeRoleWithWebIdentity&RoleArn={role_arn}&WebIdentityToken={token}&Version=2011-06-15&RoleSessionName={role_session_name}");
        let req = http::request::Request::builder()
            .method("GET")
            .uri(url)
            .header(
                http::header::CONTENT_TYPE.as_str(),
                "application/x-www-form-urlencoded",
            )
            .body(Bytes::new())?;

        let resp = ctx.http_send_as_string(req).await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.into_body();
            return Err(anyhow!("request to AWS STS Services failed: {content}"));
        }

        let resp: AssumeRoleWithWebIdentityResponse = de::from_str(&resp.into_body())?;
        let resp_cred = resp.result.credentials;

        let cred = Credential {
            access_key_id: resp_cred.access_key_id,
            secret_access_key: resp_cred.secret_access_key,
            session_token: Some(resp_cred.session_token),
            expires_in: Some(parse_rfc3339(&resp_cred.expiration)?),
        };

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResponse {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    result: AssumeRoleWithWebIdentityResult,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResult {
    credentials: AssumeRoleWithWebIdentityCredentials,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

impl Debug for AssumeRoleWithWebIdentityCredentials {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssumeRoleWithWebIdentityCredentials")
            .field("access_key_id", &Redact::from(&self.access_key_id))
            .field("secret_access_key", &Redact::from(&self.secret_access_key))
            .field("session_token", &Redact::from(&self.session_token))
            .field("expiration", &self.expiration)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_parse_assume_role_with_web_identity_response() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let content = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Audience>test_audience</Audience>
    <AssumedRoleUser>
      <AssumedRoleId>role_id:reqsign</AssumedRoleId>
      <Arn>arn:aws:sts::123:assumed-role/reqsign/reqsign</Arn>
    </AssumedRoleUser>
    <Provider>arn:aws:iam::123:oidc-provider/example.com/</Provider>
    <Credentials>
      <AccessKeyId>access_key_id</AccessKeyId>
      <SecretAccessKey>secret_access_key</SecretAccessKey>
      <SessionToken>session_token</SessionToken>
      <Expiration>2022-05-25T11:45:17Z</Expiration>
    </Credentials>
    <SubjectFromWebIdentityToken>subject</SubjectFromWebIdentityToken>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>b1663ad1-23ab-45e9-b465-9af30b202eba</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>"#;

        let resp: AssumeRoleWithWebIdentityResponse =
            de::from_str(content).expect("xml deserialize must success");

        assert_eq!(&resp.result.credentials.access_key_id, "access_key_id");
        assert_eq!(
            &resp.result.credentials.secret_access_key,
            "secret_access_key"
        );
        assert_eq!(&resp.result.credentials.session_token, "session_token");
        assert_eq!(&resp.result.credentials.expiration, "2022-05-25T11:45:17Z");

        Ok(())
    }
}
