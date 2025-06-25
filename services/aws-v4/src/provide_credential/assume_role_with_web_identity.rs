use crate::provide_credential::utils::sts_endpoint;
use crate::Credential;
use async_trait::async_trait;
use bytes::Bytes;
use quick_xml::de;
use reqsign_core::time::parse_rfc3339;
use reqsign_core::{utils::Redact, Context, Error, ProvideCredential, Result};
use serde::Deserialize;
use std::fmt::{Debug, Formatter};
use std::path::PathBuf;

/// AssumeRoleWithWebIdentityCredentialProvider will load credential via assume role with web identity.
#[derive(Debug)]
pub struct AssumeRoleWithWebIdentityCredentialProvider {
    // Web Identity configuration
    role_arn: String,
    role_session_name: String,
    web_identity_token_file: PathBuf,

    // STS configuration
    region: Option<String>,
    use_regional_sts_endpoint: bool,
}

impl AssumeRoleWithWebIdentityCredentialProvider {
    /// Create a new `AssumeRoleWithWebIdentityCredentialProvider` instance.
    pub fn new(role_arn: String, token_file: PathBuf) -> Self {
        Self {
            role_arn,
            role_session_name: "reqsign".to_string(),
            web_identity_token_file: token_file,
            region: None,
            use_regional_sts_endpoint: false,
        }
    }

    /// Set the role session name.
    pub fn with_role_session_name(mut self, name: String) -> Self {
        self.role_session_name = name;
        self
    }

    /// Set the region.
    pub fn with_region(mut self, region: String) -> Self {
        self.region = Some(region);
        self
    }

    /// Use regional STS endpoint.
    pub fn with_regional_sts_endpoint(mut self) -> Self {
        self.use_regional_sts_endpoint = true;
        self
    }

    /// Create from environment variables.
    pub fn from_env(ctx: &Context) -> Option<Self> {
        let role_arn = ctx.env_var("AWS_ROLE_ARN")?;
        let token_file = ctx.env_var("AWS_WEB_IDENTITY_TOKEN_FILE")?;

        let mut provider = Self::new(role_arn, PathBuf::from(token_file));

        if let Some(name) = ctx.env_var("AWS_ROLE_SESSION_NAME") {
            provider = provider.with_role_session_name(name);
        }

        if let Some(region) = ctx.env_var("AWS_REGION") {
            provider = provider.with_region(region);
        }

        if ctx.env_var("AWS_STS_REGIONAL_ENDPOINTS") == Some("regional".to_string()) {
            provider = provider.with_regional_sts_endpoint();
        }

        Some(provider)
    }
}

#[async_trait]
impl ProvideCredential for AssumeRoleWithWebIdentityCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let token = ctx
            .file_read_as_string(&self.web_identity_token_file.to_string_lossy())
            .await
            .map_err(|e| {
                Error::unexpected("failed to read web identity token file").with_source(e)
            })?;

        let endpoint = sts_endpoint(self.region.as_deref(), self.use_regional_sts_endpoint)
            .map_err(|e| {
                Error::config_invalid("failed to determine STS endpoint").with_source(e)
            })?;

        // Construct request to AWS STS Service.
        let url = format!("https://{endpoint}/?Action=AssumeRoleWithWebIdentity&RoleArn={}&WebIdentityToken={token}&Version=2011-06-15&RoleSessionName={}", self.role_arn, self.role_session_name);
        let req = http::request::Request::builder()
            .method("GET")
            .uri(url)
            .header(
                http::header::CONTENT_TYPE.as_str(),
                "application/x-www-form-urlencoded",
            )
            .body(Bytes::new())
            .map_err(|e| Error::unexpected("failed to build HTTP request").with_source(e))?;

        let resp = ctx
            .http_send_as_string(req)
            .await
            .map_err(|e| Error::unexpected("failed to send HTTP request to STS").with_source(e))?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.into_body();
            return Err(Error::credential_denied(format!(
                "request to AWS STS Services failed: {content}"
            )));
        }

        let resp: AssumeRoleWithWebIdentityResponse = de::from_str(&resp.into_body())
            .map_err(|e| Error::unexpected("failed to parse STS response").with_source(e))?;
        let resp_cred = resp.result.credentials;

        let cred = Credential {
            access_key_id: resp_cred.access_key_id,
            secret_access_key: resp_cred.secret_access_key,
            session_token: Some(resp_cred.session_token),
            expires_in: Some(parse_rfc3339(&resp_cred.expiration).map_err(|e| {
                Error::unexpected("failed to parse credential expiration time").with_source(e)
            })?),
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
