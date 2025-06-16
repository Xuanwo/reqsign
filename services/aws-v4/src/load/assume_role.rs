use crate::constants::X_AMZ_CONTENT_SHA_256;
use crate::key::Credential;
use crate::load::utils::sts_endpoint;
use crate::{Config, EMPTY_STRING_SHA256};
use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;
use quick_xml::de;
use reqsign_core::time::parse_rfc3339;
use reqsign_core::{Context, ProvideCredential, Signer};
use serde::Deserialize;
use std::fmt::Write;
use std::sync::Arc;

/// AssumeRoleLoader will load credential via assume role.
#[derive(Debug)]
pub struct AssumeRoleLoader {
    config: Arc<Config>,

    sts_signer: Signer<Credential>,
}

impl AssumeRoleLoader {
    /// Create a new assume role loader.
    pub fn new(config: Arc<Config>, sts_signer: Signer<Credential>) -> anyhow::Result<Self> {
        Ok(Self { config, sts_signer })
    }
}

#[async_trait]
impl ProvideCredential for AssumeRoleLoader {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> anyhow::Result<Option<Self::Credential>> {
        let role_arn =self.config.role_arn.clone().ok_or_else(|| {
            anyhow!("assume role loader requires role_arn, but not found, please check your configuration")
        })?;

        let role_session_name = &self.config.role_session_name;

        let endpoint = sts_endpoint(&self.config)?;

        // Construct request to AWS STS Service.
        let mut url = format!("https://{endpoint}/?Action=AssumeRole&RoleArn={role_arn}&Version=2011-06-15&RoleSessionName={role_session_name}");
        if let Some(external_id) = &self.config.external_id {
            write!(url, "&ExternalId={external_id}")?;
        }
        if let Some(duration_seconds) = &self.config.duration_seconds {
            write!(url, "&DurationSeconds={duration_seconds}")?;
        }
        if let Some(tags) = &self.config.tags {
            for (idx, (key, value)) in tags.iter().enumerate() {
                let tag_index = idx + 1;
                write!(
                    url,
                    "&Tags.member.{tag_index}.Key={key}&Tags.member.{tag_index}.Value={value}"
                )?;
            }
        }

        let req = http::request::Request::builder()
            .method("GET")
            .uri(url)
            .header(
                http::header::CONTENT_TYPE.as_str(),
                "application/x-www-form-urlencoded",
            )
            // Set content sha to empty string.
            .header(X_AMZ_CONTENT_SHA_256, EMPTY_STRING_SHA256)
            .body(Bytes::new())?;

        let (mut parts, body) = req.into_parts();
        self.sts_signer.sign(&mut parts, None).await?;
        let req = http::Request::from_parts(parts, body);

        let resp = ctx.http_send_as_string(req).await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.into_body();
            return Err(anyhow!("request to AWS STS Services failed: {content}"));
        }

        let resp: AssumeRoleResponse = de::from_str(&resp.into_body())?;
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
struct AssumeRoleResponse {
    #[serde(rename = "AssumeRoleResult")]
    result: AssumeRoleResult,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleResult {
    credentials: AssumeRoleCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::de;

    #[test]
    fn test_parse_assume_role_response() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let content = r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
  <SourceIdentity>Alice</SourceIdentity>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/demo/TestAR</Arn>
      <AssumedRoleId>ARO123EXAMPLE123:TestAR</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <SessionToken>
       AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW
       LWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGd
       QrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU
       9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz
       +scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==
      </SessionToken>
      <Expiration>2019-11-09T13:34:41Z</Expiration>
    </Credentials>
    <PackedPolicySize>6</PackedPolicySize>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>"#;

        let resp: AssumeRoleResponse = de::from_str(content).expect("xml deserialize must success");

        assert_eq!(
            &resp.result.credentials.access_key_id,
            "ASIAIOSFODNN7EXAMPLE"
        );
        assert_eq!(
            &resp.result.credentials.secret_access_key,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
        );
        assert_eq!(
            &resp.result.credentials.session_token,
            "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW
       LWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGd
       QrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU
       9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz
       +scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA=="
        );
        assert_eq!(&resp.result.credentials.expiration, "2019-11-09T13:34:41Z");

        Ok(())
    }
}
