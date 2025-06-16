use crate::{Config, Credential};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use reqsign_core::time::{format_rfc3339, now, parse_rfc3339};
use reqsign_core::{Context, Load};
use serde::Deserialize;
use std::sync::Arc;

/// AssumeRoleWithOidcLoader loads credential via assume role with OIDC.
#[derive(Debug)]
pub struct AssumeRoleWithOidcLoader {
    config: Arc<Config>,
}

impl AssumeRoleWithOidcLoader {
    /// Create a new `AssumeRoleWithOidcLoader` instance.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    fn get_sts_endpoint(&self) -> String {
        match &self.config.sts_endpoint {
            Some(defined_sts_endpoint) => format!("https://{}", defined_sts_endpoint),
            None => "https://sts.aliyuncs.com".to_string(),
        }
    }
}

#[async_trait]
impl Load for AssumeRoleWithOidcLoader {
    type Key = Credential;

    async fn load(&self, ctx: &Context) -> Result<Option<Self::Key>> {
        let (token_file, role_arn, provider_arn) = match (
            &self.config.oidc_token_file,
            &self.config.role_arn,
            &self.config.oidc_provider_arn,
        ) {
            (Some(token_file), Some(role_arn), Some(provider_arn)) => {
                (token_file, role_arn, provider_arn)
            }
            _ => return Ok(None),
        };

        let token = ctx.file_read(token_file).await?;
        let token = String::from_utf8(token)?;
        let role_session_name = &self.config.role_session_name;

        // Construct request to Aliyun STS Service.
        let url = format!(
            "{}/?Action=AssumeRoleWithOIDC&OIDCProviderArn={}&RoleArn={}&RoleSessionName={}&Format=JSON&Version=2015-04-01&Timestamp={}&OIDCToken={}",
            self.get_sts_endpoint(),
            provider_arn,
            role_arn,
            role_session_name,
            format_rfc3339(now()),
            token
        );

        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(&url)
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Vec::new())?;

        let resp = ctx.http_send(req.map(|body| body.into())).await?;

        if resp.status() != http::StatusCode::OK {
            let content = String::from_utf8_lossy(resp.body());
            return Err(anyhow!("request to Aliyun STS Services failed: {content}"));
        }

        let resp: AssumeRoleWithOidcResponse = serde_json::from_slice(resp.body())?;
        let resp_cred = resp.credentials;

        let cred = Credential {
            access_key_id: resp_cred.access_key_id,
            access_key_secret: resp_cred.access_key_secret,
            security_token: Some(resp_cred.security_token),
            expires_in: Some(parse_rfc3339(&resp_cred.expiration)?),
        };

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default)]
struct AssumeRoleWithOidcResponse {
    #[serde(rename = "Credentials")]
    credentials: AssumeRoleWithOidcCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithOidcCredentials {
    access_key_id: String,
    access_key_secret: String,
    security_token: String,
    expiration: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::StaticEnv;
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;

    #[test]
    fn test_parse_assume_role_with_oidc_response() -> Result<()> {
        let content = r#"{
    "RequestId": "3D57EAD2-8723-1F26-B69C-F8707D8B565D",
    "OIDCTokenInfo": {
        "Subject": "KryrkIdjylZb7agUgCEf****",
        "Issuer": "https://dev-xxxxxx.okta.com",
        "ClientIds": "496271242565057****"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "33157794895460****",
        "Arn": "acs:ram::113511544585****:role/testoidc/TestOidcAssumedRoleSession"
    },
    "Credentials": {
        "SecurityToken": "CAIShwJ1q6Ft5B2yfSjIr5bSEsj4g7BihPWGWHz****",
        "Expiration": "2021-10-20T04:27:09Z",
        "AccessKeySecret": "CVwjCkNzTMupZ8NbTCxCBRq3K16jtcWFTJAyBEv2****",
        "AccessKeyId": "STS.NUgYrLnoC37mZZCNnAbez****"
    }
}"#;

        let resp: AssumeRoleWithOidcResponse =
            serde_json::from_str(content).expect("json deserialize must success");

        assert_eq!(
            &resp.credentials.access_key_id,
            "STS.NUgYrLnoC37mZZCNnAbez****"
        );
        assert_eq!(
            &resp.credentials.access_key_secret,
            "CVwjCkNzTMupZ8NbTCxCBRq3K16jtcWFTJAyBEv2****"
        );
        assert_eq!(
            &resp.credentials.security_token,
            "CAIShwJ1q6Ft5B2yfSjIr5bSEsj4g7BihPWGWHz****"
        );
        assert_eq!(&resp.credentials.expiration, "2021-10-20T04:27:09Z");

        Ok(())
    }

    #[tokio::test]
    async fn test_assume_role_with_oidc_loader_without_config() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let config = Config::default();
        let loader = AssumeRoleWithOidcLoader::new(Arc::new(config));
        let credential = loader.load(&ctx).await.unwrap();

        assert!(credential.is_none());
    }
}
