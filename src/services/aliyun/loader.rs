//! Loader is used to load credential or region from env.
//!
//! - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION
//! - Web Identity Token credentials from the environment
//! - ECS Container Credentials (IAM roles for tasks)
//! - EC2 Instance Metadata Service (IAM Roles attached to instance)

use std::thread::sleep;

use anyhow::{anyhow, Result};
use backon::ExponentialBackoff;
use log::warn;
use serde::Deserialize;

use super::credential::Credential;
use crate::time::parse_rfc3339;

/// Loader trait will try to load credential from different sources.
pub trait CredentialLoad: Send + Sync {
    /// Load credential from sources.
    ///
    /// - If succeed, return `Ok(Some(cred))`
    /// - If not found, return `Ok(None)`
    /// - If unexpected errors happened, return `Err(err)`
    fn load_credential(&self) -> Result<Option<Credential>>;
}

/// CredentialLoadChain will try to load credential via the insert order.
///
/// - If found, return directly.
/// - If not found, keep going and try next one.
/// - If meeting error, return directly.
#[derive(Default)]
pub struct CredentialLoadChain {
    loaders: Vec<Box<dyn CredentialLoad>>,
}

impl CredentialLoadChain {
    /// Check if this chain is empty.
    pub fn is_empty(&self) -> bool {
        self.loaders.is_empty()
    }

    /// Insert new loaders into chain.
    pub fn push(&mut self, l: impl CredentialLoad + 'static) -> &mut Self {
        self.loaders.push(Box::new(l));

        self
    }
}

impl CredentialLoad for CredentialLoadChain {
    fn load_credential(&self) -> Result<Option<Credential>> {
        for l in self.loaders.iter() {
            if let Some(c) = l.load_credential()? {
                return Ok(Some(c));
            }
        }

        Ok(None)
    }
}

/// DummyLoader always returns `Ok(None)`.
///
/// It's useful when users don't want to load credential/region from env.
pub struct DummyLoader {}

impl CredentialLoad for DummyLoader {
    fn load_credential(&self) -> Result<Option<Credential>> {
        Ok(None)
    }
}

/// Load credential via OIDC token
#[derive(Clone, Debug)]
pub struct OidcTokenLoader {
    client: ureq::Agent,
    provider_arn: String,
    role_arn: String,
    token: String,
}

impl OidcTokenLoader {
    /// Create a new oidc token loader
    pub fn new(client: ureq::Agent, provider_arn: &str, role_arn: &str, token: &str) -> Self {
        Self {
            client,
            provider_arn: provider_arn.to_string(),
            role_arn: role_arn.to_string(),
            token: token.to_string(),
        }
    }
}

impl CredentialLoad for OidcTokenLoader {
    fn load_credential(&self) -> Result<Option<Credential>> {
        // Based on our user reports, Aliyun STS may need 10s to reach consistency
        // Let's retry 4 times: 1s -> 2s -> 4s -> 8s.
        //
        // Reference: <https://github.com/datafuselabs/opendal/issues/288>
        let mut retry = ExponentialBackoff::default()
            .with_max_times(4)
            .with_jitter();

        loop {
            match self.load_credential_inner() {
                Ok(v) => return Ok(v),
                Err(e) => {
                    warn!("load credential from Aliyun STS Services failed: {e}");

                    match retry.next() {
                        Some(dur) => sleep(dur),
                        None => {
                            return Err(anyhow!(
                            "load credential from Aliyun STS Services still failed after retry: {e}",
                        ))
                        }
                    }
                }
            }
        }
    }
}

impl OidcTokenLoader {
    fn load_credential_inner(&self) -> Result<Option<Credential>> {
        // TODO: use `reqsign` as default session name for now.
        let role_session_name = "reqsign";

        // Construct request to Aliyun STS Service.
        let url = format!("https://sts.aliyuncs.com/?Action=AssumeRoleWithOIDC&OIDCProviderArn={}&RoleArn={}&OIDCToken={}&RoleSessionName={}&Format=JSON", self.provider_arn, self.role_arn, self.token, role_session_name);

        let req = self.client.get(&url).set(
            http::header::CONTENT_TYPE.as_str(),
            "application/x-www-form-urlencoded",
        );

        let resp = req.call()?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.into_string()?;
            return Err(anyhow!("request to Aliyun STS Services failed: {content}"));
        }

        let resp: AssumeRoleWithOidcResponse = serde_json::from_str(&resp.into_string()?)?;
        let cred = resp.credentials;

        let mut builder = Credential::builder();
        builder.access_key(&cred.access_key_id);
        builder.secret_key(&cred.access_key_secret);
        builder.security_token(&cred.security_token);
        builder.expires_in(parse_rfc3339(&cred.expiration)?);

        Ok(Some(builder.build()?))
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
}
