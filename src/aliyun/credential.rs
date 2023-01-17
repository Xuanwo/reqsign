use std::fs;
use std::sync::Arc;
use std::sync::RwLock;
use std::thread::sleep;

use anyhow::anyhow;
use anyhow::Result;
use backon::ExponentialBackoff;
use log::warn;
use serde::Deserialize;

use super::config::ConfigLoader;
use crate::credential::Credential;
use crate::time::format_rfc3339;
use crate::time::now;
use crate::time::parse_rfc3339;

/// CredentialLoader will load credential from different methods.
#[cfg_attr(test, derive(Debug))]
pub struct CredentialLoader {
    credential: Arc<RwLock<Option<Credential>>>,

    disable_env: bool,
    disable_assume_role_with_oidc: bool,

    client: ureq::Agent,
    config_loader: ConfigLoader,
}

impl Default for CredentialLoader {
    fn default() -> Self {
        Self {
            credential: Arc::new(Default::default()),
            disable_env: false,
            disable_assume_role_with_oidc: false,
            client: ureq::Agent::new(),
            config_loader: Default::default(),
        }
    }
}

impl CredentialLoader {
    /// Disable load from env.
    pub fn with_disable_env(mut self) -> Self {
        self.disable_env = true;
        self
    }

    /// Disable load from assume role with oidc.
    pub fn with_disable_assume_role_with_oidc(mut self) -> Self {
        self.disable_assume_role_with_oidc = true;
        self
    }

    /// Set Credential.
    pub fn with_credential(self, cred: Credential) -> Self {
        *self.credential.write().expect("lock poisoned") = Some(cred);
        self
    }

    /// Load credential.
    pub fn load(&self) -> Option<Credential> {
        // Return cached credential if it's valid.
        match self.credential.read().expect("lock poisoned").clone() {
            Some(cred) if cred.is_valid() => return Some(cred),
            _ => (),
        }

        // Let's retry 4 times: 1s -> 2s -> 4s -> 8s.
        let mut retry = ExponentialBackoff::default()
            .with_max_times(4)
            .with_jitter();

        let cred = loop {
            let cred = self.load_via_env().or_else(|| {
                self.load_via_assume_role_with_oidc()
                    .map_err(|err| {
                        warn!("load credential via assume role with oidc failed: {err:?}");
                        err
                    })
                    .unwrap_or_default()
            });

            match cred {
                Some(cred) => break cred,
                None => match retry.next() {
                    Some(dur) => {
                        sleep(dur);
                        continue;
                    }
                    None => {
                        warn!("load credential still failed after retry");
                        return None;
                    }
                },
            }
        };

        let mut lock = self.credential.write().expect("lock poisoned");
        *lock = Some(cred.clone());

        Some(cred)
    }

    fn load_via_env(&self) -> Option<Credential> {
        if self.disable_env {
            return None;
        }

        self.config_loader.load_via_env();

        if let (Some(ak), Some(sk)) = (
            self.config_loader.access_key_id(),
            self.config_loader.access_key_secret(),
        ) {
            let mut cred = Credential::new(&ak, &sk);
            if let Some(tk) = self.config_loader.security_token() {
                cred.set_security_token(&tk);
            }
            Some(cred)
        } else {
            None
        }
    }

    fn load_via_assume_role_with_oidc(&self) -> Result<Option<Credential>> {
        if self.disable_assume_role_with_oidc {
            return Ok(None);
        }

        let (token_file, role_arn, provider_arn) = match (
            self.config_loader.oidc_token_file(),
            self.config_loader.role_arn(),
            self.config_loader.oidc_provider_arn(),
        ) {
            (Some(token_file), Some(role_arn), Some(provider_arn)) => {
                (token_file, role_arn, provider_arn)
            }
            _ => return Ok(None),
        };

        let token = fs::read_to_string(token_file)?;
        let role_session_name = self.config_loader.role_session_name();

        // Construct request to Aliyun STS Service.
        let url = format!("https://sts.aliyuncs.com/?Action=AssumeRoleWithOIDC&OIDCProviderArn={}&RoleArn={}&RoleSessionName={}&Format=JSON&Version=2015-04-01&Timestamp={}&OIDCToken={}", provider_arn, role_arn,  role_session_name, format_rfc3339(now()), token);

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
        let resp_cred = resp.credentials;

        let cred = Credential::new(&resp_cred.access_key_id, &resp_cred.access_key_secret)
            .with_security_token(&resp_cred.security_token)
            .with_expires_in(parse_rfc3339(&resp_cred.expiration)?);

        cred.check()?;

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
    use std::env;
    use std::str::FromStr;

    use http::Request;
    use reqwest::blocking::Client;
    use time::Duration;

    use super::super::constants::*;
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

    #[test]
    fn test_signer_with_oidc() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        dotenv::from_filename(".env").ok();

        if env::var("REQSIGN_ALIYUN_OSS_TEST").is_err()
            || env::var("REQSIGN_ALIYUN_OSS_TEST").unwrap() != "on"
        {
            return Ok(());
        }

        let provider_arn =
            env::var("REQSIGN_ALIYUN_PROVIDER_ARN").expect("REQSIGN_ALIYUN_PROVIDER_ARN not exist");
        let role_arn =
            env::var("REQSIGN_ALIYUN_ROLE_ARN").expect("REQSIGN_ALIYUN_ROLE_ARN not exist");
        let idp_url = env::var("REQSIGN_ALIYUN_IDP_URL").expect("REQSIGN_ALIYUN_IDP_URL not exist");
        let idp_content =
            env::var("REQSIGN_ALIYUN_IDP_BODY").expect("REQSIGN_ALIYUN_IDP_BODY not exist");

        let mut req = Request::new(idp_content);
        *req.method_mut() = http::Method::POST;
        *req.uri_mut() = http::Uri::from_str(&idp_url)?;
        req.headers_mut().insert(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse()?,
        );

        #[derive(Deserialize)]
        struct Token {
            id_token: String,
        }
        let token = Client::new()
            .execute(req.try_into()?)?
            .json::<Token>()?
            .id_token;

        let file_path = format!(
            "{}/testdata/services/aliyun/oidc_token_file",
            env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );
        fs::write(&file_path, token)?;

        temp_env::with_vars(
            vec![
                (ALIBABA_CLOUD_ROLE_ARN, Some(&role_arn)),
                (ALIBABA_CLOUD_OIDC_PROVIDER_ARN, Some(&provider_arn)),
                (ALIBABA_CLOUD_OIDC_TOKEN_FILE, Some(&file_path)),
            ],
            || {
                let l = CredentialLoader::default();
                let x = l.load().expect("credential must be valid");

                assert!(x.is_valid());
            },
        );

        Ok(())
    }

    #[test]
    fn test_signer_with_oidc_query() -> Result<()> {
        let _ = env_logger::builder().try_init();

        use log::debug;

        dotenv::from_filename(".env").ok();

        if env::var("REQSIGN_ALIYUN_OSS_TEST").is_err()
            || env::var("REQSIGN_ALIYUN_OSS_TEST").unwrap() != "on"
        {
            panic!("test not enabled");
        }

        let provider_arn =
            env::var("REQSIGN_ALIYUN_PROVIDER_ARN").expect("REQSIGN_ALIYUN_PROVIDER_ARN not exist");
        let role_arn =
            env::var("REQSIGN_ALIYUN_ROLE_ARN").expect("REQSIGN_ALIYUN_ROLE_ARN not exist");
        let idp_url = env::var("REQSIGN_ALIYUN_IDP_URL").expect("REQSIGN_ALIYUN_IDP_URL not exist");
        let idp_content =
            env::var("REQSIGN_ALIYUN_IDP_BODY").expect("REQSIGN_ALIYUN_IDP_BODY not exist");

        let mut req = Request::new(idp_content);
        *req.method_mut() = http::Method::POST;
        *req.uri_mut() = http::Uri::from_str(&idp_url)?;
        req.headers_mut().insert(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse()?,
        );

        #[derive(Deserialize)]
        struct Token {
            id_token: String,
        }
        let token = Client::new()
            .execute(req.try_into()?)?
            .json::<Token>()?
            .id_token;

        let file_path = format!(
            "{}/testdata/services/aliyun/oidc_token_file",
            env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );
        fs::write(&file_path, token)?;

        temp_env::with_vars(
            vec![
                (ALIBABA_CLOUD_ROLE_ARN, Some(&role_arn)),
                (ALIBABA_CLOUD_OIDC_PROVIDER_ARN, Some(&provider_arn)),
                (ALIBABA_CLOUD_OIDC_TOKEN_FILE, Some(&file_path)),
            ],
            || {
                let mut builder = super::super::oss::Builder::default();
                builder.bucket(
                    &env::var("REQSIGN_ALIYUN_OSS_BUCKET")
                        .expect("env REQSIGN_ALIYUN_OSS_BUCKET must set"),
                );
                let signer = builder.build().expect("must succeed");

                let url = &env::var("REQSIGN_ALIYUN_OSS_URL")
                    .expect("env REQSIGN_ALIYUN_OSS_URL must set");

                let mut req = Request::new("");
                *req.method_mut() = http::Method::GET;
                *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))
                    .expect("must valid");

                signer
                    .sign_query(&mut req, Duration::seconds(3600))
                    .expect("sign request must success");

                debug!("signed request url: {:?}", req.uri().to_string());
                debug!("signed request: {:?}", req);
            },
        );
        Ok(())
    }
}
