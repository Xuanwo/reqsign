use anyhow::Result;
use reqsign_core::{Context, ProvideCredential};

use crate::config::Config;
use crate::key::Credential;

/// ConfigLoader will load credential from config.
#[derive(Debug, Clone)]
pub struct ConfigLoader {
    config: Config,
}

impl ConfigLoader {
    /// Create a new loader via config.
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl ProvideCredential for ConfigLoader {
    type Credential = Credential;

    async fn provide_credential(&self, _: &Context) -> Result<Option<Self::Credential>> {
        if let (Some(ak), Some(sk)) = (&self.config.access_key_id, &self.config.secret_access_key) {
            let cred = Credential::new(ak.clone(), sk.clone(), self.config.security_token.clone());
            return Ok(Some(cred));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;

    #[test]
    fn test_credential_env_loader_with_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (HUAWEI_CLOUD_ACCESS_KEY_ID, Some("access_key_id")),
                (HUAWEI_CLOUD_SECRET_ACCESS_KEY, Some("secret_access_key")),
            ],
            || {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
                    let config = Config::default().from_env(&ctx);
                    let loader = ConfigLoader::new(config);

                    let x = loader
                        .provide_credential(&ctx)
                        .await
                        .expect("load must succeed");
                    let x = x.expect("must load succeed");
                    assert_eq!("access_key_id", x.access_key_id);
                    assert_eq!("secret_access_key", x.secret_access_key);
                })
            },
        );
    }
}
