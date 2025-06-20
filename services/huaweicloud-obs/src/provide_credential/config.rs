use reqsign_core::Result;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential};
use std::sync::Arc;

use crate::config::Config;
use crate::credential::Credential;

/// ConfigCredentialProvider will load credential from config.
#[derive(Debug)]
pub struct ConfigCredentialProvider {
    config: Arc<Config>,
}

impl ConfigCredentialProvider {
    /// Create a new loader via config.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ProvideCredential for ConfigCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // Load config from environment
        let config = self.config.as_ref().clone().from_env(ctx);

        if let (Some(ak), Some(sk)) = (&config.access_key_id, &config.secret_access_key) {
            let cred = Credential::new(ak.clone(), sk.clone(), config.security_token.clone());
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
                    let config = Arc::new(Config::default());
                    let loader = ConfigCredentialProvider::new(config);

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
