use std::sync::Arc;
use std::sync::Mutex;

use anyhow::Result;

use super::config::Config;

/// Credential for obs.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Credential {
    /// Access key id for obs
    pub access_key_id: String,
    /// Secret access key for obs
    pub secret_access_key: String,
    /// security_token for obs.
    pub security_token: Option<String>,
}

/// CredentialLoader will load credential from different methods.
#[derive(Default)]
#[cfg_attr(test, derive(Debug))]
pub struct CredentialLoader {
    config: Config,

    credential: Arc<Mutex<Option<Credential>>>,
}

impl CredentialLoader {
    /// Create a new loader via config.
    pub fn new(config: Config) -> Self {
        Self {
            config,

            credential: Arc::default(),
        }
    }

    /// Load credential
    pub async fn load(&self) -> Result<Option<Credential>> {
        // Return cached credential if it's valid.
        if let Some(cred) = self.credential.lock().expect("lock poisoned").clone() {
            return Ok(Some(cred));
        }

        let cred = self.load_inner().await?;

        let mut lock = self.credential.lock().expect("lock poisoned");
        *lock = cred.clone();

        Ok(cred)
    }

    async fn load_inner(&self) -> Result<Option<Credential>> {
        if let Some(cred) = self.load_via_config()? {
            return Ok(Some(cred));
        }

        Ok(None)
    }

    fn load_via_config(&self) -> Result<Option<Credential>> {
        if let (Some(ak), Some(sk)) = (&self.config.access_key_id, &self.config.secret_access_key) {
            let cred = Credential {
                access_key_id: ak.clone(),
                secret_access_key: sk.clone(),
                security_token: self.config.security_token.clone(),
            };
            return Ok(Some(cred));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;
    use tokio::runtime::Runtime;

    use super::super::super::constants::*;
    use super::*;

    static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Should create a tokio runtime")
    });

    #[test]
    fn test_credential_env_loader_with_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (HUAWEI_CLOUD_ACCESS_KEY_ID, Some("access_key_id")),
                (HUAWEI_CLOUD_SECRET_ACCESS_KEY, Some("secret_access_key")),
            ],
            || {
                RUNTIME.block_on(async {
                    let l = CredentialLoader::new(Config::default().from_env());
                    let x = l.load().await.expect("load must succeed");

                    let x = x.expect("must load succeed");
                    assert_eq!("access_key_id", x.access_key_id);
                    assert_eq!("secret_access_key", x.secret_access_key);
                })
            },
        );
    }
}
