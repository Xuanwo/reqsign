use super::credential::Credential;
use anyhow::Result;
use async_trait::async_trait;

use std::str::FromStr;
use std::{env, fs};
/// Loader trait will try to load credential and region from different sources.
#[async_trait]
pub trait CredentialLoad: Send + Sync {
    async fn load_credential(&self) -> Result<Option<Credential>>;
}

#[derive(Default)]
pub struct CredentialLoadChain {
    loaders: Vec<Box<dyn CredentialLoad>>,
}

impl CredentialLoadChain {
    pub fn push(&mut self, l: impl CredentialLoad + 'static) -> &mut Self {
        self.loaders.push(Box::new(l));

        self
    }
    pub fn is_empty(&self) -> bool {
        self.loaders.is_empty()
    }
}
#[async_trait]
impl CredentialLoad for CredentialLoadChain {
    async fn load_credential(&self) -> Result<Option<Credential>> {
        for l in self.loaders.iter() {
            if let Some(c) = l.load_credential().await? {
                return Ok(Some(c));
            }
        }

        Ok(None)
    }
}

/// Load credential from env values
///
/// - `AWS_ACCESS_KEY_ID`
/// - `AWS_SECRET_ACCESS_KEY`
/// - `AWS_REGION`
#[derive(Default, Clone, Debug)]
pub struct EnvLoader {}

#[async_trait]
impl CredentialLoad for EnvLoader {
    async fn load_credential(&self) -> Result<Option<Credential>> {
        if let (Ok(sa), Ok(sk)) = (
            env::var(super::constants::AZURE_STORAGE_ACCOUNT),
            env::var(super::constants::AZURE_STORAGE_KEY),
        ) {
            Ok(Some(Credential::new(&sa, &sk)))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::services::azure::constants::*;

    static TOKIO: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("runtime must be valid"));

    #[test]
    fn test_credential_env_loader_with_env() {
        temp_env::with_vars(
            vec![
                (AZURE_STORAGE_ACCOUNT, Some("access_acount")),
                (AZURE_STORAGE_KEY, Some("access_key")),
            ],
            || {
                TOKIO.block_on(async {
                    let l = EnvLoader {};
                    let x = l
                        .load_credential()
                        .await
                        .expect("load_credential must success")
                        .expect("credential must be valid");
                    assert_eq!("access_acount", x.access_acount());
                    assert_eq!("access_key", x.access_key());
                });
            },
        );
    }
}
