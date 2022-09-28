use std::env;

use anyhow::Result;

use crate::credential::{Credential, CredentialLoad};

/// Load credential from env values
///
/// - `AZURE_STORAGE_ACCOUNT_NAME`
/// - `AZURE_STORAGE_ACCOUNT_KEY`
#[derive(Default, Clone, Debug)]
pub struct EnvLoader {}

impl CredentialLoad for EnvLoader {
    fn load_credential(&self) -> Result<Option<Credential>> {
        if let (Ok(sa), Ok(sk)) = (
            env::var(super::constants::AZURE_STORAGE_ACCOUNT_NAME),
            env::var(super::constants::AZURE_STORAGE_ACCOUNT_KEY),
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
                (AZURE_STORAGE_ACCOUNT_NAME, Some("account_name")),
                (AZURE_STORAGE_ACCOUNT_KEY, Some("account_key")),
            ],
            || {
                TOKIO.block_on(async {
                    let l = EnvLoader {};
                    let x = l
                        .load_credential()
                        .expect("load_credential must success")
                        .expect("credential must be valid");
                    assert_eq!("account_name", x.access_key());
                    assert_eq!("account_key", x.secret_key());
                });
            },
        );
    }
}
