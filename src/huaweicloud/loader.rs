use std::env;

use anyhow::Result;

use crate::credential::Credential;
use crate::credential::CredentialLoad;

/// Load credential from env values
///
/// - `HUAWEICLOUD_OBS_ACCESS_KEY`
/// - `HUAWEICLOUD_OBS_SECRET_KEY`
#[derive(Default, Clone, Debug)]
pub struct EnvLoader {}

impl CredentialLoad for EnvLoader {
    fn load_credential(&self) -> Result<Option<Credential>> {
        if let (Ok(ak), Ok(sk)) = (
            env::var(super::constants::HUAWEICLOUD_OBS_ACCESS_KEY),
            env::var(super::constants::HUAWEICLOUD_OBS_SECRET_KEY),
        ) {
            Ok(Some(Credential::new(&ak, &sk)))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;
    use tokio::runtime::Runtime;

    use super::super::constants::*;
    use super::*;

    static TOKIO: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("runtime must be valid"));

    #[test]
    fn test_credential_env_loader_with_env() {
        temp_env::with_vars(
            vec![
                (HUAWEICLOUD_OBS_ACCESS_KEY, Some("access_key")),
                (HUAWEICLOUD_OBS_SECRET_KEY, Some("secret_key")),
            ],
            || {
                TOKIO.block_on(async {
                    let l = EnvLoader {};
                    let x = l
                        .load_credential()
                        .expect("load_credential must success")
                        .expect("credential must be valid");
                    assert_eq!("access_key", x.access_key());
                    assert_eq!("secret_key", x.secret_key());
                });
            },
        );
    }
}
