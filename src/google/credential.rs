pub mod external_account;
pub mod service_account;

use std::env;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::bail;
use anyhow::Result;
use log::debug;

pub use self::external_account::ExternalAccount;
pub use self::service_account::ServiceAccount;

use super::constants::GOOGLE_APPLICATION_CREDENTIALS;
use crate::hash::base64_decode;

/// A Google credential account, either a service or an external account.
#[derive(Clone, serde::Deserialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum CredentialAccount {
    /// An external account, used by a Workload Identity User.
    ExternalAccount(ExternalAccount),
    /// A service account.
    ServiceAccount(ServiceAccount),
}

/// CredentialLoader will load credential from different methods.
#[derive(Default)]
#[cfg_attr(test, derive(Debug))]
pub struct CredentialLoader {
    path: Option<String>,
    content: Option<String>,
    disable_env: bool,
    disable_well_known_location: bool,

    credential: Arc<Mutex<Option<CredentialAccount>>>,
}

impl CredentialLoader {
    /// Disable load from env.
    pub fn with_disable_env(mut self) -> Self {
        self.disable_env = true;
        self
    }

    /// Disable load from well known location.
    pub fn with_disable_well_known_location(mut self) -> Self {
        self.disable_well_known_location = true;
        self
    }

    /// Set credential path.
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = Some(path.to_string());
        self
    }

    /// Set credential content.
    pub fn with_content(mut self, content: &str) -> Self {
        self.content = Some(content.to_string());
        self
    }

    /// Load credential from pre-configured methods.
    pub fn load(&self) -> Result<Option<ServiceAccount>> {
        match self.load_account()? {
            Some(CredentialAccount::ServiceAccount(credential)) => Ok(Some(credential)),
            Some(CredentialAccount::ExternalAccount(_)) => {
                bail!("expected service account, got external account")
            }
            None => Ok(None),
        }
    }

    /// Load account from pre-configured methods.
    pub fn load_account(&self) -> Result<Option<CredentialAccount>> {
        // Return cached credential if it has been loaded at least once.
        if let Some(cred) = self.credential.lock().expect("lock poisoned").clone() {
            return Ok(Some(cred));
        }

        let cred = if let Some(cred) = self.load_inner()? {
            cred
        } else {
            return Ok(None);
        };

        let mut lock = self.credential.lock().expect("lock poisoned");
        *lock = Some(cred.clone());

        Ok(Some(cred))
    }

    fn load_inner(&self) -> Result<Option<CredentialAccount>> {
        if let Ok(Some(cred)) = self.load_via_content() {
            return Ok(Some(cred));
        }

        if let Ok(Some(cred)) = self.load_via_path() {
            return Ok(Some(cred));
        }

        if let Ok(Some(cred)) = self.load_via_env() {
            return Ok(Some(cred));
        }

        if let Ok(Some(cred)) = self.load_via_well_known_location() {
            return Ok(Some(cred));
        }

        Ok(None)
    }

    fn load_via_path(&self) -> Result<Option<CredentialAccount>> {
        let path = if let Some(path) = &self.path {
            path
        } else {
            return Ok(None);
        };

        Ok(Some(Self::load_file(path)?))
    }

    /// Build credential loader from given base64 content.
    fn load_via_content(&self) -> Result<Option<CredentialAccount>> {
        let content = if let Some(content) = &self.content {
            content
        } else {
            return Ok(None);
        };

        let cred = serde_json::from_slice(&base64_decode(content)).map_err(|err| {
            debug!("load credential from content failed: {err:?}");
            err
        })?;
        Ok(Some(cred))
    }

    /// Load from env GOOGLE_APPLICATION_CREDENTIALS.
    fn load_via_env(&self) -> Result<Option<CredentialAccount>> {
        if self.disable_env {
            return Ok(None);
        }

        if let Ok(cred_path) = env::var(GOOGLE_APPLICATION_CREDENTIALS) {
            let cred = Self::load_file(&cred_path)?;
            Ok(Some(cred))
        } else {
            Ok(None)
        }
    }

    /// Load from well known locations:
    ///
    /// - `$HOME/.config/gcloud/application_default_credentials.json`
    /// - `%APPDATA%\gcloud\application_default_credentials.json`
    fn load_via_well_known_location(&self) -> Result<Option<CredentialAccount>> {
        if self.disable_well_known_location {
            return Ok(None);
        }

        let config_dir = if let Ok(v) = env::var("APPDATA") {
            v
        } else if let Ok(v) = env::var("XDG_CONFIG_HOME") {
            v
        } else if let Ok(v) = env::var("HOME") {
            format!("{v}/.config")
        } else {
            // User's env doesn't have a config dir.
            return Ok(None);
        };

        let cred = Self::load_file(&format!(
            "{config_dir}/gcloud/application_default_credentials.json"
        ))?;
        Ok(Some(cred))
    }

    /// Build credential loader from given path.
    fn load_file(path: &str) -> Result<CredentialAccount> {
        let content = std::fs::read(path).map_err(|err| {
            debug!("load credential failed at reading file: {err:?}");
            err
        })?;

        let account = serde_json::from_slice(&content).map_err(|err| {
            debug!("load credential failed at serde_json: {err:?}");
            err
        })?;

        Ok(account)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        external_account::{CredentialSource, FormatType},
        *,
    };

    #[test]
    fn loader_returns_service_account() {
        temp_env::with_vars(
            vec![(
                GOOGLE_APPLICATION_CREDENTIALS,
                Some(format!(
                    "{}/testdata/services/google/test_credential.json",
                    env::current_dir()
                        .expect("current_dir must exist")
                        .to_string_lossy()
                )),
            )],
            || {
                let cred_loader = CredentialLoader::default();

                let cred = cred_loader
                    .load_account()
                    .expect("credentail must be exist")
                    .unwrap();

                let CredentialAccount::ServiceAccount(cred) = cred else {
                        panic!("expected service account");
                    };

                assert_eq!("test-234@test.iam.gserviceaccount.com", &cred.client_email);
                assert_eq!(
                    "-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDOy4jaJIcVlffi5ENtlNhJ0tsI1zt21BI3DMGtPq7n3Ymow24w
BV2Z73l4dsqwRo2QVSwnCQ2bVtM2DgckMNDShfWfKe3LRcl96nnn51AtAYIfRnc+
ogstzxZi4J64f7IR3KIAFxJnzo+a6FS6MmsYMAs8/Oj68fRmCD0AbAs5ZwIDAQAB
AoGAVpPkMeBFJgZph/alPEWq4A2FYogp/y/+iEmw9IVf2PdpYNyhTz2P2JjoNEUX
ywFe12SxXY5uwfBx8RmiZ8aARkIBWs7q9Sz6f/4fdCHAuu3GAv5hmMO4dLQsGcKl
XAQW4QxZM5/x5IXlDh4KdcUP65P0ZNS3deqDlsq/vVfY9EECQQD9I/6KNmlSrbnf
Fa/5ybF+IV8mOkEfkslQT4a9pWbA1FF53Vk4e7B+Faow3uUGHYs/HUwrd3vIVP84
S+4Jeuc3AkEA0SGF5l3BrWWTok1Wr/UE+oPOUp2L4AV6kH8co11ZyxSQkRloLdMd
bNzNXShuhwgvNjvgkseNSeQPJKxFRn73UQJACacMtrJ6c6eiNcp66lhxhzC4kxmX
kB+lw4U0yxh6gZHXBYGWPFwjD7u9wJ1POFt6Cs8QL3wf4TS0gq4KhpwEIwJACIA8
WSjmfo3qemZ6Z5ymHyjMcj9FOE4AtW71Uw6wX7juR3eo7HPwdkRjdK34EDUc9i9o
6Y6DB8Xld7ApALyYgQJBAPTMFpKpCRNvYH5VrdObid5+T7OwDrJFHGWdbDGiT++O
V08rl535r74rMilnQ37X1/zaKBYyxpfhnd2XXgoCgTM=
-----END RSA PRIVATE KEY-----
",
                    &cred.private_key
                );
            },
        );
    }

    #[test]
    fn loader_returns_external_account() {
        temp_env::with_vars(
            vec![(
                GOOGLE_APPLICATION_CREDENTIALS,
                Some(format!(
                    "{}/testdata/services/google/test_external_account.json",
                    env::current_dir()
                        .expect("current_dir must exist")
                        .to_string_lossy()
                )),
            )],
            || {
                let cred_loader = CredentialLoader::default();

                let cred = cred_loader
                    .load_account()
                    .expect("credentail must be exist")
                    .unwrap();

                let CredentialAccount::ExternalAccount(cred) = cred else {
                        panic!("expected external account");
                    };

                assert_eq!(
                    "//iam.googleapis.com/projects/000000000000/locations/global/workloadIdentityPools/reqsign/providers/reqsign-provider",
                    &cred.audience
                );
                assert_eq!(
                    "urn:ietf:params:oauth:token-type:jwt",
                    &cred.subject_token_type
                );
                assert_eq!(
                    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test-234@test.iam.gserviceaccount.com:generateAccessToken",
                    &cred.service_account_impersonation_url.unwrap()
                );
                assert_eq!("https://sts.googleapis.com/v1/token", &cred.token_url);

                let CredentialSource::UrlSourced(source) = cred.credential_source else {
                    panic!("expected URL credential source");
                };

                assert_eq!("http://localhost:5000/token", &source.url);
                assert!(matches!(&source.format, FormatType::Json { .. }));
            },
        );
    }
}
