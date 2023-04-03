use std::env;
use std::sync::Arc;
use std::sync::Mutex;

use log::debug;
use serde::Deserialize;

use super::constants::GOOGLE_APPLICATION_CREDENTIALS;
use crate::hash::base64_decode;
use crate::Error;
use crate::ErrorKind;
use crate::Result;

/// Credential is the file which stores service account's client_id and private key.
#[derive(Clone, Deserialize)]
#[cfg_attr(test, derive(Debug))]
pub struct Credential {
    /// Private key of credential
    pub private_key: String,
    /// The client email of credential
    pub client_email: String,
}

/// CredentialLoader will load credential from different methods.
#[derive(Default)]
#[cfg_attr(test, derive(Debug))]
pub struct CredentialLoader {
    path: Option<String>,
    content: Option<String>,
    disable_env: bool,
    disable_well_known_location: bool,

    credential: Arc<Mutex<Option<Credential>>>,
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
    pub async fn load(&self) -> Result<Credential> {
        // Return cached credential if it has been loaded at least once.
        if let Some(cred) = self.credential.lock().expect("lock poisoned").clone() {
            return Ok(cred);
        }

        let cred = self.load_inner().await?;

        let mut lock = self.credential.lock().expect("lock poisoned");
        *lock = Some(cred.clone());

        Ok(cred)
    }

    async fn load_inner(&self) -> Result<Credential> {
        if let Ok(Some(cred)) = self.load_via_content() {
            return Ok(cred);
        }

        if let Ok(Some(cred)) = self.load_via_path().await {
            return Ok(cred);
        }

        if let Ok(Some(cred)) = self.load_via_env().await {
            return Ok(cred);
        }

        if let Ok(Some(cred)) = self.load_via_well_known_location().await {
            return Ok(cred);
        }

        Err(Error::new(
            ErrorKind::NotFound,
            "no credential found for google service",
        ))
    }

    async fn load_via_path(&self) -> Result<Option<Credential>> {
        let path = if let Some(path) = &self.path {
            path
        } else {
            return Ok(None);
        };

        Ok(Some(Self::load_file(path).await?))
    }

    /// Build credential loader from given base64 content.
    fn load_via_content(&self) -> Result<Option<Credential>> {
        let content = if let Some(content) = &self.content {
            content
        } else {
            return Ok(None);
        };

        let cred: Credential = serde_json::from_slice(&base64_decode(content)).map_err(|err| {
            debug!("load credential from content failed: {err:?}");
            err
        })?;
        Ok(Some(cred))
    }

    /// Load from env GOOGLE_APPLICATION_CREDENTIALS.
    async fn load_via_env(&self) -> Result<Option<Credential>> {
        if self.disable_env {
            return Ok(None);
        }

        if let Ok(cred_path) = env::var(GOOGLE_APPLICATION_CREDENTIALS) {
            let cred = Self::load_file(&cred_path).await?;
            Ok(Some(cred))
        } else {
            Ok(None)
        }
    }

    /// Load from well known locations:
    ///
    /// - `$HOME/.config/gcloud/application_default_credentials.json`
    /// - `%APPDATA%\gcloud\application_default_credentials.json`
    async fn load_via_well_known_location(&self) -> Result<Option<Credential>> {
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
        ))
        .await?;
        Ok(Some(cred))
    }

    /// Build credential loader from given path.
    async fn load_file(path: &str) -> Result<Credential> {
        let content = tokio::fs::read(path).await.map_err(|err| {
            debug!("load credential failed at reading file: {err:?}");
            err
        })?;

        let credential: Credential = serde_json::from_slice(&content).map_err(|err| {
            debug!("load credential failed at serde_json: {err:?}");
            err
        })?;

        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;
    use tokio::runtime::Runtime;

    use super::*;

    static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Should create a tokio runtime")
    });

    #[test]
    fn test_credential_loader() {
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
                RUNTIME.block_on(async {
                    let cred_loader = CredentialLoader::default();

                    let cred = cred_loader.load().await.expect("credentail must be exist");

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
                })
            },
        );
    }
}
