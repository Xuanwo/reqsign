use std::sync::Arc;
use std::sync::RwLock;
use std::thread::sleep;
use backon::{BackoffBuilder, ExponentialBuilder};
use log::warn;
use serde::Deserialize;

use super::config::ConfigLoader;
use crate::credential::Credential;

/// CredentialLoader will load credential from different methods.
#[cfg_attr(test, derive(Debug))]
pub struct CredentialLoader {
    credential: Arc<RwLock<Option<Credential>>>,

    disable_env: bool,
    disable_assume_role_with_oidc: bool,
    config_loader: ConfigLoader,
}

impl Default for CredentialLoader {
    fn default() -> Self {
        Self {
            credential: Arc::new(Default::default()),
            disable_env: false,
            disable_assume_role_with_oidc: false,
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
        let mut retry = ExponentialBuilder::default()
            .with_max_times(4)
            .with_jitter()
            .build();

        let cred = loop {
            let cred = self.load_via_env();

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
            self.config_loader.secret_id(),
            self.config_loader.secret_key(),
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