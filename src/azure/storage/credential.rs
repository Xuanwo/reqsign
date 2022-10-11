use crate::credential::Credential;
use std::sync::{Arc, RwLock};

/// CredentialLoader will load credential from different methods.
#[derive(Default)]
#[cfg_attr(test, derive(Debug))]
pub struct CredentialLoader {
    credential: Arc<RwLock<Option<Credential>>>,
}

impl CredentialLoader {
    /// Set Credential.
    pub fn with_credential(self, cred: Credential) -> Self {
        *self.credential.write().expect("lock poisoned") = Some(cred);
        self
    }

    /// Load credential.
    pub fn load(&self) -> Option<Credential> {
        // Return cached credential if it's valid.
        match self.credential.read().expect("lock poisoned").clone() {
            Some(cred) if cred.is_valid() => Some(cred),
            _ => None,
        }
    }
}
