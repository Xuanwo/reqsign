use crate::{Context, ProvideCredential, SignRequest, SigningCredential};
use anyhow::Result;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Signer is the main struct used to sign the request.
#[derive(Clone, Debug)]
pub struct Signer<K: SigningCredential> {
    ctx: Context,
    loader: Arc<dyn ProvideCredential<Credential = K>>,
    builder: Arc<dyn SignRequest<Credential = K>>,
    credential: Arc<Mutex<Option<K>>>,
}

impl<K: SigningCredential> Signer<K> {
    /// Create a new signer.
    pub fn new(
        ctx: Context,
        loader: impl ProvideCredential<Credential = K>,
        builder: impl SignRequest<Credential = K>,
    ) -> Self {
        Self {
            ctx,

            loader: Arc::new(loader),
            builder: Arc::new(builder),
            credential: Arc::new(Mutex::new(None)),
        }
    }

    /// Signing request.
    pub async fn sign(
        &self,
        req: &mut http::request::Parts,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let credential = self.credential.lock().expect("lock poisoned").clone();
        let credential = if credential.is_valid() {
            credential
        } else {
            let ctx = self.loader.provide_credential(&self.ctx).await?;
            *self.credential.lock().expect("lock poisoned") = ctx.clone();
            ctx
        };

        self.builder
            .sign_request(&self.ctx, req, credential.as_ref(), expires_in)
            .await
    }
}
