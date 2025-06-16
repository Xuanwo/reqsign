use crate::{Build, Context, Key, ProvideCredential};
use anyhow::Result;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Signer is the main struct used to sign the request.
#[derive(Clone, Debug)]
pub struct Signer<K: Key> {
    ctx: Context,
    loader: Arc<dyn ProvideCredential<Credential = K>>,
    builder: Arc<dyn Build<Key = K>>,
    key: Arc<Mutex<Option<K>>>,
}

impl<K: Key> Signer<K> {
    /// Create a new signer.
    pub fn new(ctx: Context, loader: impl ProvideCredential<Credential = K>, builder: impl Build<Key = K>) -> Self {
        Self {
            ctx,

            loader: Arc::new(loader),
            builder: Arc::new(builder),
            key: Arc::new(Mutex::new(None)),
        }
    }

    /// Signing request.
    pub async fn sign(
        &self,
        req: &mut http::request::Parts,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let key = self.key.lock().expect("lock poisoned").clone();
        let key = if key.is_valid() {
            key
        } else {
            let ctx = self.loader.provide_credential(&self.ctx).await?;
            *self.key.lock().expect("lock poisoned") = ctx.clone();
            ctx
        };

        self.builder
            .build(&self.ctx, req, key.as_ref(), expires_in)
            .await
    }
}
