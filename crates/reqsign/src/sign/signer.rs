use crate::{Build, Context, Load};
use anyhow::Result;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Signer is the main struct used to sign the request.
#[derive(Clone, Debug)]
pub struct Signer<Ctx: Context> {
    loader: Arc<dyn Load<Context = Ctx>>,
    builder: Arc<dyn Build<Context = Ctx>>,
    context: Arc<Mutex<Option<Ctx>>>,
}

impl<Ctx: Context> Signer<Ctx> {
    /// Create a new signer.
    pub fn new(loader: impl Load<Context = Ctx>, builder: impl Build<Context = Ctx>) -> Self {
        Self {
            loader: Arc::new(loader),
            builder: Arc::new(builder),
            context: Arc::new(Mutex::new(None)),
        }
    }

    /// Signing request.
    pub async fn sign(
        &self,
        req: &mut http::request::Parts,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let ctx = self.context.lock().expect("lock poisoned").clone();
        let ctx = if ctx.is_valid() {
            ctx
        } else {
            let ctx = self.loader.load().await?;
            *self.context.lock().expect("lock poisoned") = ctx.clone();
            ctx
        };

        let signing = self.builder.build(req, ctx.as_ref(), expires_in).await?;
        signing.apply(req)
    }
}
