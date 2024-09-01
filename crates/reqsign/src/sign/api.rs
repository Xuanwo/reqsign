use super::SigningRequest;
use std::fmt::Debug;
use std::time::Duration;

/// Context is the trait used by signer as the signing context.
pub trait Context: Clone + Debug + Send + Sync + Unpin + 'static {
    /// Check if the context is valid.
    fn is_valid(&self) -> bool;
}

impl<T: Context> Context for Option<T> {
    fn is_valid(&self) -> bool {
        let Some(ctx) = self else {
            return false;
        };

        ctx.is_valid()
    }
}

/// Load is the trait used by signer to load the context from the environment.
///
/// Service may require different context to sign the request, for example, AWS require
/// access key and secret key, while Google Cloud Storage require token.
#[async_trait::async_trait]
pub trait Load: Debug + Send + Sync + Unpin + 'static {
    /// Context returned by this loader.
    ///
    /// Typically, it will be a credential.
    type Context: Send + Sync + Unpin + 'static;

    /// Load signing context from current env.
    async fn load(&self) -> anyhow::Result<Option<Self::Context>>;
}

/// Build is the trait used by signer to build the signing request.
#[async_trait::async_trait]
pub trait Build: Debug + Send + Sync + Unpin + 'static {
    /// Context used by this builder.
    ///
    /// Typically, it will be a credential.
    type Context: Send + Sync + Unpin + 'static;

    /// Construct the signing request.
    ///
    /// ## Context
    ///
    /// The `ctx` parameter is the context required by the signer to sign the request.
    ///
    /// ## Expires In
    ///
    /// The `expires_in` parameter specifies the expiration time for the result.
    /// If the signer does not support expiration, it should return an error.
    ///
    /// Implementation details determine how to handle the expiration logic. For instance,
    /// AWS uses a query string that includes an `Expires` parameter.
    async fn build(
        &self,
        req: &mut http::request::Parts,
        ctx: Option<&Self::Context>,
        expires_in: Option<Duration>,
    ) -> anyhow::Result<SigningRequest>;
}
