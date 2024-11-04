use crate::Context;
use std::fmt::Debug;
use std::time::Duration;

/// Key is the trait used by signer as the signing key.
pub trait Key: Clone + Debug + Send + Sync + Unpin + 'static {
    /// Check if the key is valid.
    fn is_valid(&self) -> bool;
}

impl<T: Key> Key for Option<T> {
    fn is_valid(&self) -> bool {
        let Some(ctx) = self else {
            return false;
        };

        ctx.is_valid()
    }
}

/// Load is the trait used by signer to load the key from the environment.
///
/// Service may require different key to sign the request, for example, AWS require
/// access key and secret key, while Google Cloud Storage require token.
#[async_trait::async_trait]
pub trait Load: Debug + Send + Sync + Unpin + 'static {
    /// Key returned by this loader.
    ///
    /// Typically, it will be a credential.
    type Key: Send + Sync + Unpin + 'static;

    /// Load signing key from current env.
    async fn load(&self, ctx: &Context) -> anyhow::Result<Option<Self::Key>>;
}

/// Build is the trait used by signer to build the signing request.
#[async_trait::async_trait]
pub trait Build: Debug + Send + Sync + Unpin + 'static {
    /// Key used by this builder.
    ///
    /// Typically, it will be a credential.
    type Key: Send + Sync + Unpin + 'static;

    /// Construct the signing request.
    ///
    /// ## Key
    ///
    /// The `key` parameter is the key required by the signer to sign the request.
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
        ctx: &Context,
        req: &mut http::request::Parts,
        key: Option<&Self::Key>,
        expires_in: Option<Duration>,
    ) -> anyhow::Result<()>;
}
