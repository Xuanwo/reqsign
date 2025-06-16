use crate::Context;
use std::fmt::Debug;
use std::time::Duration;

/// SigningCredential is the trait used by signer as the signing credential.
pub trait SigningCredential: Clone + Debug + Send + Sync + Unpin + 'static {
    /// Check if the signing credential is valid.
    fn is_valid(&self) -> bool;
}

impl<T: SigningCredential> SigningCredential for Option<T> {
    fn is_valid(&self) -> bool {
        let Some(ctx) = self else {
            return false;
        };

        ctx.is_valid()
    }
}

/// ProvideCredential is the trait used by signer to load the key from the environment.
///
/// Service may require different key to sign the request, for example, AWS require
/// access key and secret key, while Google Cloud Storage require token.
#[async_trait::async_trait]
pub trait ProvideCredential: Debug + Send + Sync + Unpin + 'static {
    /// Credential returned by this loader.
    ///
    /// Typically, it will be a credential.
    type Credential: Send + Sync + Unpin + 'static;

    /// Load signing credential from current env.
    async fn provide_credential(&self, ctx: &Context) -> anyhow::Result<Option<Self::Credential>>;
}

/// SignRequest is the trait used by signer to build the signing request.
#[async_trait::async_trait]
pub trait SignRequest: Debug + Send + Sync + Unpin + 'static {
    /// Credential used by this builder.
    ///
    /// Typically, it will be a credential.
    type Credential: Send + Sync + Unpin + 'static;

    /// Construct the signing request.
    ///
    /// ## Credential
    ///
    /// The `credential` parameter is the credential required by the signer to sign the request.
    ///
    /// ## Expires In
    ///
    /// The `expires_in` parameter specifies the expiration time for the result.
    /// If the signer does not support expiration, it should return an error.
    ///
    /// Implementation details determine how to handle the expiration logic. For instance,
    /// AWS uses a query string that includes an `Expires` parameter.
    async fn sign_request(
        &self,
        ctx: &Context,
        req: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> anyhow::Result<()>;
}
