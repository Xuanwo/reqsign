use std::time::Duration;

use crate::request::SignableRequest;

#[allow(unused)]
#[async_trait::async_trait]
pub trait Sign<R: SignableRequest>: 'static {
    type Credential;

    async fn sign(&self, req: &mut R, cred: &Self::Credential) -> anyhow::Result<()>;

    async fn sign_query(
        &self,
        req: &mut R,
        expires: Duration,
        cred: &Self::Credential,
    ) -> anyhow::Result<()>;
}
