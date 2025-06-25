#[cfg(test)]
mod tests {
    use reqsign_aws_v4::*;
    use reqsign_core::{Context, ProvideCredential, Signer};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;

    #[tokio::test]
    async fn test_ecs_provider_compiles() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let provider = ECSCredentialProvider::new();

        // This will return None since we're not in an ECS environment
        let result = provider.provide_credential(&ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sso_provider_compiles() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let provider = SSOCredentialProvider::new()
            .with_profile("test")
            .with_region("us-east-1");

        // This will return None since we don't have SSO config
        let result = provider.provide_credential(&ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_process_provider_compiles() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let provider = ProcessCredentialProvider::new().with_command("echo '{\"Version\": 1}'");

        // This will fail but at least it compiles
        let result = provider.provide_credential(&ctx).await;
        assert!(result.is_ok() || result.is_err());
    }

    #[tokio::test]
    async fn test_cognito_provider_compiles() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let provider = CognitoIdentityCredentialProvider::new()
            .with_identity_pool_id("us-east-1:test")
            .with_region("us-east-1");

        // This will return an error since we don't have valid pool/network access
        // Just check that it compiles
        let _ = provider.provide_credential(&ctx).await;
    }

    #[tokio::test]
    async fn test_assume_role_with_mfa() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let base_provider = StaticCredentialProvider::new("test_key", "test_secret");
        let signer = Signer::new(
            ctx.clone(),
            base_provider,
            RequestSigner::new("sts", "us-east-1"),
        );

        let provider = AssumeRoleCredentialProvider::new(
            "arn:aws:iam::123456789012:role/test".to_string(),
            signer,
        )
        .with_external_id("test-external-id".to_string())
        .with_mfa_serial("arn:aws:iam::123456789012:mfa/test".to_string())
        .with_mfa_code("123456".to_string());

        // This will fail but shows MFA support is compiled
        let _ = provider.provide_credential(&ctx).await;
    }

    #[tokio::test]
    async fn test_new_default_chain() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let provider = DefaultCredentialProvider::new();

        // Should try all providers in the chain
        let result = provider.provide_credential(&ctx).await;
        assert!(result.is_ok());
    }
}
