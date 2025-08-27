mod authorized_user;
mod default;
mod external_account;
mod impersonated_service_account;
mod static_provider;
mod vm_metadata;

use reqsign_core::{Context, OsEnv, StaticEnv};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use std::collections::HashMap;

pub fn create_test_context() -> Context {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenv::dotenv();

    Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv)
}

pub fn create_test_context_with_env(envs: HashMap<String, String>) -> Context {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenv::dotenv();

    let home_dir = std::env::var("HOME").ok().map(std::path::PathBuf::from);

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    ctx.with_env(StaticEnv { home_dir, envs })
}
