mod assume_role;
mod assume_role_with_web_identity;
mod cognito;
mod ecs;
mod env;
mod imds;
#[cfg(not(target_arch = "wasm32"))]
mod process;
mod profile;
#[cfg(not(target_arch = "wasm32"))]
mod sso;

#[cfg(not(target_arch = "wasm32"))]
use reqsign_command_execute_tokio::TokioCommandExecute;
use reqsign_core::{Context, OsEnv, StaticEnv};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use std::collections::HashMap;

pub fn create_test_context() -> Context {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenv::dotenv();

    let mut ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    #[cfg(not(target_arch = "wasm32"))]
    {
        ctx = ctx.with_command_execute(TokioCommandExecute);
    }

    ctx
}

pub fn create_test_context_with_env(envs: HashMap<String, String>) -> Context {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenv::dotenv();

    // Get home directory from HOME environment variable if set
    let home_dir = std::env::var("HOME").ok().map(std::path::PathBuf::from);

    let mut ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    #[cfg(not(target_arch = "wasm32"))]
    {
        ctx = ctx.with_command_execute(TokioCommandExecute);
    }

    // StaticEnv overrides specific environment variables on top of OsEnv
    ctx.with_env(StaticEnv { home_dir, envs })
}
