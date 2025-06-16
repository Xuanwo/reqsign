use std::collections::HashMap;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use http::Request;
use http::StatusCode;
use log::debug;
use log::warn;
use percent_encoding::utf8_percent_encode;
use percent_encoding::NON_ALPHANUMERIC;
use reqsign_aws_v4::{AssumeRoleLoader, Config};
use reqsign_aws_v4::{Builder, DefaultLoader};
use reqsign_core::{Build, Context, ProvideCredential, Signer, StaticEnv};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqwest::Client;
use sha2::Digest;
use sha2::Sha256;
use tokio::fs;

async fn init_default_loader() -> Option<(Context, DefaultLoader, Builder)> {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenv::dotenv();

    if env::var("REQSIGN_AWS_V4_TEST").is_err() || env::var("REQSIGN_AWS_V4_TEST").unwrap() != "on"
    {
        return None;
    }

    let context = Context::new(TokioFileRead, ReqwestHttpSend::default());

    let config = Config {
        region: Some(
            env::var("REQSIGN_AWS_V4_REGION").expect("env REQSIGN_AWS_V4_REGION must set"),
        ),
        access_key_id: Some(
            env::var("REQSIGN_AWS_V4_ACCESS_KEY").expect("env REQSIGN_AWS_V4_ACCESS_KEY must set"),
        ),
        secret_access_key: Some(
            env::var("REQSIGN_AWS_V4_SECRET_KEY").expect("env REQSIGN_AWS_V4_SECRET_KEY must set"),
        ),
        ..Default::default()
    }
    .from_env(&context)
    .from_profile(&context)
    .await;

    let region = config.region.as_deref().unwrap().to_string();

    let loader = DefaultLoader::new(config.into());

    let builder = Builder::new(
        &env::var("REQSIGN_AWS_V4_SERVICE").expect("env REQSIGN_AWS_V4_SERVICE must set"),
        &region,
    );

    Some((context, loader, builder))
}

#[tokio::test]
async fn test_head_object() -> Result<()> {
    let Some((ctx, loader, builder)) = init_default_loader().await else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))?;

    let cred = loader
        .provide_credential(&ctx)
        .await
        .expect("load request must success")
        .unwrap();

    let req = {
        let (mut parts, body) = req.into_parts();
        builder
            .build(&ctx, &mut parts, Some(&cred), None)
            .await
            .expect("sign request must success");
        Request::from_parts(parts, body)
    };

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must succeed");

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::NOT_FOUND, resp.status());
    Ok(())
}

#[tokio::test]
async fn test_put_object_with_query() -> Result<()> {
    let Some((ctx, loader, builder)) = init_default_loader().await else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");
    let body = "Hello, World!";
    let body_digest = hex::encode(Sha256::digest(body).as_slice());

    let mut req = Request::new(body);
    req.headers_mut().insert(
        "x-amz-content-sha256",
        body_digest.parse().expect("parse digest failed"),
    );
    *req.method_mut() = http::Method::PUT;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "put_object_test"))?;

    let cred = loader
        .provide_credential(&ctx)
        .await
        .expect("load request must success")
        .unwrap();

    let req = {
        let (mut parts, body) = req.into_parts();
        builder
            .build(&ctx, &mut parts, Some(&cred), None)
            .await
            .expect("sign request must success");
        Request::from_parts(parts, body)
    };

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must succeed");

    let status = resp.status();
    debug!(
        "got response: {:?}",
        String::from_utf8(resp.bytes().await?.to_vec())?
    );
    assert_eq!(StatusCode::OK, status);
    Ok(())
}

#[tokio::test]
async fn test_get_object_with_query() -> Result<()> {
    let Some((ctx, loader, builder)) = init_default_loader().await else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))?;

    let cred = loader
        .provide_credential(&ctx)
        .await
        .expect("load request must success")
        .unwrap();

    let req = {
        let (mut parts, body) = req.into_parts();
        builder
            .build(
                &ctx,
                &mut parts,
                Some(&cred),
                Some(Duration::from_secs(3600)),
            )
            .await
            .expect("sign request must success");
        Request::from_parts(parts, body)
    };

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must success");

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::NOT_FOUND, resp.status());
    Ok(())
}

#[tokio::test]
async fn test_head_object_with_special_characters() -> Result<()> {
    let Some((ctx, loader, builder)) = init_default_loader().await else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
    ))?;

    let cred = loader
        .provide_credential(&ctx)
        .await
        .expect("load request must success")
        .unwrap();

    let req = {
        let (mut parts, body) = req.into_parts();
        builder
            .build(&ctx, &mut parts, Some(&cred), None)
            .await
            .expect("sign request must success");
        Request::from_parts(parts, body)
    };

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must success");

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::NOT_FOUND, resp.status());
    Ok(())
}

#[tokio::test]
async fn test_head_object_with_encoded_characters() -> Result<()> {
    let Some((ctx, loader, builder)) = init_default_loader().await else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
    ))?;

    let cred = loader
        .provide_credential(&ctx)
        .await
        .expect("load request must success")
        .unwrap();

    let req = {
        let (mut parts, body) = req.into_parts();
        builder
            .build(&ctx, &mut parts, Some(&cred), None)
            .await
            .expect("sign request must success");
        Request::from_parts(parts, body)
    };

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must success");

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::NOT_FOUND, resp.status());
    Ok(())
}

#[tokio::test]
async fn test_list_bucket() -> Result<()> {
    let Some((ctx, loader, builder)) = init_default_loader().await else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() =
        http::Uri::from_str(&format!("{url}?list-type=2&delimiter=/&encoding-type=url"))?;

    let cred = loader
        .provide_credential(&ctx)
        .await
        .expect("load request must success")
        .unwrap();

    let req = {
        let (mut parts, body) = req.into_parts();
        builder
            .build(&ctx, &mut parts, Some(&cred), None)
            .await
            .expect("sign request must success");
        Request::from_parts(parts, body)
    };

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must success");

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::OK, resp.status());
    Ok(())
}

#[tokio::test]
async fn test_signer_with_web_loader() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenv::dotenv();

    if env::var("REQSIGN_AWS_S3_TEST").is_err() || env::var("REQSIGN_AWS_S3_TEST").unwrap() != "on"
    {
        return Ok(());
    }

    // Ignore test if role_arn not set
    let role_arn = if let Ok(v) = env::var("REQSIGN_AWS_ASSUME_ROLE_ARN") {
        v
    } else {
        return Ok(());
    };

    let region = env::var("REQSIGN_AWS_S3_REGION").expect("REQSIGN_AWS_S3_REGION not exist");

    let github_token = env::var("GITHUB_ID_TOKEN").expect("GITHUB_ID_TOKEN not exist");
    let file_path = format!(
        "{}/testdata/web_identity_token_file",
        env::current_dir()
            .expect("current_dir must exist")
            .to_string_lossy()
    );
    fs::write(&file_path, github_token).await?;

    let context = Context::new(TokioFileRead, ReqwestHttpSend::default());
    let context = context.with_env(StaticEnv {
        home_dir: None,
        envs: HashMap::from_iter([
            ("AWS_REGION".to_string(), region.to_string()),
            ("AWS_ROLE_ARN".to_string(), role_arn.to_string()),
            (
                "AWS_WEB_IDENTITY_TOKEN_FILE".to_string(),
                file_path.to_string(),
            ),
        ]),
    });

    let config = Config::default().from_env(&context);
    let loader = DefaultLoader::new(config.into());

    let builder = Builder::new("s3", &region);

    let endpoint = format!("https://s3.{}.amazonaws.com/opendal-testing", region);
    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", endpoint, "not_exist_file")).unwrap();

    let cred = loader
        .provide_credential(&context)
        .await
        .expect("credential must be valid")
        .unwrap();

    let (mut req, body) = req.into_parts();
    builder
        .build(&context, &mut req, Some(&cred), None)
        .await
        .expect("sign must success");
    let req = Request::from_parts(req, body);

    debug!("signed request url: {:?}", req.uri().to_string());
    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client.execute(req.try_into().unwrap()).await.unwrap();

    let status = resp.status();
    debug!("got response: {:?}", resp);
    debug!("got response content: {:?}", resp.text().await.unwrap());
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn test_signer_with_web_loader_assume_role() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenv::dotenv();

    if env::var("REQSIGN_AWS_S3_TEST").is_err() || env::var("REQSIGN_AWS_S3_TEST").unwrap() != "on"
    {
        return Ok(());
    }

    // Ignore test if role_arn not set
    let role_arn = if let Ok(v) = env::var("REQSIGN_AWS_ROLE_ARN") {
        v
    } else {
        return Ok(());
    };
    // Ignore test if assume_role_arn not set
    let assume_role_arn = if let Ok(v) = env::var("REQSIGN_AWS_ASSUME_ROLE_ARN") {
        v
    } else {
        return Ok(());
    };

    let region = env::var("REQSIGN_AWS_S3_REGION").expect("REQSIGN_AWS_S3_REGION not exist");

    let github_token = env::var("GITHUB_ID_TOKEN").expect("GITHUB_ID_TOKEN not exist");
    let file_path = format!(
        "{}/testdata/web_identity_token_file",
        env::current_dir()
            .expect("current_dir must exist")
            .to_string_lossy()
    );
    fs::write(&file_path, github_token).await?;

    let context = Context::new(TokioFileRead, ReqwestHttpSend::default());
    let context = context.with_env(StaticEnv {
        home_dir: None,
        envs: HashMap::from_iter([
            ("AWS_REGION".to_string(), region.to_string()),
            ("AWS_ROLE_ARN".to_string(), role_arn.to_string()),
            (
                "AWS_WEB_IDENTITY_TOKEN_FILE".to_string(),
                file_path.to_string(),
            ),
        ]),
    });

    let cfg = Config {
        ec2_metadata_disabled: true,
        ..Default::default()
    };
    let cfg: Arc<Config> = cfg.from_env(&context).into();

    let default_loader = DefaultLoader::new(cfg.clone());
    let sts_signer = Signer::new(
        context.clone(),
        default_loader,
        Builder::new("sts", &region),
    );

    let cfg = Config {
        role_arn: Some(assume_role_arn.clone()),
        region: Some(region.clone()),
        sts_regional_endpoints: "regional".to_string(),
        ..Default::default()
    };
    let loader =
        AssumeRoleLoader::new(cfg.into(), sts_signer).expect("AssumeRoleLoader must be valid");

    let builder = Builder::new("s3", &region);
    let endpoint = format!("https://s3.{}.amazonaws.com/opendal-testing", region);
    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", endpoint, "not_exist_file")).unwrap();
    let cred = loader
        .provide_credential(&context)
        .await
        .expect("credential must be valid")
        .unwrap();

    let (mut parts, body) = req.into_parts();
    builder
        .build(&context, &mut parts, Some(&cred), None)
        .await
        .expect("sign must success");
    let req = Request::from_parts(parts, body);

    debug!("signed request url: {:?}", req.uri().to_string());
    debug!("signed request: {:?}", req);
    let client = Client::new();
    let resp = client.execute(req.try_into().unwrap()).await.unwrap();
    let status = resp.status();
    debug!("got response: {:?}", resp);
    debug!("got response content: {:?}", resp.text().await.unwrap());
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}
