use std::env;
use std::time::Duration;

use anyhow::Result;
use http::Request;
use http::StatusCode;
use log::debug;
use log::warn;
use percent_encoding::utf8_percent_encode;
use percent_encoding::NON_ALPHANUMERIC;
use reqsign_azure_storage::{
    ConfigCredentialProvider, Credential, DefaultCredentialProvider, ImdsCredentialProvider,
    RequestSigner,
};
use reqsign_core::{Context, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqwest::Client;

fn init_signer() -> Option<(Context, Signer<Credential>)> {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenv::dotenv();

    if env::var("REQSIGN_AZURE_STORAGE_TEST").is_err()
        || env::var("REQSIGN_AZURE_STORAGE_TEST").unwrap() != "on"
    {
        return None;
    }

    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    let loader = ConfigCredentialProvider::new()
        .with_account_name(
            env::var("REQSIGN_AZURE_STORAGE_ACCOUNT_NAME")
                .expect("env REQSIGN_AZURE_STORAGE_ACCOUNT_NAME must set"),
        )
        .with_account_key(
            env::var("REQSIGN_AZURE_STORAGE_ACCOUNT_KEY")
                .expect("env REQSIGN_AZURE_STORAGE_ACCOUNT_KEY must set"),
        );

    let builder = RequestSigner::new();
    let signer = Signer::new(ctx.clone(), loader, builder);

    Some((ctx, signer))
}

#[tokio::test]
async fn test_head_blob() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AZURE_STORAGE_ON_TEST is not set, skipped");
        return Ok(());
    }
    let (_ctx, signer) = signer.unwrap();

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    let mut req = http::Request::builder()
        .method(http::Method::HEAD)
        .header("x-ms-version", "2023-01-03")
        .uri(format!("{}/{}", url, "not_exist_file"))
        .body(reqwest::Body::default())?;

    let (mut parts, body) = req.into_parts();
    signer.sign(&mut parts, None).await?;
    req = Request::from_parts(parts, body);

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into().map_err(|e| reqsign_core::Error::unexpected("failed to convert request").with_source(anyhow::Error::new(e)))?)
        .await
        .map_err(|e| reqsign_core::Error::unexpected("failed to execute request").with_source(anyhow::Error::new(e)))?;

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::NOT_FOUND, resp.status());
    Ok(())
}

#[tokio::test]
async fn test_head_object_with_encoded_characters() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AZURE_STORAGE_ON_TEST is not set, skipped");
        return Ok(());
    }
    let (_ctx, signer) = signer.unwrap();

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    let mut req = http::Request::builder()
        .method(http::Method::HEAD)
        .header("x-ms-version", "2023-01-03")
        .uri(format!(
            "{}/{}",
            url,
            utf8_percent_encode("!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
        ))
        .body(reqwest::Body::default())?;

    let (mut parts, body) = req.into_parts();
    signer.sign(&mut parts, None).await?;
    req = Request::from_parts(parts, body);

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into().map_err(|e| reqsign_core::Error::unexpected("failed to convert request").with_source(anyhow::Error::new(e)))?)
        .await
        .map_err(|e| reqsign_core::Error::unexpected("failed to execute request").with_source(anyhow::Error::new(e)))?;

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::NOT_FOUND, resp.status());
    Ok(())
}

#[tokio::test]
async fn test_list_container_blobs() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AZURE_STORAGE_ON_TEST is not set, skipped");
        return Ok(());
    }
    let (_ctx, signer) = signer.unwrap();

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    for query in [
        // Without prefix
        "restype=container&comp=list",
        // With not encoded prefix
        "restype=container&comp=list&prefix=test/path/to/dir",
        // With encoded prefix
        "restype=container&comp=list&prefix=test%2Fpath%2Fto%2Fdir",
    ] {
        let mut req = http::Request::builder()
            .method(http::Method::GET)
            .uri(format!("{url}?{query}"))
            .header("x-ms-version", "2023-01-03")
            .body(reqwest::Body::default())?;

        let (mut parts, body) = req.into_parts();
        signer.sign(&mut parts, None).await?;
        req = Request::from_parts(parts, body);

        debug!("signed request: {:?}", req);

        let client = Client::new();
        let resp = client
            .execute(req.try_into().map_err(|e| reqsign_core::Error::unexpected("failed to convert request").with_source(anyhow::Error::new(e)))?)
            .await
            .map_err(|e| reqsign_core::Error::unexpected("failed to execute request").with_source(anyhow::Error::new(e)))?;

        debug!("got response: {:?}", resp);
        assert_eq!(StatusCode::OK, resp.status());
    }

    Ok(())
}

#[tokio::test]
async fn test_can_head_blob_with_sas() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AZURE_STORAGE_ON_TEST is not set, skipped");
        return Ok(());
    }
    let (_ctx, signer) = signer.unwrap();

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    let mut req = http::Request::builder()
        .method(http::Method::HEAD)
        .header("x-ms-version", "2023-01-03")
        .uri(format!("{}/{}", url, "not_exist_file"))
        .body(reqwest::Body::default())?;

    let (mut parts, body) = req.into_parts();
    signer
        .sign(&mut parts, Some(Duration::from_secs(60)))
        .await?;
    req = Request::from_parts(parts, body);

    println!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into().map_err(|e| reqsign_core::Error::unexpected("failed to convert request").with_source(anyhow::Error::new(e)))?)
        .await
        .expect("request must success");

    println!("got response: {:?}", resp);
    assert_eq!(StatusCode::NOT_FOUND, resp.status());
    Ok(())
}

#[tokio::test]
async fn test_can_list_container_blobs() -> Result<()> {
    // API https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs?tabs=azure-ad
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AZURE_STORAGE_ON_TEST is not set, skipped");
        return Ok(());
    }
    let (_ctx, signer) = signer.unwrap();

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    for query in [
        // Without prefix
        "restype=container&comp=list",
        // With not encoded prefix
        "restype=container&comp=list&prefix=test/path/to/dir",
        // With encoded prefix
        "restype=container&comp=list&prefix=test%2Fpath%2Fto%2Fdir",
    ] {
        let mut req = http::Request::builder()
            .method(http::Method::GET)
            .header("x-ms-version", "2023-01-03")
            .uri(format!("{url}?{query}"))
            .body(reqwest::Body::default())?;

        let (mut parts, body) = req.into_parts();
        signer
            .sign(&mut parts, Some(Duration::from_secs(60)))
            .await?;
        req = Request::from_parts(parts, body);

        let client = Client::new();
        let resp = client
            .execute(req.try_into().map_err(|e| reqsign_core::Error::unexpected("failed to convert request").with_source(anyhow::Error::new(e)))?)
            .await
            .map_err(|e| reqsign_core::Error::unexpected("failed to execute request").with_source(anyhow::Error::new(e)))?;

        debug!("got response: {:?}", resp);
        assert_eq!(StatusCode::OK, resp.status());
    }

    Ok(())
}

/// This test must run on azure vm with imds enabled,
#[tokio::test]
async fn test_head_blob_with_imds() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenv::dotenv();

    if env::var("REQSIGN_AZURE_STORAGE_TEST").is_err()
        || env::var("REQSIGN_AZURE_STORAGE_TEST").unwrap() != "on"
        || env::var("REQSIGN_AZURE_STORAGE_CRED").is_err()
        || env::var("REQSIGN_AZURE_STORAGE_CRED").unwrap() != "imds"
    {
        return Ok(());
    }

    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    let loader = ImdsCredentialProvider::new();
    let builder = RequestSigner::new();
    let signer = Signer::new(ctx.clone(), loader, builder);

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    let mut req = http::Request::builder()
        .method(http::Method::HEAD)
        .header("x-ms-version", "2023-01-03")
        .uri(format!("{}/{}", url, "not_exist_file"))
        .body(reqwest::Body::default())?;

    let (mut parts, body) = req.into_parts();
    signer.sign(&mut parts, None).await?;
    req = Request::from_parts(parts, body);

    println!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into().map_err(|e| reqsign_core::Error::unexpected("failed to convert request").with_source(anyhow::Error::new(e)))?)
        .await
        .expect("request must success");

    assert_eq!(StatusCode::NOT_FOUND, resp.status());

    Ok(())
}

/// This test must run on azure vm with imds enabled
#[tokio::test]
async fn test_can_list_container_blobs_with_imds() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenv::dotenv();

    if env::var("REQSIGN_AZURE_STORAGE_TEST").is_err()
        || env::var("REQSIGN_AZURE_STORAGE_TEST").unwrap() != "on"
        || env::var("REQSIGN_AZURE_STORAGE_CRED").is_err()
        || env::var("REQSIGN_AZURE_STORAGE_CRED").unwrap() != "imds"
    {
        return Ok(());
    }

    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    let loader = ImdsCredentialProvider::new();
    let builder = RequestSigner::new();
    let signer = Signer::new(ctx.clone(), loader, builder);

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    for query in [
        // Without prefix
        "restype=container&comp=list",
        // With not encoded prefix
        "restype=container&comp=list&prefix=test/path/to/dir",
        // With encoded prefix
        "restype=container&comp=list&prefix=test%2Fpath%2Fto%2Fdir",
    ] {
        let mut req = http::Request::builder()
            .method(http::Method::GET)
            .header("x-ms-version", "2023-01-03")
            .uri(format!("{url}?{query}"))
            .body(reqwest::Body::default())?;

        let (mut parts, body) = req.into_parts();
        signer.sign(&mut parts, None).await?;
        req = Request::from_parts(parts, body);

        let client = Client::new();
        let resp = client
            .execute(req.try_into().map_err(|e| reqsign_core::Error::unexpected("failed to convert request").with_source(anyhow::Error::new(e)))?)
            .await
            .map_err(|e| reqsign_core::Error::unexpected("failed to execute request").with_source(anyhow::Error::new(e)))?;

        debug!("got response: {:?}", resp);
        assert_eq!(StatusCode::OK, resp.status());
    }

    Ok(())
}

/// This test must run on azure vm with client secret configured
#[tokio::test]
async fn test_head_blob_with_client_secret() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenv::dotenv();

    if env::var("REQSIGN_AZURE_STORAGE_TEST").is_err()
        || env::var("REQSIGN_AZURE_STORAGE_TEST").unwrap() != "on"
    {
        warn!("REQSIGN_AZURE_STORAGE_ON_TEST is not set, skipped");
        return Ok(());
    }

    if env::var("REQSIGN_AZURE_STORAGE_CLIENT_SECRET")
        .unwrap_or_default()
        .is_empty()
    {
        warn!("REQSIGN_AZURE_STORAGE_CLIENT_SECRET is not set, skipped");
        return Ok(());
    }

    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    let loader = DefaultCredentialProvider::new().from_env(&ctx);
    let builder = RequestSigner::new();
    let signer = Signer::new(ctx.clone(), loader, builder);

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    let mut req = http::Request::builder()
        .method(http::Method::HEAD)
        .header("x-ms-version", "2023-01-03")
        .uri(format!("{}/{}", url, "not_exist_file"))
        .body(reqwest::Body::default())?;

    let (mut parts, body) = req.into_parts();
    signer.sign(&mut parts, None).await?;
    req = Request::from_parts(parts, body);

    println!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into().map_err(|e| reqsign_core::Error::unexpected("failed to convert request").with_source(anyhow::Error::new(e)))?)
        .await
        .expect("request must success");

    assert_eq!(StatusCode::NOT_FOUND, resp.status());

    Ok(())
}

/// This test must run with client secret configured
#[tokio::test]
async fn test_can_list_container_blobs_client_secret() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenv::dotenv();

    if env::var("REQSIGN_AZURE_STORAGE_TEST").is_err()
        || env::var("REQSIGN_AZURE_STORAGE_TEST").unwrap() != "on"
    {
        warn!("REQSIGN_AZURE_STORAGE_ON_TEST is not set, skipped");
        return Ok(());
    }

    if env::var("REQSIGN_AZURE_STORAGE_CLIENT_SECRET")
        .unwrap_or_default()
        .is_empty()
    {
        warn!("REQSIGN_AZURE_STORAGE_CLIENT_SECRET is not set, skipped");
        return Ok(());
    }

    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    let loader = DefaultCredentialProvider::new().from_env(&ctx);
    let builder = RequestSigner::new();
    let signer = Signer::new(ctx.clone(), loader, builder);

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    for query in [
        // Without prefix
        "restype=container&comp=list",
        // With not encoded prefix
        "restype=container&comp=list&prefix=test/path/to/dir",
        // With encoded prefix
        "restype=container&comp=list&prefix=test%2Fpath%2Fto%2Fdir",
    ] {
        let mut req = http::Request::builder()
            .method(http::Method::GET)
            .header("x-ms-version", "2023-01-03")
            .uri(format!("{url}?{query}"))
            .body(reqwest::Body::default())?;

        let (mut parts, body) = req.into_parts();
        signer.sign(&mut parts, None).await?;
        req = Request::from_parts(parts, body);

        let client = Client::new();
        let resp = client
            .execute(req.try_into().map_err(|e| reqsign_core::Error::unexpected("failed to convert request").with_source(anyhow::Error::new(e)))?)
            .await
            .map_err(|e| reqsign_core::Error::unexpected("failed to execute request").with_source(anyhow::Error::new(e)))?;

        let stat = resp.status();
        debug!("got response: {:?}", resp);
        if stat != StatusCode::OK {
            debug!("{}", resp.text().await.map_err(|e| reqsign_core::Error::unexpected("failed to get response text").with_source(anyhow::Error::new(e)))?);
        }

        assert_eq!(StatusCode::OK, stat);
    }

    Ok(())
}
