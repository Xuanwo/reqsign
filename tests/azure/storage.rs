use std::env;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use http::StatusCode;
use log::debug;
use log::warn;
use percent_encoding::utf8_percent_encode;
use percent_encoding::NON_ALPHANUMERIC;
use reqsign::AzureStorageConfig;
use reqsign::AzureStorageLoader;
use reqsign::AzureStorageSigner;
use reqwest::Client;

fn init_signer() -> Option<(AzureStorageLoader, AzureStorageSigner)> {
    let _ = env_logger::builder().is_test(true).try_init();

    dotenv::from_filename(".env").ok();

    if env::var("REQSIGN_AZURE_STORAGE_TEST").is_err()
        || env::var("REQSIGN_AZURE_STORAGE_TEST").unwrap() != "on"
    {
        return None;
    }

    let config = AzureStorageConfig {
        account_name: Some(
            env::var("REQSIGN_AZURE_STORAGE_ACCOUNT_NAME")
                .expect("env REQSIGN_AZURE_STORAGE_ACCOUNT_NAME must set"),
        ),
        account_key: Some(
            env::var("REQSIGN_AZURE_STORAGE_ACCOUNT_KEY")
                .expect("env REQSIGN_AZURE_STORAGE_ACCOUNT_KEY must set"),
        ),
        ..Default::default()
    };

    let loader = AzureStorageLoader::new(config);

    Some((loader, AzureStorageSigner::new()))
}

#[tokio::test]
async fn test_head_blob() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AZURE_STORAGE_ON_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    let mut builder = http::Request::builder();
    builder = builder.method(http::Method::HEAD);
    builder = builder.header("x-ms-version", "2023-01-03");
    builder = builder.uri(format!("{}/{}", url, "not_exist_file"));
    let mut req = builder.body("")?;

    let cred = loader
        .load()
        .await
        .expect("load credential must success")
        .unwrap();
    signer
        .sign(&mut req, &cred)
        .expect("sign request must success");

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
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AZURE_STORAGE_ON_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    let mut req = http::Request::new("");
    *req.method_mut() = http::Method::HEAD;
    req.headers_mut()
        .insert("x-ms-version", "2023-01-03".parse().unwrap());
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
    ))?;

    let cred = loader
        .load()
        .await
        .expect("load credential must success")
        .unwrap();
    signer
        .sign(&mut req, &cred)
        .expect("sign request must success");

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
async fn test_list_container_blobs() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AZURE_STORAGE_ON_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();

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
        let mut builder = http::Request::builder();
        builder = builder.method(http::Method::GET);
        builder = builder.uri(format!("{url}?{query}"));
        builder = builder.header("x-ms-version", "2023-01-03");
        let mut req = builder.body("")?;

        let cred = loader
            .load()
            .await
            .expect("load credential must success")
            .unwrap();
        signer
            .sign(&mut req, &cred)
            .expect("sign request must success");

        debug!("signed request: {:?}", req);

        let client = Client::new();
        let resp = client
            .execute(req.try_into()?)
            .await
            .expect("request must success");

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
    let (loader, signer) = signer.unwrap();

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    let mut builder = http::Request::builder();
    builder = builder.method(http::Method::HEAD);
    builder = builder.header("x-ms-version", "2023-01-03");
    builder = builder.uri(format!("{}/{}", url, "not_exist_file"));
    let mut req = builder.body("")?;

    let cred = loader
        .load()
        .await
        .expect("load credential must success")
        .unwrap();
    signer
        .sign_query(&mut req, Duration::from_secs(60), &cred)
        .expect("sign request must success");

    println!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
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
    let (loader, signer) = signer.unwrap();

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
        let mut builder = http::Request::builder();
        builder = builder.method(http::Method::GET);
        builder = builder.header("x-ms-version", "2023-01-03");
        builder = builder.uri(format!("{url}?{query}"));
        let mut req = builder.body("")?;

        let cred = loader
            .load()
            .await
            .expect("load credential must success")
            .unwrap();
        signer
            .sign_query(&mut req, Duration::from_secs(60), &cred)
            .expect("sign request must success");

        let client = Client::new();
        let resp = client
            .execute(req.try_into()?)
            .await
            .expect("request must success");

        debug!("got response: {:?}", resp);
        assert_eq!(StatusCode::OK, resp.status());
    }

    Ok(())
}

/// This test must run on azure vm with imds enabled,
#[tokio::test]
async fn test_head_blob_with_ldms() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    dotenv::from_filename(".env").ok();

    if env::var("REQSIGN_AZURE_STORAGE_TEST").is_err()
        || env::var("REQSIGN_AZURE_STORAGE_TEST").unwrap() != "on"
        || env::var("REQSIGN_AZURE_STORAGE_CRED").is_err()
        || env::var("REQSIGN_AZURE_STORAGE_CRED").unwrap() != "imds"
    {
        return Ok(());
    }

    let config = AzureStorageConfig {
        ..Default::default()
    };
    let loader = AzureStorageLoader::new(config);
    let cred = loader
        .load()
        .await
        .expect("load credential must success")
        .unwrap();

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    let mut req = http::Request::builder()
        .method(http::Method::HEAD)
        .header("x-ms-version", "2023-01-03")
        .uri(format!("{}/{}", url, "not_exist_file"))
        .body("")?;

    AzureStorageSigner::new()
        .sign(&mut req, &cred)
        .expect("sign request must success");

    println!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must success");

    assert_eq!(StatusCode::NOT_FOUND, resp.status());

    Ok(())
}

/// This test must run on azure vm with imds enabled
#[tokio::test]
async fn test_can_list_container_blobs_with_ldms() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    dotenv::from_filename(".env").ok();

    if env::var("REQSIGN_AZURE_STORAGE_TEST").is_err()
        || env::var("REQSIGN_AZURE_STORAGE_TEST").unwrap() != "on"
        || env::var("REQSIGN_AZURE_STORAGE_CRED").is_err()
        || env::var("REQSIGN_AZURE_STORAGE_CRED").unwrap() != "imds"
    {
        return Ok(());
    }

    let config = AzureStorageConfig {
        ..Default::default()
    };
    let loader = AzureStorageLoader::new(config);
    let cred = loader
        .load()
        .await
        .expect("load credential must success")
        .unwrap();

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
        let mut builder = http::Request::builder();
        builder = builder.method(http::Method::GET);
        builder = builder.header("x-ms-version", "2023-01-03");
        builder = builder.uri(format!("{url}?{query}"));
        let mut req = builder.body("")?;

        AzureStorageSigner::new()
            .sign(&mut req, &cred)
            .expect("sign request must success");

        let client = Client::new();
        let resp = client
            .execute(req.try_into()?)
            .await
            .expect("request must success");

        debug!("got response: {:?}", resp);
        assert_eq!(StatusCode::OK, resp.status());
    }

    Ok(())
}
