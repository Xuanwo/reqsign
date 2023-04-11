use std::env;
use std::time::Duration;

use anyhow::Result;
use http::StatusCode;
use log::debug;
use log::warn;
use reqsign::GoogleCredentialLoader;
use reqsign::GoogleSigner;
use reqsign::GoogleTokenLoader;
use reqwest::Client;

async fn init_signer() -> Option<(GoogleCredentialLoader, GoogleTokenLoader, GoogleSigner)> {
    let _ = env_logger::builder().is_test(true).try_init();

    dotenv::from_filename(".env").ok();

    if env::var("REQSIGN_GOOGLE_TEST").is_err() || env::var("REQSIGN_GOOGLE_TEST").unwrap() != "on"
    {
        return None;
    }

    let cred_loader = GoogleCredentialLoader::default().with_content(
        &env::var("REQSIGN_GOOGLE_CREDENTIAL").expect("env REQSIGN_GOOGLE_CREDENTIAL must set"),
    );

    let token_loader = GoogleTokenLoader::new(
        &env::var("REQSIGN_GOOGLE_CLOUD_STORAGE_SCOPE")
            .expect("env REQSIGN_GOOGLE_CLOUD_STORAGE_SCOPE must set"),
        Client::new(),
    )
    .with_credentials(cred_loader.load().unwrap().unwrap());

    let signer = GoogleSigner::new("storage");

    Some((cred_loader, token_loader, signer))
}

#[tokio::test]
async fn test_get_object() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_GOOGLE_TEST is not set, skipped");
        return Ok(());
    }
    let (_, token_loader, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_GOOGLE_CLOUD_STORAGE_URL")
        .expect("env REQSIGN_GOOGLE_CLOUD_STORAGE_URL must set");

    let mut builder = http::Request::builder();
    builder = builder.method(http::Method::GET);
    builder = builder.uri(format!("{}/o/{}", url, "not_exist_file"));
    let mut req = builder.body("")?;

    let token = token_loader.load().await?.unwrap();
    signer
        .sign(&mut req, &token)
        .expect("sign request must success");

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
async fn test_list_objects() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_GOOGLE_TEST is not set, skipped");
        return Ok(());
    }
    let (_, token_loader, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_GOOGLE_CLOUD_STORAGE_URL")
        .expect("env REQSIGN_GOOGLE_CLOUD_STORAGE_URL must set");

    let mut builder = http::Request::builder();
    builder = builder.method(http::Method::GET);
    builder = builder.uri(format!("{url}/o"));
    let mut req = builder.body("")?;

    let token = token_loader.load().await?.unwrap();
    signer
        .sign(&mut req, &token)
        .expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must succeed");

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::OK, resp.status());
    Ok(())
}

#[tokio::test]
async fn test_get_object_with_query() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_GOOGLE_TEST is not set, skipped");
        return Ok(());
    }
    let (cred_loader, _, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_GOOGLE_CLOUD_STORAGE_URL")
        .expect("env REQSIGN_GOOGLE_CLOUD_STORAGE_URL must set");

    let mut builder = http::Request::builder();
    builder = builder.method(http::Method::GET);
    builder = builder.uri(format!(
        "{}/{}",
        url.replace("storage/v1/b/", ""),
        "not_exist_file"
    ));
    let mut req = builder.body("")?;

    let cred = cred_loader.load()?.unwrap();
    signer
        .sign_query(&mut req, Duration::from_secs(3600), &cred)
        .expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must succeed");

    let code = resp.status();
    debug!("got response: {:?}", resp);
    debug!("got body: {}", resp.text().await?);
    assert_eq!(StatusCode::NOT_FOUND, code);
    Ok(())
}
