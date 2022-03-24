use anyhow::Result;
use log::{debug, warn};
use reqsign::services::azure::storage::Signer;
use reqwest::StatusCode;
use std::env;

async fn init_signer() -> Option<Signer> {
    let _ = env_logger::builder().is_test(true).try_init();

    dotenv::from_filename(".env").ok();

    if env::var("REQSIGN_AZURE_STORAGE_TEST").is_err()
        || env::var("REQSIGN_AZURE_STORAGE_TEST").unwrap() != "on"
    {
        return None;
    }

    let mut builder = Signer::builder();
    builder.account_name(
        &env::var("REQSIGN_AZURE_STORAGE_ACCOUNT_NAME")
            .expect("env REQSIGN_AZURE_STORAGE_ACCOUNT_NAME must set"),
    );
    builder.account_key(
        &env::var("REQSIGN_AZURE_STORAGE_ACCOUNT_KEY")
            .expect("env REQSIGN_AZURE_STORAGE_ACCOUNT_KEY must set"),
    );

    Some(builder.build().await.expect("signer must be valid"))
}

#[tokio::test]
async fn test_head_blob() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_AZURE_STORAGE_ON_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    let mut req = reqwest::Request::new(
        http::Method::HEAD,
        format!("{}/{}", url, "not_exist_file").parse()?,
    );

    signer
        .sign(&mut req)
        .await
        .expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = reqwest::Client::new();
    let resp = client.execute(req).await.expect("request must success");

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::NOT_FOUND, resp.status());
    Ok(())
}

#[tokio::test]
async fn test_list_blobs() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_AZURE_STORAGE_ON_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

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
        let mut req =
            reqwest::Request::new(http::Method::GET, format!("{}?{}", url, query).parse()?);

        signer
            .sign(&mut req)
            .await
            .expect("sign request must success");

        debug!("signed request: {:?}", req);

        let client = reqwest::Client::new();
        let resp = client.execute(req).await.expect("request must success");

        debug!("got response: {:?}", resp);
        assert_eq!(StatusCode::OK, resp.status());
    }

    Ok(())
}
