use anyhow::Result;
use http::header;
use httpdate::fmt_http_date;
use log::{debug, warn};
use reqsign::services::azure::storage::Signer;
use reqwest::{Request, StatusCode, Url};
use std::env;
use std::time::SystemTime;
use time::format_description::well_known::Rfc2822;
use time::OffsetDateTime;

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
async fn test_head_object() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_AZURE_STORAGE_ON_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let endpoint = &env::var("REQSIGN_AZURE_STORAGE_ENDPOINT")
        .expect("env REQSIGN_AZURE_STORAGE_ENDPOINT must set");
    let bucket = &env::var("REQSIGN_AZURE_STORAGE_BUCKET")
        .expect("env REQSIGN_AZURE_STORAGE_BUCKET must set");

    let mut req = reqwest::Request::new(
        http::Method::HEAD,
        format!("{}/{}/{}", endpoint, bucket, "not_exist_file").parse()?,
    );

    signer
        .sign(&mut req)
        .await
        .expect("sign request must success");

    debug!("current header: {:?}", req.headers());

    let client = reqwest::Client::new();
    let resp = client.execute(req).await.expect("request must success");

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::NOT_FOUND, resp.status());
    Ok(())
}
