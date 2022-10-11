use std::env;

use anyhow::Result;
use http::StatusCode;
use log::debug;
use log::warn;
use reqsign::GoogleSigner;
use reqwest::blocking::Client;

fn init_signer() -> Option<GoogleSigner> {
    let _ = env_logger::builder().is_test(true).try_init();

    dotenv::from_filename(".env").ok();

    if env::var("REQSIGN_GOOGLE_TEST").is_err() || env::var("REQSIGN_GOOGLE_TEST").unwrap() != "on"
    {
        return None;
    }

    let mut builder = GoogleSigner::builder();
    builder.scope(
        &env::var("REQSIGN_GOOGLE_CLOUD_STORAGE_SCOPE")
            .expect("env REQSIGN_GOOGLE_CLOUD_STORAGE_SCOPE must set"),
    );
    builder.credential_from_content(
        &env::var("REQSIGN_GOOGLE_CREDENTIAL").expect("env REQSIGN_GOOGLE_CREDENTIAL must set"),
    );

    Some(builder.build().expect("signer must be valid"))
}

#[test]
fn test_get_object() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_GOOGLE_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_GOOGLE_CLOUD_STORAGE_URL")
        .expect("env REQSIGN_GOOGLE_CLOUD_STORAGE_URL must set");

    let mut builder = http::Request::builder();
    builder = builder.method(http::Method::GET);
    builder = builder.uri(format!("{}/o/{}", url, "not_exist_file"));
    let mut req = builder.body("")?;

    signer.sign(&mut req).expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .expect("request must succeed");

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::NOT_FOUND, resp.status());
    Ok(())
}

#[test]
fn test_list_objects() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_GOOGLE_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_GOOGLE_CLOUD_STORAGE_URL")
        .expect("env REQSIGN_GOOGLE_CLOUD_STORAGE_URL must set");

    let mut builder = http::Request::builder();
    builder = builder.method(http::Method::GET);
    builder = builder.uri(format!("{}/o", url));
    let mut req = builder.body("")?;

    signer.sign(&mut req).expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .expect("request must succeed");

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::OK, resp.status());
    Ok(())
}
