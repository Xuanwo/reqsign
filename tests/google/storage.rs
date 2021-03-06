use anyhow::Result;
use http::StatusCode;
use isahc::HttpClient;
use log::{debug, warn};
use reqsign::services::google::Signer;
use std::env;

fn init_signer() -> Option<Signer> {
    let _ = env_logger::builder().is_test(true).try_init();

    dotenv::from_filename(".env").ok();

    if env::var("REQSIGN_GOOGLE_TEST").is_err() || env::var("REQSIGN_GOOGLE_TEST").unwrap() != "on"
    {
        return None;
    }

    let mut builder = Signer::builder();
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

    let mut builder = isahc::Request::builder();
    builder = builder.method(http::Method::GET);
    builder = builder.uri(format!("{}/o/{}", url, "not_exist_file"));
    let mut req = builder.body(isahc::Body::empty())?;

    signer.sign(&mut req).expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = HttpClient::new()?;
    let resp = client.send(req).expect("request must success");

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

    let mut builder = isahc::Request::builder();
    builder = builder.method(http::Method::GET);
    builder = builder.uri(format!("{}/o", url));
    let mut req = builder.body(isahc::Body::empty())?;

    signer.sign(&mut req).expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = HttpClient::new()?;
    let resp = client.send(req).expect("request must success");

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::OK, resp.status());
    Ok(())
}
