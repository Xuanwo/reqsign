use anyhow::Result;
use http::StatusCode;
use log::{debug, warn};
use reqsign::services::azure::storage::Signer;
use std::env;

fn init_signer() -> Option<Signer> {
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

    Some(builder.build().expect("signer must be valid"))
}

#[test]
fn test_head_blob() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AZURE_STORAGE_ON_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url =
        &env::var("REQSIGN_AZURE_STORAGE_URL").expect("env REQSIGN_AZURE_STORAGE_URL must set");

    let mut builder = isahc::Request::builder();
    builder = builder.method(http::Method::HEAD);
    builder = builder.uri(format!("{}/{}", url, "not_exist_file"));
    let mut req = builder.body(isahc::Body::empty())?;

    signer.sign(&mut req).expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = isahc::HttpClient::new()?;
    let resp = client.send(req).expect("request must success");

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::NOT_FOUND, resp.status());
    Ok(())
}

#[test]
fn test_list_blobs() -> Result<()> {
    let signer = init_signer();
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
        let mut builder = isahc::Request::builder();
        builder = builder.method(http::Method::GET);
        builder = builder.uri(format!("{}?{}", url, query));
        let mut req = builder.body(isahc::Body::empty())?;

        signer.sign(&mut req).expect("sign request must success");

        debug!("signed request: {:?}", req);

        let client = isahc::HttpClient::new()?;
        let resp = client.send(req).expect("request must success");

        debug!("got response: {:?}", resp);
        assert_eq!(StatusCode::OK, resp.status());
    }

    Ok(())
}
