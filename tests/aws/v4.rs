use anyhow::Result;
use http::StatusCode;
use log::{debug, warn};
use reqsign::services::aws::v4::Signer;
use std::env;

async fn init_signer() -> Option<Signer> {
    let _ = env_logger::builder().is_test(true).try_init();

    dotenv::from_filename(".env").ok();

    if env::var("REQSIGN_AWS_V4_TEST").is_err() || env::var("REQSIGN_AWS_V4_TEST").unwrap() != "on"
    {
        return None;
    }

    let mut builder = Signer::builder();
    builder
        .service(&env::var("REQSIGN_AWS_V4_SERVICE").expect("env REQSIGN_AWS_V4_SERVICE must set"));
    builder.region(&env::var("REQSIGN_AWS_V4_REGION").expect("env REQSIGN_AWS_V4_REGION must set"));
    builder.access_key(
        &env::var("REQSIGN_AWS_V4_ACCESS_KEY").expect("env REQSIGN_AWS_V4_ACCESS_KEY must set"),
    );
    builder.secret_key(
        &env::var("REQSIGN_AWS_V4_SECRET_KEY").expect("env REQSIGN_AWS_V4_SECRET_KEY must set"),
    );

    Some(builder.build().await.expect("signer must be valid"))
}

#[tokio::test]
async fn test_head_object() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

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
async fn test_list_bucket() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = reqwest::Request::new(
        http::Method::GET,
        format!("{}?list-type=2&delimiter=/&encoding-type=url", url).parse()?,
    );

    signer
        .sign(&mut req)
        .await
        .expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = reqwest::Client::new();
    let resp = client.execute(req).await.expect("request must success");

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::OK, resp.status());
    Ok(())
}
