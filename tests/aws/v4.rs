use std::env;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use http::Request;
use http::StatusCode;
use log::debug;
use log::warn;
use percent_encoding::utf8_percent_encode;
use percent_encoding::NON_ALPHANUMERIC;
use reqsign::AwsConfig;
use reqsign::AwsDefaultLoader;
use reqsign::AwsV4Signer;
use reqwest::Client;
use sha2::Digest;
use sha2::Sha256;

fn init_signer() -> Option<(AwsDefaultLoader, AwsV4Signer)> {
    let _ = env_logger::builder().is_test(true).try_init();

    dotenv::from_filename(".env").ok();

    if env::var("REQSIGN_AWS_V4_TEST").is_err() || env::var("REQSIGN_AWS_V4_TEST").unwrap() != "on"
    {
        return None;
    }

    let config = AwsConfig {
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
    .from_env()
    .from_profile();

    let region = config.region.as_deref().unwrap().to_string();

    let loader = AwsDefaultLoader::new(Client::new(), config);

    let signer = AwsV4Signer::new(
        &env::var("REQSIGN_AWS_V4_SERVICE").expect("env REQSIGN_AWS_V4_SERVICE must set"),
        &region,
    );

    Some((loader, signer))
}

#[tokio::test]
async fn test_head_object() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))?;

    let cred = loader
        .load()
        .await
        .expect("load request must success")
        .unwrap();
    signer
        .sign(&mut req, &cred)
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
async fn test_put_object_with_query() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();

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
        .load()
        .await
        .expect("load request must success")
        .unwrap();
    signer
        .sign_query(&mut req, Duration::from_secs(3600), &cred)
        .expect("sign request must success");

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
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))?;

    let cred = loader
        .load()
        .await
        .expect("load request must success")
        .unwrap();
    signer
        .sign_query(&mut req, Duration::from_secs(3600), &cred)
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
async fn test_head_object_with_special_characters() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
    ))?;

    let cred = loader
        .load()
        .await
        .expect("load request must success")
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
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
    ))?;

    let cred = loader
        .load()
        .await
        .expect("load request must success")
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
async fn test_list_bucket() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() =
        http::Uri::from_str(&format!("{url}?list-type=2&delimiter=/&encoding-type=url"))?;

    let cred = loader
        .load()
        .await
        .expect("load request must success")
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
    Ok(())
}
