use super::{init_signing_test, load_static_credential, send_signed_request};
use anyhow::Result;
use http::{Method, Request, StatusCode};
use log::warn;
use sha2::{Digest, Sha256};
use std::str::FromStr;

#[tokio::test]
async fn test_head_object() -> Result<()> {
    let Some((ctx, signer, url)) = init_signing_test() else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let cred = load_static_credential()?;

    let mut req = Request::new(String::new());
    *req.method_mut() = Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))?;

    let (status, _body) = send_signed_request(&ctx, &signer, req, &cred).await?;
    assert_eq!(StatusCode::NOT_FOUND, status);
    Ok(())
}

#[tokio::test]
async fn test_get_object() -> Result<()> {
    let Some((ctx, signer, url)) = init_signing_test() else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let cred = load_static_credential()?;

    let mut req = Request::new(String::new());
    *req.method_mut() = Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))?;

    let (status, _body) = send_signed_request(&ctx, &signer, req, &cred).await?;
    assert_eq!(StatusCode::NOT_FOUND, status);
    Ok(())
}

#[tokio::test]
async fn test_put_object() -> Result<()> {
    let Some((ctx, signer, url)) = init_signing_test() else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let cred = load_static_credential()?;
    let body = "Hello, World!";
    let body_digest = hex::encode(Sha256::digest(body).as_slice());

    let mut req = Request::new(body.to_string());
    req.headers_mut().insert(
        "x-amz-content-sha256",
        body_digest.parse().expect("parse digest failed"),
    );
    *req.method_mut() = Method::PUT;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "put_object_test"))?;

    let (status, _body) = send_signed_request(&ctx, &signer, req, &cred).await?;
    assert_eq!(StatusCode::OK, status);
    Ok(())
}

#[tokio::test]
async fn test_list_bucket() -> Result<()> {
    let Some((ctx, signer, url)) = init_signing_test() else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let cred = load_static_credential()?;

    let mut req = Request::new(String::new());
    *req.method_mut() = Method::GET;
    *req.uri_mut() =
        http::Uri::from_str(&format!("{url}?list-type=2&delimiter=/&encoding-type=url"))?;

    let (status, _body) = send_signed_request(&ctx, &signer, req, &cred).await?;
    assert_eq!(StatusCode::OK, status);
    Ok(())
}
