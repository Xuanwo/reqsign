use super::{init_signing_test, load_static_credential, send_signed_request};
use anyhow::Result;
use http::{Method, Request, StatusCode};
use log::warn;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use std::str::FromStr;

#[tokio::test]
async fn test_head_object_with_special_characters() -> Result<()> {
    let Some((ctx, signer, url)) = init_signing_test() else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let cred = load_static_credential()?;

    let mut req = Request::new(String::new());
    *req.method_mut() = Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
    ))?;

    let (status, _body) = send_signed_request(&ctx, &signer, req, &cred).await?;
    assert_eq!(StatusCode::NOT_FOUND, status);
    Ok(())
}

#[tokio::test]
async fn test_head_object_with_encoded_characters() -> Result<()> {
    let Some((ctx, signer, url)) = init_signing_test() else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let cred = load_static_credential()?;

    let mut req = Request::new(String::new());
    *req.method_mut() = Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("test file with spaces.txt", NON_ALPHANUMERIC)
    ))?;

    let (status, _body) = send_signed_request(&ctx, &signer, req, &cred).await?;
    assert_eq!(StatusCode::NOT_FOUND, status);
    Ok(())
}

#[tokio::test]
async fn test_object_with_unicode_characters() -> Result<()> {
    let Some((ctx, signer, url)) = init_signing_test() else {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    };

    let cred = load_static_credential()?;

    let mut req = Request::new(String::new());
    *req.method_mut() = Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("文件名.txt", NON_ALPHANUMERIC)
    ))?;

    let (status, _body) = send_signed_request(&ctx, &signer, req, &cred).await?;
    assert_eq!(StatusCode::NOT_FOUND, status);
    Ok(())
}
