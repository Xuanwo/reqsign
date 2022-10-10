use std::env;
use std::str::FromStr;

use anyhow::Result;
use http::Request;
use http::StatusCode;
use log::debug;
use log::warn;
use percent_encoding::utf8_percent_encode;
use percent_encoding::NON_ALPHANUMERIC;
use reqsign::aliyun::loader;
use reqsign::aliyun::oss::Builder;
use reqsign::aliyun::oss::Signer;
use reqsign::credential::CredentialLoad;
use reqwest::blocking::Client;
use serde::Deserialize;
use ureq::Agent;

fn init_signer() -> Option<Signer> {
    let _ = env_logger::builder().is_test(true).try_init();

    dotenv::from_filename(".env").ok();

    if env::var("REQSIGN_ALIYUN_OSS_TEST").is_err()
        || env::var("REQSIGN_ALIYUN_OSS_TEST").unwrap() != "on"
    {
        return None;
    }

    let mut builder = Builder::default();
    builder.bucket(
        &env::var("REQSIGN_ALIYUN_OSS_BUCKET").expect("env REQSIGN_ALIYUN_OSS_BUCKET must set"),
    );
    builder.access_key_id(
        &env::var("REQSIGN_ALIYUN_OSS_ACCESS_KEY")
            .expect("env REQSIGN_ALIYUN_OSS_ACCESS_KEY must set"),
    );
    builder.access_key_secret(
        &env::var("REQSIGN_ALIYUN_OSS_SECRET_KEY")
            .expect("env REQSIGN_ALIYUN_OSS_SECRET_KEY must set"),
    );

    Some(builder.build().expect("signer must be valid"))
}

#[test]
fn test_signer_with_oidc() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    dotenv::from_filename(".env").ok();

    if env::var("REQSIGN_ALIYUN_OSS_TEST").is_err()
        || env::var("REQSIGN_ALIYUN_OSS_TEST").unwrap() != "on"
    {
        return Ok(());
    }

    let provider_arn =
        env::var("REQSIGN_ALIYUN_PROVIDER_ARN").expect("REQSIGN_ALIYUN_PROVIDER_ARN not exist");
    let role_arn = env::var("REQSIGN_ALIYUN_ROLE_ARN").expect("REQSIGN_ALIYUN_ROLE_ARN not exist");
    let idp_url = env::var("REQSIGN_ALIYUN_IDP_URL").expect("REQSIGN_ALIYUN_IDP_URL not exist");
    let idp_content =
        env::var("REQSIGN_ALIYUN_IDP_BODY").expect("REQSIGN_ALIYUN_IDP_BODY not exist");

    let mut req = Request::new(idp_content);
    *req.method_mut() = http::Method::POST;
    *req.uri_mut() = http::Uri::from_str(&idp_url)?;
    req.headers_mut().insert(
        http::header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse()?,
    );

    #[derive(Deserialize)]
    struct Token {
        id_token: String,
    }
    let token = Client::new()
        .execute(req.try_into()?)?
        .json::<Token>()?
        .id_token;

    let l = loader::OidcTokenLoader::new(Agent::new(), &provider_arn, &role_arn, &token);
    let x = l
        .load_credential()
        .expect("load_credential must success")
        .expect("credential must be valid");

    assert!(x.is_valid());

    Ok(())
}

#[test]
fn test_get_object() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_ALIYUN_OSS_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_ALIYUN_OSS_URL").expect("env REQSIGN_ALIYUN_OSS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))?;

    signer.sign(&mut req).expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .expect("request must succeed");

    let status = resp.status();
    debug!("got response: {:?}", resp);
    debug!("got response content: {}", resp.text()?);
    assert_eq!(StatusCode::NOT_FOUND, status);
    Ok(())
}

#[test]
fn test_head_object_with_special_characters() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_ALIYUN_OSS_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_ALIYUN_OSS_URL").expect("env REQSIGN_ALIYUN_OSS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("not-exist-!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
    ))?;

    signer.sign(&mut req).expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .expect("request must success");

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::NOT_FOUND, resp.status());
    Ok(())
}

#[test]
fn test_put_object_with_special_characters() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_ALIYUN_OSS_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_ALIYUN_OSS_URL").expect("env REQSIGN_ALIYUN_OSS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::PUT;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("put-!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
    ))?;

    signer.sign(&mut req).expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .expect("request must success");

    let status = resp.status();
    debug!("got response: {:?}", resp);
    debug!("got response content: {:?}", resp.text()?);
    assert_eq!(StatusCode::OK, status);
    Ok(())
}

#[test]
fn test_list_bucket() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_ALIYUN_OSS_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_ALIYUN_OSS_URL").expect("env REQSIGN_ALIYUN_OSS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}?list-type=2&delimiter=/&encoding-type=url",
        url
    ))?;

    signer.sign(&mut req).expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .expect("request must success");

    let status = resp.status();
    debug!("got response: {:?}", resp);
    debug!("got response content: {}", resp.text()?);
    assert_eq!(StatusCode::OK, status);
    Ok(())
}

#[test]
fn test_list_bucket_with_invalid_token() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_ALIYUN_OSS_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_ALIYUN_OSS_URL").expect("env REQSIGN_ALIYUN_OSS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}?list-type=2&delimiter=/&encoding-type=url&continuation-token={}",
        url,
        utf8_percent_encode("hello.txt", NON_ALPHANUMERIC)
    ))?;

    signer.sign(&mut req).expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .expect("request must success");

    let status = resp.status();
    debug!("got response: {:?}", resp);
    debug!("got response content: {}", resp.text()?);
    assert_eq!(StatusCode::BAD_REQUEST, status);
    Ok(())
}
