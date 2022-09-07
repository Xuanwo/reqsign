use anyhow::Result;
use http::{Request, StatusCode};
use log::{debug, warn};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use reqsign::services::aws::loader;
use reqsign::services::aws::loader::CredentialLoad;
use reqsign::services::aws::v4::Signer;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::str::FromStr;
use std::{env, fs};
use time::Duration;

fn init_signer() -> Option<Signer> {
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

    Some(builder.build().expect("signer must be valid"))
}

#[test]
fn test_signer_with_web_loader() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    dotenv::from_filename(".env").ok();

    if env::var("REQSIGN_AWS_V4_TEST").is_err() || env::var("REQSIGN_AWS_V4_TEST").unwrap() != "on"
    {
        return Ok(());
    }

    let role_arn = env::var("REQSIGN_AWS_ROLE_ARN").expect("REQSIGN_AWS_ROLE_ARN not exist");
    let idp_url = env::var("REQSIGN_AWS_IDP_URL").expect("REQSIGN_AWS_IDP_URL not exist");
    let idp_content =
        base64::decode(env::var("REQSIGN_AWS_IDP_BODY").expect("REQSIGN_AWS_IDP_BODY not exist"))?;

    let mut req = Request::new(idp_content);
    *req.method_mut() = http::Method::POST;
    *req.uri_mut() = http::Uri::from_str(&idp_url)?;
    req.headers_mut()
        .insert(http::header::CONTENT_TYPE, "application/json".parse()?);

    #[derive(Deserialize)]
    struct Token {
        access_token: String,
    }
    let token = Client::new()
        .execute(req.try_into()?)?
        .json::<Token>()?
        .access_token;

    let file_path = format!(
        "{}/testdata/services/aws/web_identity_token_file",
        env::current_dir()
            .expect("current_dir must exist")
            .to_string_lossy()
    );
    fs::write(&file_path, token)?;

    temp_env::with_vars(
        vec![
            ("AWS_ROLE_ARN", Some(&role_arn)),
            ("AWS_WEB_IDENTITY_TOKEN_FILE", Some(&file_path)),
        ],
        || {
            let l = loader::WebIdentityTokenLoader {};
            let x = l
                .load_credential()
                .expect("load_credential must success")
                .expect("credential must be valid");

            assert!(x.is_valid());
        },
    );

    Ok(())
}

#[test]
fn test_head_object() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))?;

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
fn test_put_object_with_query() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("Hello, World!");
    *req.method_mut() = http::Method::PUT;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "put_object_test"))?;

    signer
        .sign_query(&mut req, Duration::hours(1))
        .expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .expect("request must succeed");

    let status = resp.status();
    debug!(
        "got response: {:?}",
        String::from_utf8(resp.bytes()?.to_vec())?
    );
    assert_eq!(StatusCode::OK, status);
    Ok(())
}

#[test]
fn test_get_object_with_query() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))?;

    signer
        .sign_query(&mut req, Duration::hours(1))
        .expect("sign request must success");

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
fn test_head_object_with_special_characters() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "!@#$%^&*()_+-=;:'><,/?.txt"))?;

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
fn test_head_object_with_encoded_characters() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
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
fn test_list_bucket() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_AWS_V4_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_AWS_V4_URL").expect("env REQSIGN_AWS_V4_URL must set");

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

    debug!("got response: {:?}", resp);
    assert_eq!(StatusCode::OK, resp.status());
    Ok(())
}
