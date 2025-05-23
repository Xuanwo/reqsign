use std::env;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use http::header::AUTHORIZATION;
use http::header::CONTENT_LENGTH;
use http::Request;
use http::StatusCode;
use log::debug;
use log::warn;
use percent_encoding::utf8_percent_encode;
use percent_encoding::NON_ALPHANUMERIC;
use reqsign_tencent_cos::Config;
use reqsign_tencent_cos::CredentialLoader;
use reqsign_tencent_cos::Signer;
use reqwest::Client;

fn init_signer() -> Option<(CredentialLoader, Signer)> {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenv::dotenv();
    if env::var("REQSIGN_TENCENT_COS_TEST").is_err()
        || env::var("REQSIGN_TENCENT_COS_TEST").unwrap() != "on"
    {
        return None;
    }

    let config = Config {
        secret_id: Some(
            env::var("REQSIGN_TENCENT_COS_ACCESS_KEY")
                .expect("env REQSIGN_TENCENT_COS_ACCESS_KEY must set"),
        ),
        secret_key: Some(
            env::var("REQSIGN_TENCENT_COS_SECRET_KEY")
                .expect("env REQSIGN_TENCENT_COS_SECRET_KEY must set"),
        ),
        ..Default::default()
    };
    let loader = CredentialLoader::new(reqwest::Client::new(), config);

    Some((loader, Signer::new()))
}

#[tokio::test]
async fn test_get_object() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_TENCENT_COS_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();
    let cred = loader.load().await?.unwrap();

    let url = &env::var("REQSIGN_TENCENT_COS_URL").expect("env REQSIGN_TENCENT_COS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))?;

    let (mut parts, body) = req.into_parts();
    signer
        .sign(&mut parts, &cred)
        .expect("sign request must success");
    let req = http::Request::from_parts(parts, body);

    debug!("signed request: {:?}", req.headers().get(AUTHORIZATION));

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must succeed");

    let status = resp.status();
    debug!("got response: {:?}", resp);
    debug!("got response content: {}", resp.text().await?);
    assert_eq!(StatusCode::NOT_FOUND, status);
    Ok(())
}

#[tokio::test]
async fn test_delete_objects() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_TENCENT_COS_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();
    let cred = loader.load().await?.unwrap();

    let url = &env::var("REQSIGN_TENCENT_COS_URL").expect("env REQSIGN_TENCENT_COS_URL must set");

    let content = r#"<Delete>
<Object>
 <Key>sample1.txt</Key>
 </Object>
 <Object>
   <Key>sample2.txt</Key>
 </Object>
 </Delete>"#;
    let mut req = Request::new(content);
    *req.method_mut() = http::Method::POST;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/?delete", url))?;
    req.headers_mut()
        .insert(CONTENT_LENGTH, content.len().to_string().parse().unwrap());
    req.headers_mut()
        .insert("CONTENT-MD5", "WOctCY1SS662e7ziElh4cw==".parse().unwrap());

    let (mut parts, body) = req.into_parts();
    signer
        .sign(&mut parts, &cred)
        .expect("sign request must success");
    let req = http::Request::from_parts(parts, body);

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must succeed");

    let status = resp.status();
    debug!("got response: {:?}", resp);
    debug!("got response content: {}", resp.text().await?);
    assert_eq!(StatusCode::OK, status);
    Ok(())
}

#[tokio::test]
async fn test_get_object_with_query_sign() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_TENCENT_COS_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();
    let cred = loader.load().await?.unwrap();

    let url = &env::var("REQSIGN_TENCENT_COS_URL").expect("env REQSIGN_TENCENT_COS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))?;

    let (mut parts, body) = req.into_parts();
    signer
        .sign_query(&mut parts, Duration::from_secs(3600), &cred)
        .expect("sign request must success");
    let req = http::Request::from_parts(parts, body);

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must succeed");

    let status = resp.status();
    debug!("got response: {:?}", resp);
    debug!("got response content: {}", resp.text().await?);
    assert_eq!(StatusCode::NOT_FOUND, status);
    Ok(())
}

#[tokio::test]
async fn test_head_object_with_special_characters() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_TENCENT_COS_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();
    let cred = loader.load().await?.unwrap();

    let url = &env::var("REQSIGN_TENCENT_COS_URL").expect("env REQSIGN_TENCENT_COS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::HEAD;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("not-exist-!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
    ))?;

    let (mut parts, body) = req.into_parts();
    signer
        .sign(&mut parts, &cred)
        .expect("sign request must success");
    let req = http::Request::from_parts(parts, body);

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
async fn test_put_object_with_special_characters() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_TENCENT_COS_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();
    let cred = loader.load().await?.unwrap();

    let url = &env::var("REQSIGN_TENCENT_COS_URL").expect("env REQSIGN_TENCENT_COS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::PUT;
    *req.uri_mut() = http::Uri::from_str(&format!(
        "{}/{}",
        url,
        utf8_percent_encode("put-!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
    ))?;
    req.headers_mut()
        .insert(CONTENT_LENGTH, "0".parse().unwrap());

    let (mut parts, body) = req.into_parts();
    signer
        .sign(&mut parts, &cred)
        .expect("sign request must success");
    let req = http::Request::from_parts(parts, body);

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must success");

    let status = resp.status();
    debug!("got response: {:?}", resp);
    debug!("got response content: {:?}", resp.text().await?);
    assert_eq!(StatusCode::OK, status);
    Ok(())
}

#[tokio::test]
async fn test_list_bucket() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_TENCENT_COS_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();
    let cred = loader.load().await?.unwrap();

    let url = &env::var("REQSIGN_TENCENT_COS_URL").expect("env REQSIGN_TENCENT_COS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() =
        http::Uri::from_str(&format!("{url}?list-type=2&delimiter=/&encoding-type=url"))?;

    let (mut parts, body) = req.into_parts();
    signer
        .sign(&mut parts, &cred)
        .expect("sign request must success");
    let req = http::Request::from_parts(parts, body);

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must success");

    let status = resp.status();
    debug!("got response: {:?}", resp);
    debug!("got response content: {}", resp.text().await?);
    assert_eq!(StatusCode::OK, status);
    Ok(())
}

#[tokio::test]
async fn test_list_bucket_with_upper_cases() -> Result<()> {
    let signer = init_signer();
    if signer.is_none() {
        warn!("REQSIGN_TENCENT_COS_TEST is not set, skipped");
        return Ok(());
    }
    let (loader, signer) = signer.unwrap();
    let cred = loader.load().await?.unwrap();

    let url = &env::var("REQSIGN_TENCENT_COS_URL").expect("env REQSIGN_TENCENT_COS_URL must set");

    let mut req = Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = http::Uri::from_str(&format!("{url}?prefix=stage/1712557668-ZgPY8Ql4"))?;

    let (mut parts, body) = req.into_parts();
    signer
        .sign(&mut parts, &cred)
        .expect("sign request must success");
    let req = http::Request::from_parts(parts, body);

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .await
        .expect("request must success");

    let status = resp.status();
    debug!("got response: {:?}", resp);
    debug!("got response content: {}", resp.text().await?);
    assert_eq!(StatusCode::OK, status);
    Ok(())
}
