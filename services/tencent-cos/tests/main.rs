use std::env;
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
use reqsign_core::{Context, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqsign_tencent_cos::{Config, Credential, DefaultCredentialProvider, RequestSigner};

async fn init_signer() -> Option<Signer<Credential>> {
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
    let loader = DefaultCredentialProvider::new(config);
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
    let signer = Signer::new(ctx, loader, RequestSigner::new());

    Some(signer)
}

#[tokio::test]
async fn test_get_object() -> Result<()> {
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_TENCENT_COS_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_TENCENT_COS_URL").expect("env REQSIGN_TENCENT_COS_URL must set");

    let req = Request::builder()
        .method(http::Method::GET)
        .uri(format!("{}/{}", url, "not_exist_file"))
        .body("")?;

    let (mut parts, body) = req.into_parts();
    signer.sign(&mut parts, None).await?;
    let req = Request::from_parts(parts, body);

    debug!("signed request: {:?}", req.headers().get(AUTHORIZATION));

    let client = reqwest::Client::new();
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
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_TENCENT_COS_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_TENCENT_COS_URL").expect("env REQSIGN_TENCENT_COS_URL must set");

    let content = r#"<Delete>
<Object>
 <Key>sample1.txt</Key>
 </Object>
 <Object>
   <Key>sample2.txt</Key>
 </Object>
 </Delete>"#;
    let req = Request::builder()
        .method(http::Method::POST)
        .uri(format!("{}/?delete", url))
        .header(CONTENT_LENGTH, content.len().to_string())
        .header("CONTENT-MD5", "WOctCY1SS662e7ziElh4cw==")
        .body(content)?;

    let (mut parts, body) = req.into_parts();
    signer.sign(&mut parts, None).await?;
    let req = Request::from_parts(parts, body);

    debug!("signed request: {:?}", req);

    let client = reqwest::Client::new();
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
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_TENCENT_COS_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_TENCENT_COS_URL").expect("env REQSIGN_TENCENT_COS_URL must set");

    let req = Request::builder()
        .method(http::Method::GET)
        .uri(format!("{}/{}", url, "not_exist_file"))
        .body("")?;

    let (mut parts, body) = req.into_parts();
    signer
        .sign(&mut parts, Some(Duration::from_secs(3600)))
        .await?;
    let req = Request::from_parts(parts, body);

    debug!("signed request: {:?}", req);

    let client = reqwest::Client::new();
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
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_TENCENT_COS_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_TENCENT_COS_URL").expect("env REQSIGN_TENCENT_COS_URL must set");

    let req = Request::builder()
        .method(http::Method::HEAD)
        .uri(format!(
            "{}/{}",
            url,
            utf8_percent_encode("not-exist-!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
        ))
        .body("")?;

    let (mut parts, body) = req.into_parts();
    signer.sign(&mut parts, None).await?;
    let req = Request::from_parts(parts, body);

    debug!("signed request: {:?}", req);

    let client = reqwest::Client::new();
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
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_TENCENT_COS_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_TENCENT_COS_URL").expect("env REQSIGN_TENCENT_COS_URL must set");

    let req = Request::builder()
        .method(http::Method::PUT)
        .uri(format!(
            "{}/{}",
            url,
            utf8_percent_encode("put-!@#$%^&*()_+-=;:'><,/?.txt", NON_ALPHANUMERIC)
        ))
        .header(CONTENT_LENGTH, "0")
        .body("")?;

    let (mut parts, body) = req.into_parts();
    signer.sign(&mut parts, None).await?;
    let req = Request::from_parts(parts, body);

    debug!("signed request: {:?}", req);

    let client = reqwest::Client::new();
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
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_TENCENT_COS_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_TENCENT_COS_URL").expect("env REQSIGN_TENCENT_COS_URL must set");

    let req = Request::builder()
        .method(http::Method::GET)
        .uri(format!("{url}?list-type=2&delimiter=/&encoding-type=url"))
        .body("")?;

    let (mut parts, body) = req.into_parts();
    signer.sign(&mut parts, None).await?;
    let req = Request::from_parts(parts, body);

    debug!("signed request: {:?}", req);

    let client = reqwest::Client::new();
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
    let signer = init_signer().await;
    if signer.is_none() {
        warn!("REQSIGN_TENCENT_COS_TEST is not set, skipped");
        return Ok(());
    }
    let signer = signer.unwrap();

    let url = &env::var("REQSIGN_TENCENT_COS_URL").expect("env REQSIGN_TENCENT_COS_URL must set");

    let req = Request::builder()
        .method(http::Method::GET)
        .uri(format!("{url}?prefix=stage/1712557668-ZgPY8Ql4"))
        .body("")?;

    let (mut parts, body) = req.into_parts();
    signer.sign(&mut parts, None).await?;
    let req = Request::from_parts(parts, body);

    debug!("signed request: {:?}", req);

    let client = reqwest::Client::new();
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
