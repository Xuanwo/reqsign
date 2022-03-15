use std::time::SystemTime;

use anyhow::Result;
use aws_sigv4;
use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
};
use aws_sigv4::SigningParams;

use crate::services::aws::v4::Signer;
use crate::time::{PrimitiveDateTime, ISO8601};

fn test_time() -> SystemTime {
    PrimitiveDateTime::parse("20220101T120000Z", ISO8601)
        .expect("test time must be valid")
        .assume_utc()
        .into()
}

#[tokio::test]
async fn test_get_object() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut req = http::Request::new("");
    *req.method_mut() = http::Method::GET;
    *req.uri_mut() = "http://127.0.0.1:9000/hello"
        .parse()
        .expect("url must be valid");

    let mut ss = SigningSettings::default();
    ss.percent_encoding_mode = PercentEncodingMode::Single;
    ss.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

    let sp = SigningParams::builder()
        .access_key("access_key_id")
        .secret_key("secret_access_key")
        .region("test")
        .service_name("s3")
        .time(test_time())
        .settings(ss)
        .build()
        .expect("signing params must be valid");

    let output = aws_sigv4::http_request::sign(
        SignableRequest::new(
            req.method(),
            req.uri(),
            req.headers(),
            SignableBody::UnsignedPayload,
        ),
        &sp,
    )
    .expect("signing must succeed");
    let (_, expect) = output.into_parts();

    let signer = Signer::builder()
        .access_key("access_key_id")
        .secret_key("secret_access_key")
        .region("test")
        .service("s3")
        .time(test_time())
        .build()
        .await?;

    let actual = signer.calculate(&req).await?;

    assert_eq!(expect, actual.signature());
    Ok(())
}
