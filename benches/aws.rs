use std::time::SystemTime;

use aws_sigv4::http_request::PayloadChecksumKind;
use aws_sigv4::http_request::PercentEncodingMode;
use aws_sigv4::http_request::SignableBody;
use aws_sigv4::http_request::SignableRequest;
use aws_sigv4::http_request::SigningSettings;
use aws_sigv4::sign::v4::SigningParams;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use reqsign::AwsCredential;
use reqsign::AwsV4Signer;

criterion_group!(benches, bench);
criterion_main!(benches);

pub fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("aws_v4");

    group.bench_function("reqsign", |b| {
        let cred = AwsCredential {
            access_key_id: "access_key_id".to_string(),
            secret_access_key: "secret_access_key".to_string(),
            ..Default::default()
        };

        let s = AwsV4Signer::new("s3", "test");

        b.iter(|| {
            let mut req = http::Request::new("");
            *req.method_mut() = http::Method::GET;
            *req.uri_mut() = "http://127.0.0.1:9000/hello"
                .parse()
                .expect("url must be valid");

            s.sign(&mut req, &cred).expect("must success")
        })
    });

    group.bench_function("aws_sigv4", |b| {
        let mut ss = SigningSettings::default();
        ss.percent_encoding_mode = PercentEncodingMode::Single;
        ss.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

        let credentials = aws_credential_types::Credentials::new(
            "access_key_id".to_string(),
            "secret_access_key".to_string(),
            None,
            None,
            "test",
        )
        .into();

        let sp = SigningParams::builder()
            .identity(&credentials)
            .region("test")
            .name("s3")
            .time(SystemTime::now())
            .settings(ss)
            .build()
            .expect("signing params must be valid")
            .into();

        let mut req = http::Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "http://127.0.0.1:9000/hello"
            .parse()
            .expect("url must be valid");
        let method = req.method().as_str();
        let uri = req.uri().to_string();
        let headers = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str(), std::str::from_utf8(v.as_bytes()).unwrap()))
            .collect::<Vec<_>>();

        b.iter(|| {
            let _ = aws_sigv4::http_request::sign(
                SignableRequest::new(
                    method,
                    uri.as_str(),
                    headers.clone().into_iter(),
                    SignableBody::UnsignedPayload,
                )
                .unwrap(),
                &sp,
            )
            .expect("signing must succeed");
        })
    });

    group.finish();
}
