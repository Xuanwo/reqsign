use std::time::SystemTime;

use aws_sigv4::http_request::PayloadChecksumKind;
use aws_sigv4::http_request::PercentEncodingMode;
use aws_sigv4::http_request::SignableBody;
use aws_sigv4::http_request::SignableRequest;
use aws_sigv4::http_request::SigningSettings;
use aws_sigv4::SigningParams;
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

        let sp = SigningParams::builder()
            .access_key("access_key_id")
            .secret_key("secret_access_key")
            .region("test")
            .service_name("s3")
            .time(SystemTime::now())
            .settings(ss)
            .build()
            .expect("signing params must be valid");

        b.iter(|| {
            let mut req = http::Request::new("");
            *req.method_mut() = http::Method::GET;
            *req.uri_mut() = "http://127.0.0.1:9000/hello"
                .parse()
                .expect("url must be valid");

            let _ = aws_sigv4::http_request::sign(
                SignableRequest::new(
                    req.method(),
                    req.uri(),
                    req.headers(),
                    SignableBody::UnsignedPayload,
                ),
                &sp,
            )
            .expect("signing must succeed");
        })
    });

    group.finish();
}
