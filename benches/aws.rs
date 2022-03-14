use std::str::FromStr;
use std::time::SystemTime;

use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
};
use aws_sigv4::SigningParams;
use criterion::criterion_main;
use criterion::{criterion_group, Criterion};
use reqwest::Url;

use reqsign::services::aws::v4::Signer;

criterion_group!(benches, bench);
criterion_main!(benches);

pub fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("aws_v4");

    group.bench_function("reqsign", |b| {
        let s = Signer::builder()
            .access_key("access_key_id")
            .secret_key("secret_access_key")
            .service("s3")
            .region("test")
            .build();

        b.iter(|| {
            let mut req = reqwest::Request::new(
                http::Method::GET,
                Url::from_str("http://127.0.0.1:9900/hello").expect("must success"),
            );
            s.sign(&mut req).expect("must success")
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
