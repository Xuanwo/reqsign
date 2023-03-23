use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use reqsign::AliyunOssBuilder;

criterion_group!(benches, bench);
criterion_main!(benches);

pub fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("oss");

    group.bench_function("reqsign", |b| {
        let s = AliyunOssBuilder::default()
            .access_key_id("access_key_id")
            .access_key_secret("secret_access_key")
            .bucket("test")
            .build()
            .expect("signer must be valid");

        b.iter(|| {
            let mut req = http::Request::new("");
            *req.method_mut() = http::Method::GET;
            *req.uri_mut() = "http://127.0.0.1:9000/hello"
                .parse()
                .expect("url must be valid");
            req.headers_mut()
                .insert("1", "Hello, World!".parse().unwrap());
            req.headers_mut()
                .insert("2", "Hello, World!".parse().unwrap());
            req.headers_mut()
                .insert("3", "Hello, World!".parse().unwrap());
            req.headers_mut()
                .insert("4", "Hello, World!".parse().unwrap());
            req.headers_mut()
                .insert("5", "Hello, World!".parse().unwrap());

            s.sign(&mut req).expect("must success")
        })
    });

    group.finish();
}
