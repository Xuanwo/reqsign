use std::env;
use std::process::exit;

use anyhow::Result;
use log::debug;
use reqsign::GoogleBuilder;
use reqwest::blocking::Client;

fn main() -> Result<()> {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "debug");
    }
    env_logger::init();

    // input args is url.
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        println!("url is missing");
        exit(1)
    }

    let signer = GoogleBuilder::default().scope("read-only").build()?;
    let mut builder = http::Request::builder();
    builder = builder.method(http::Method::GET);
    builder = builder.uri(&args[1]);
    let mut req = builder.body("")?;

    signer.sign(&mut req).expect("sign request must success");

    debug!("signed request: {:?}", req);

    let client = Client::new();
    let resp = client
        .execute(req.try_into()?)
        .expect("request must succeed");

    debug!("got response: {:?}", resp);

    Ok(())
}
