use std::str::FromStr;

use anyhow::Result;
use http::header::HeaderName;
use http::{HeaderMap, Method, Uri};

pub trait SignableRequest {
    fn method(&self) -> http::Method;
    fn uri(&self) -> http::uri::Uri;
    fn headers(&self) -> &http::HeaderMap;

    fn apply_header(&mut self, name: HeaderName, value: &str) -> Result<()>;
}

impl SignableRequest for reqwest::Request {
    fn method(&self) -> Method {
        let this = self as &reqwest::Request;
        this.method().clone()
    }

    fn uri(&self) -> Uri {
        Uri::from_str(self.url().as_str()).expect("request url invalid")
    }

    fn headers(&self) -> &HeaderMap {
        let this = self as &reqwest::Request;
        this.headers()
    }

    fn apply_header(&mut self, name: HeaderName, value: &str) -> Result<()> {
        self.headers_mut().insert(name, value.parse()?);

        Ok(())
    }
}

impl<T> SignableRequest for http::Request<T> {
    fn method(&self) -> Method {
        let this = self as &http::Request<T>;
        this.method().clone()
    }

    fn uri(&self) -> Uri {
        let this = self as &http::Request<T>;
        this.uri().clone()
    }

    fn headers(&self) -> &HeaderMap {
        let this = self as &http::Request<T>;
        this.headers()
    }

    fn apply_header(&mut self, name: HeaderName, value: &str) -> Result<()> {
        self.headers_mut().insert(name, value.parse()?);

        Ok(())
    }
}
