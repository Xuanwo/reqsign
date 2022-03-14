use anyhow::Result;
use http::header::HeaderName;
use http::{HeaderMap, Method};

pub trait SignableRequest {
    fn method(&self) -> &http::Method;
    fn path(&self) -> &str;
    fn authority(&self) -> &str;
    fn headers(&self) -> &http::HeaderMap;

    fn apply_header(&mut self, name: HeaderName, value: &str) -> Result<()>;
}

impl SignableRequest for reqwest::Request {
    fn method(&self) -> &Method {
        let this = self as &reqwest::Request;
        this.method()
    }

    fn path(&self) -> &str {
        let this = self as &reqwest::Request;
        this.url().path()
    }

    fn authority(&self) -> &str {
        let this = self as &reqwest::Request;
        this.url().host_str().expect("request uri must have host")
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
    fn method(&self) -> &Method {
        let this = self as &http::Request<T>;
        this.method()
    }

    fn path(&self) -> &str {
        let this = self as &http::Request<T>;
        this.uri().path()
    }

    fn authority(&self) -> &str {
        let this = self as &http::Request<T>;
        this.uri()
            .authority()
            .expect("request uri must have authority")
            .as_str()
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
