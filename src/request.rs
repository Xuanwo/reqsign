use anyhow::Result;
use http::header::HeaderName;
use http::{HeaderMap, Method};

pub trait SignableRequest {
    // Read operations.
    fn method(&self) -> &http::Method;
    fn path(&self) -> &str;
    fn query(&self) -> Option<&str>;
    fn host(&self) -> &str;
    fn port(&self) -> Option<usize>;
    fn headers(&self) -> &http::HeaderMap;

    fn host_port(&self) -> String {
        if let Some(port) = self.port() {
            format!("{}:{}", self.host(), port)
        } else {
            self.host().to_string()
        }
    }

    // Write operations.
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

    fn query(&self) -> Option<&str> {
        let this = self as &reqwest::Request;
        this.url().query()
    }

    fn host(&self) -> &str {
        let this = self as &reqwest::Request;
        this.url().host_str().expect("request uri must have host")
    }

    fn port(&self) -> Option<usize> {
        let this = self as &reqwest::Request;
        this.url().port().map(|v| v as usize)
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

    fn query(&self) -> Option<&str> {
        let this = self as &http::Request<T>;
        this.uri().query()
    }

    fn host(&self) -> &str {
        let this = self as &http::Request<T>;
        this.uri().host().expect("request uri must have host")
    }

    fn port(&self) -> Option<usize> {
        let this = self as &http::Request<T>;
        this.uri().port_u16().map(|v| v as usize)
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
