//! Provide common request trait for signing.

use anyhow::Result;
use http::header::HeaderName;
use http::{HeaderMap, HeaderValue, Method};

/// Trait for all signable request.
///
/// Any request type that implement this trait can be used by signers as input.
/// Different requests may have different uri implementations, so we return detailed
/// uri components instead of a complete struct.
pub trait SignableRequest {
    /// Get method of request.
    fn method(&self) -> &http::Method;
    /// Get header of request.
    fn headers(&self) -> &http::HeaderMap;

    /// Get path of request.
    ///
    /// ```text
    /// abc://username:password@example.com:123/path/data?key=value&key2=value2#fragid1
    ///                                         |-------|
    ///                                             |
    ///                                           path
    /// ```
    fn path(&self) -> &str;
    /// Get query of request.
    ///
    ///```text
    /// abc://username:password@example.com:123/path/data?key=value&key2=value2#fragid1
    ///                                                   +---------+---------+
    ///                                                             |
    ///                                                           query
    /// ```
    fn query(&self) -> Option<&str>;
    /// Get host of request
    ///
    ///```text
    /// abc://username:password@example.com:123/path/data?key=value&key2=value2#fragid1
    ///                         +---------+
    ///                             |
    ///                            host
    /// ```
    fn host(&self) -> &str;
    /// Get port of request
    ///
    ///```text
    /// abc://username:password@example.com:123/path/data?key=value&key2=value2#fragid1
    ///                                     +-+
    ///                                      |
    ///                                     port
    /// ```
    fn port(&self) -> Option<usize>;

    /// Construct host and port.
    ///
    ///```text
    /// abc://username:password@example.com:123/path/data?key=value&key2=value2#fragid1
    ///                         +-------------+
    ///                                |
    ///                            host_port
    /// ```
    fn host_port(&self) -> String {
        if let Some(port) = self.port() {
            format!("{}:{}", self.host(), port)
        } else {
            self.host().to_string()
        }
    }

    /// Insert new headers into header map.
    fn apply_header(&mut self, name: HeaderName, value: &str) -> Result<()>;
}

/// Implement `SignableRequest` for `reqwest::Request`
impl SignableRequest for reqwest::Request {
    fn method(&self) -> &Method {
        let this = self as &reqwest::Request;
        this.method()
    }

    fn headers(&self) -> &HeaderMap {
        let this = self as &reqwest::Request;
        this.headers()
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

    fn apply_header(&mut self, name: HeaderName, value: &str) -> Result<()> {
        let mut value: HeaderValue = value.parse()?;
        value.set_sensitive(true);
        self.headers_mut().insert(name, value);

        Ok(())
    }
}

/// Implement `SignableRequest` for `http::Request`
impl<T> SignableRequest for http::Request<T> {
    fn method(&self) -> &Method {
        let this = self as &http::Request<T>;
        this.method()
    }

    fn headers(&self) -> &HeaderMap {
        let this = self as &http::Request<T>;
        this.headers()
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

    fn apply_header(&mut self, name: HeaderName, value: &str) -> Result<()> {
        let mut value: HeaderValue = value.parse()?;
        value.set_sensitive(true);
        self.headers_mut().insert(name, value);

        Ok(())
    }
}
