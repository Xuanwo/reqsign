//! Provide common request trait for signing.

use std::mem;
use std::str::FromStr;

use anyhow::Result;
use http::header::HeaderName;
use http::uri::PathAndQuery;
use http::HeaderMap;
use http::HeaderValue;
use http::Method;
use http::Uri;

/// Trait for all signable request.
///
/// Any request type that implement this trait can be used by signers as input.
/// Different requests may have different uri implementations, so we return detailed
/// uri components instead of a complete struct.
pub trait SignableRequest {
    /// Get method of request.
    fn method(&self) -> Method;
    /// Get header of request.
    fn headers(&self) -> HeaderMap;

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
    fn insert_header(&mut self, name: HeaderName, value: HeaderValue) -> Result<()>;

    /// Set new query into url.
    ///
    /// This function SHOULD append full query.
    fn set_query(&mut self, query: &str) -> Result<()>;
}

/// Implement `SignableRequest` for [`http::Request`]
impl<T> SignableRequest for http::Request<T> {
    fn method(&self) -> Method {
        let this = self as &http::Request<T>;
        this.method().clone()
    }

    fn headers(&self) -> HeaderMap {
        let this = self as &http::Request<T>;
        this.headers().clone()
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

    fn insert_header(&mut self, name: HeaderName, value: HeaderValue) -> Result<()> {
        self.headers_mut().insert(name, value);

        Ok(())
    }

    fn set_query(&mut self, query: &str) -> Result<()> {
        let this = self as &mut http::Request<T>;

        let mut parts = mem::take(this.uri_mut()).into_parts();

        parts.path_and_query = {
            let mut pq = parts
                .path_and_query
                .unwrap_or_else(|| PathAndQuery::from_static("/"));

            pq = PathAndQuery::from_str(&format!("{}?{}", pq.path(), query))?;

            Some(pq)
        };

        *this.uri_mut() = Uri::from_parts(parts)?;

        Ok(())
    }
}

/// Implement `SignableRequest` for [`reqwest::Request`]
#[cfg(feature = "reqwest_request")]
impl SignableRequest for reqwest::Request {
    fn method(&self) -> Method {
        let this = self as &reqwest::Request;
        this.method().clone()
    }

    fn headers(&self) -> HeaderMap {
        let this = self as &reqwest::Request;
        this.headers().clone()
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

    fn insert_header(&mut self, name: HeaderName, value: HeaderValue) -> Result<()> {
        self.headers_mut().insert(name, value);

        Ok(())
    }

    fn set_query(&mut self, query: &str) -> Result<()> {
        let this = self as &mut reqwest::Request;
        this.url_mut().set_query(Some(query));

        Ok(())
    }
}

/// Implement `SignableRequest` for [`reqwest::blocking::Request`]
#[cfg(feature = "reqwest_blocking_request")]
impl SignableRequest for reqwest::blocking::Request {
    fn method(&self) -> Method {
        let this = self as &reqwest::blocking::Request;
        this.method().clone()
    }

    fn headers(&self) -> HeaderMap {
        let this = self as &reqwest::blocking::Request;
        this.headers().clone()
    }

    fn path(&self) -> &str {
        let this = self as &reqwest::blocking::Request;
        this.url().path()
    }

    fn query(&self) -> Option<&str> {
        let this = self as &reqwest::blocking::Request;
        this.url().query()
    }

    fn host(&self) -> &str {
        let this = self as &reqwest::blocking::Request;
        this.url().host_str().expect("request uri must have host")
    }

    fn port(&self) -> Option<usize> {
        let this = self as &reqwest::blocking::Request;
        this.url().port().map(|v| v as usize)
    }

    fn insert_header(&mut self, name: HeaderName, value: HeaderValue) -> Result<()> {
        self.headers_mut().insert(name, value);

        Ok(())
    }

    fn set_query(&mut self, query: &str) -> Result<()> {
        let this = self as &mut reqwest::blocking::Request;
        this.url_mut().set_query(Some(query));

        Ok(())
    }
}

/// Implement `SignableRequest` for [`http_types::Request`]
#[cfg(feature = "http_types_request")]
impl SignableRequest for http_types::Request {
    fn method(&self) -> Method {
        let this = self as &http_types::Request;
        match this.method() {
            http_types::Method::Connect => Method::CONNECT,
            http_types::Method::Delete => Method::DELETE,
            http_types::Method::Get => Method::GET,
            http_types::Method::Head => Method::HEAD,
            http_types::Method::Options => Method::OPTIONS,
            http_types::Method::Patch => Method::PATCH,
            http_types::Method::Post => Method::POST,
            http_types::Method::Put => Method::PUT,
            http_types::Method::Trace => Method::TRACE,
            v => Method::from_str(v.as_ref()).expect("must be valid http method"),
        }
    }

    fn headers(&self) -> HeaderMap {
        let this = self as &http_types::Request;
        let mut map = HeaderMap::new();
        for name in this.header_names() {
            map.insert(
                HeaderName::from_str(name.as_str()).expect("must be valid header name"),
                HeaderValue::from_str(this.header(name).expect("header value must exist").as_str())
                    .expect("must be valid header value"),
            );
        }

        map
    }

    fn path(&self) -> &str {
        let this = self as &http_types::Request;
        this.url().path()
    }

    fn query(&self) -> Option<&str> {
        let this = self as &http_types::Request;
        this.url().query()
    }

    fn host(&self) -> &str {
        let this = self as &http_types::Request;
        this.url().host_str().expect("request url must have host")
    }

    fn port(&self) -> Option<usize> {
        let this = self as &http_types::Request;
        this.url().port().map(|v| v as usize)
    }

    fn insert_header(&mut self, name: HeaderName, value: HeaderValue) -> Result<()> {
        self.insert_header(
            name.as_str(),
            value
                .to_str()
                .expect("header value must be valid")
                .parse::<http_types::headers::HeaderValue>()
                .expect("header value must be valid"),
        );

        Ok(())
    }

    fn set_query(&mut self, query: &str) -> Result<()> {
        let this = self as &mut http_types::Request;
        this.url_mut().set_query(Some(query));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[test]
    fn test_http_request_apply_query() -> Result<()> {
        let cases = vec![
            (
                "empty query",
                "http://127.0.0.1/",
                "a=b&c=d",
                "http://127.0.0.1/?a=b&c=d",
            ),
            (
                "exist query without =",
                "http://127.0.0.1/?a",
                "x=y&c=d",
                "http://127.0.0.1/?x=y&c=d",
            ),
            (
                "exist query",
                "http://127.0.0.1/?a=p",
                "x=y&c=d",
                "http://127.0.0.1/?x=y&c=d",
            ),
            (
                "with path",
                "http://127.0.0.1/abc",
                "a=b&c=d",
                "http://127.0.0.1/abc?a=b&c=d",
            ),
        ];

        for (name, input_uri, input_query, expected) in cases {
            let mut req = http::Request::get(Uri::from_str(input_uri)?).body(())?;

            req.set_query(input_query)?;

            assert_eq!(req.uri().to_string(), expected, "{name}")
        }

        Ok(())
    }
}
