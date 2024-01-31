use std::borrow::Cow;
use std::time::Duration;

use anyhow::Result;
use http::header::HeaderName;
use http::uri::Authority;
use http::uri::Scheme;
use http::HeaderMap;
use http::HeaderValue;
use http::Method;

pub struct SigningContext {
    pub method: Method,
    pub scheme: Scheme,
    pub authority: Authority,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: HeaderMap,
}

impl SigningContext {
    pub fn path_percent_decoded(&self) -> Cow<str> {
        percent_encoding::percent_decode_str(&self.path).decode_utf8_lossy()
    }

    #[inline]
    pub fn query_size(&self) -> usize {
        self.query
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>()
    }

    /// Push a new query pair into query list.
    #[inline]
    pub fn query_push(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.query.push((key.into(), value.into()));
    }

    /// Push a query string into query list.
    #[inline]
    pub fn query_append(&mut self, query: &str) {
        self.query.push((query.to_string(), "".to_string()));
    }

    pub fn query_to_vec_with_filter(&self, filter: impl Fn(&str) -> bool) -> Vec<(String, String)> {
        self.query
            .iter()
            // Filter all queries
            .filter(|(k, _)| filter(k))
            // Clone all queries
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Convert sorted query to string.
    ///
    /// ```shell
    /// [(a, b), (c, d)] => "a:b\nc:d"
    /// ```
    pub fn query_to_string(mut query: Vec<(String, String)>, sep: &str, join: &str) -> String {
        let mut s = String::with_capacity(16);

        // Sort via header name.
        query.sort();

        for (idx, (k, v)) in query.into_iter().enumerate() {
            if idx != 0 {
                s.push_str(join);
            }

            s.push_str(&k);
            if !v.is_empty() {
                s.push_str(sep);
                s.push_str(&v);
            }
        }

        s
    }

    /// Convert sorted query to percent decoded string.
    ///
    /// ```shell
    /// [(a, b), (c, d)] => "a:b\nc:d"
    /// ```
    pub fn query_to_percent_decoded_string(
        mut query: Vec<(String, String)>,
        sep: &str,
        join: &str,
    ) -> String {
        let mut s = String::with_capacity(16);

        // Sort via header name.
        query.sort();

        for (idx, (k, v)) in query.into_iter().enumerate() {
            if idx != 0 {
                s.push_str(join);
            }

            s.push_str(&k);
            if !v.is_empty() {
                s.push_str(sep);
                s.push_str(&percent_encoding::percent_decode_str(&v).decode_utf8_lossy());
            }
        }

        s
    }

    #[inline]
    pub fn header_get_or_default(&self, key: &HeaderName) -> Result<&str> {
        match self.headers.get(key) {
            Some(v) => Ok(v.to_str()?),
            None => Ok(""),
        }
    }

    pub fn header_value_normalize(v: &mut HeaderValue) {
        let bs = v.as_bytes();

        let starting_index = bs.iter().position(|b| *b != b' ').unwrap_or(0);
        let ending_offset = bs.iter().rev().position(|b| *b != b' ').unwrap_or(0);
        let ending_index = bs.len() - ending_offset;

        // This can't fail because we started with a valid HeaderValue and then only trimmed spaces
        *v = HeaderValue::from_bytes(&bs[starting_index..ending_index])
            .expect("invalid header value")
    }

    pub fn header_name_to_vec_sorted(&self) -> Vec<&str> {
        let mut h = self
            .headers
            .keys()
            .map(|k| k.as_str())
            .collect::<Vec<&str>>();
        h.sort_unstable();

        h
    }

    pub fn header_to_vec_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
        self.headers
            .iter()
            // Filter all header that starts with prefix
            .filter(|(k, _)| k.as_str().starts_with(prefix))
            // Convert all header name to lowercase
            .map(|(k, v)| {
                (
                    k.as_str().to_lowercase(),
                    v.to_str().expect("must be valid header").to_string(),
                )
            })
            .collect()
    }

    /// Convert sorted headers to string.
    ///
    /// ```shell
    /// [(a, b), (c, d)] => "a:b\nc:d"
    /// ```
    pub fn header_to_string(mut headers: Vec<(String, String)>, sep: &str, join: &str) -> String {
        let mut s = String::with_capacity(16);

        // Sort via header name.
        headers.sort();

        for (idx, (k, v)) in headers.into_iter().enumerate() {
            if idx != 0 {
                s.push_str(join);
            }

            s.push_str(&k);
            s.push_str(sep);
            s.push_str(&v);
        }

        s
    }
}

/// SigningMethod is the method that used in signing.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum SigningMethod {
    /// Signing with header.
    Header,
    /// Signing with query.
    Query(Duration),
}
