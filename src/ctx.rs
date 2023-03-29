use std::borrow::Cow;

use anyhow::Result;
use http::{
    header::HeaderName,
    uri::{Authority, Scheme},
    HeaderMap, HeaderValue, Method,
};
use time::Duration;

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

    pub fn query_push(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.query.push((key.into(), value.into()));
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

    pub fn header_names_to_vec_sorted(&self) -> Vec<&str> {
        let mut h = self
            .headers
            .keys()
            .map(|k| k.as_str())
            .collect::<Vec<&str>>();
        h.sort_unstable();

        h
    }

    pub fn headers_to_vec_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
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
}

/// SigningMethod is the method that used in signing.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum SigningMethod {
    /// Signing with header.
    Header,
    /// Signing with query.
    Query(Duration),
}
