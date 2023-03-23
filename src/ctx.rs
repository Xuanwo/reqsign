use http::{uri::Authority, HeaderMap, Method};
use time::Duration;

pub struct SigningContext {
    pub method: Method,
    pub authority: Authority,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: HeaderMap,
}

impl SigningContext {
    pub fn query_size(&self) -> usize {
        self.query
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>()
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
