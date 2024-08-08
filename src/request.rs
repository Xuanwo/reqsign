//! Provide common request trait for signing.

use std::mem;
use std::str::FromStr;

use anyhow::anyhow;
use anyhow::Result;
use http::uri::PathAndQuery;
use http::uri::Scheme;
use http::Uri;

use crate::ctx::SigningContext;

/// Trait for all signable request.
///
/// Any request type that implement this trait can be used by signers as input.
/// Different requests may have different uri implementations, so we return detailed
/// uri components instead of a complete struct.
pub trait SignableRequest {
    fn build(&mut self) -> Result<SigningContext>;

    fn apply(&mut self, _ctx: SigningContext) -> Result<()>;
}

/// Implement `SignableRequest` for [`http::request::Parts`]
impl SignableRequest for http::request::Parts {
    fn build(&mut self) -> Result<SigningContext> {
        let uri = mem::take(&mut self.uri).into_parts();
        let paq = uri
            .path_and_query
            .unwrap_or_else(|| PathAndQuery::from_static("/"));

        Ok(SigningContext {
            method: self.method.clone(),
            scheme: uri.scheme.unwrap_or(Scheme::HTTP),
            authority: uri
                .authority
                .ok_or_else(|| anyhow!("request without authority is invalid for signing"))?,
            path: paq.path().to_string(),
            query: paq
                .query()
                .map(|v| {
                    form_urlencoded::parse(v.as_bytes())
                        .map(|(k, v)| (k.into_owned(), v.into_owned()))
                        .collect()
                })
                .unwrap_or_default(),

            // Take the headers out of the request to avoid copy.
            // We will return it back when apply the context.
            headers: mem::take(&mut self.headers),
        })
    }

    fn apply(&mut self, mut ctx: SigningContext) -> Result<()> {
        let query_size = ctx.query_size();

        // Return headers back.
        mem::swap(&mut self.headers, &mut ctx.headers);

        let mut parts = mem::take(&mut self.uri).into_parts();
        // Return scheme bakc.
        parts.scheme = Some(ctx.scheme);
        // Return authority back.
        parts.authority = Some(ctx.authority);
        // Build path and query.
        parts.path_and_query = {
            let paq = if query_size == 0 {
                ctx.path
            } else {
                let mut s = ctx.path;
                s.reserve(query_size + 1);

                s.push('?');
                for (i, (k, v)) in ctx.query.iter().enumerate() {
                    if i > 0 {
                        s.push('&');
                    }

                    s.push_str(k);
                    if !v.is_empty() {
                        s.push('=');
                        s.push_str(v);
                    }
                }

                s
            };

            Some(PathAndQuery::from_str(&paq)?)
        };

        self.uri = Uri::from_parts(parts)?;

        Ok(())
    }
}
