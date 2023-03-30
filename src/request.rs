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

/// Implement `SignableRequest` for [`http::Request`]
impl<T> SignableRequest for http::Request<T> {
    fn build(&mut self) -> Result<SigningContext> {
        let this = self as &mut http::Request<T>;

        let uri = mem::take(this.uri_mut()).into_parts();
        let paq = uri
            .path_and_query
            .unwrap_or_else(|| PathAndQuery::from_static("/"));

        Ok(SigningContext {
            method: this.method().clone(),
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
            headers: mem::take(this.headers_mut()),
        })
    }

    fn apply(&mut self, mut ctx: SigningContext) -> Result<()> {
        let this = self as &mut http::Request<T>;

        let query_size = ctx.query_size();

        // Return headers back.
        mem::swap(this.headers_mut(), &mut ctx.headers);

        let mut parts = mem::take(this.uri_mut()).into_parts();
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

        *this.uri_mut() = Uri::from_parts(parts)?;

        Ok(())
    }
}

/// Implement `SignableRequest` for [`reqwest::Request`]
impl SignableRequest for reqwest::Request {
    fn build(&mut self) -> Result<SigningContext> {
        let this = self as &mut reqwest::Request;

        let uri = Uri::from_str(this.url().as_str())
            .expect("input request must contains valid uri")
            .into_parts();
        let paq = uri
            .path_and_query
            .unwrap_or_else(|| PathAndQuery::from_static("/"));

        Ok(SigningContext {
            method: this.method().clone(),
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
            headers: mem::take(this.headers_mut()),
        })
    }

    fn apply(&mut self, mut ctx: SigningContext) -> Result<()> {
        let this = self as &mut reqwest::Request;

        // Return headers back.
        mem::swap(this.headers_mut(), &mut ctx.headers);

        if ctx.query.is_empty() {
            return Ok(());
        }

        this.url_mut()
            .set_query(Some(&SigningContext::query_to_string(ctx.query, "=", "&")));

        Ok(())
    }
}

/// Implement `SignableRequest` for [`reqwest::blocking::Request`]
#[cfg(feature = "reqwest_blocking_request")]
impl SignableRequest for reqwest::blocking::Request {
    fn build(&mut self) -> Result<SigningContext> {
        let this = self as &mut reqwest::blocking::Request;

        let uri = Uri::from_str(this.url().as_str())
            .expect("input request must contains valid uri")
            .into_parts();
        let paq = uri
            .path_and_query
            .unwrap_or_else(|| PathAndQuery::from_static("/"));

        Ok(SigningContext {
            method: this.method().clone(),
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
            headers: mem::take(this.headers_mut()),
        })
    }

    fn apply(&mut self, mut ctx: SigningContext) -> Result<()> {
        let this = self as &mut reqwest::blocking::Request;

        // Return headers back.
        mem::swap(this.headers_mut(), &mut ctx.headers);

        if ctx.query.is_empty() {
            return Ok(());
        }

        this.url_mut()
            .set_query(Some(&SigningContext::query_to_string(ctx.query, "=", "&")));

        Ok(())
    }
}
