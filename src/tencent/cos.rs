//! Tencent COS Singer

use std::time::Duration;

use anyhow::Result;
use http::header::AUTHORIZATION;
use http::header::DATE;
use http::HeaderValue;
use log::debug;
use percent_encoding::percent_decode_str;
use percent_encoding::utf8_percent_encode;

use super::constants::*;
use super::credential::Credential;
use crate::ctx::SigningContext;
use crate::ctx::SigningMethod;
use crate::hash::hex_hmac_sha1;
use crate::hash::hex_sha1;
use crate::request::SignableRequest;
use crate::time;
use crate::time::format_http_date;
use crate::time::DateTime;

/// Singer for Tencent COS.
#[derive(Default)]
pub struct Signer {
    time: Option<DateTime>,
}

impl Signer {
    /// Load credential via credential load chain specified while building.
    ///
    /// # Note
    ///
    /// This function should never be exported to avoid credential leaking by
    /// mistake.
    pub fn new() -> Self {
        Self::default()
    }

    /// Specify the signing time.
    ///
    /// # Note
    ///
    /// We should always take current time to sign requests.
    /// Only use this function for testing.
    #[cfg(test)]
    pub fn with_time(mut self, time: DateTime) -> Self {
        self.time = Some(time);
        self
    }

    fn build(
        &self,
        req: &mut impl SignableRequest,
        method: SigningMethod,
        cred: &Credential,
    ) -> Result<SigningContext> {
        let now = self.time.unwrap_or_else(time::now);
        let mut ctx = req.build()?;

        match method {
            SigningMethod::Header => {
                let signature = build_signature(&mut ctx, cred, now, Duration::from_secs(3600));

                ctx.headers.insert(DATE, format_http_date(now).parse()?);
                ctx.headers.insert(AUTHORIZATION, {
                    let mut value: HeaderValue = signature.parse()?;
                    value.set_sensitive(true);
                    value
                });

                if let Some(token) = &cred.security_token {
                    ctx.headers.insert("x-cos-security-token", {
                        let mut value: HeaderValue = token.parse()?;
                        value.set_sensitive(true);

                        value
                    });
                }
            }
            SigningMethod::Query(expire) => {
                let signature = build_signature(&mut ctx, cred, now, expire);

                ctx.headers.insert(DATE, format_http_date(now).parse()?);
                ctx.query_append(&signature);

                if let Some(token) = &cred.security_token {
                    ctx.query_push(
                        "x-cos-security-token".to_string(),
                        utf8_percent_encode(token, percent_encoding::NON_ALPHANUMERIC).to_string(),
                    );
                }
            }
        }

        Ok(ctx)
    }

    /// Signing request with header.
    pub fn sign(&self, req: &mut impl SignableRequest, cred: &Credential) -> Result<()> {
        let ctx = self.build(req, SigningMethod::Header, cred)?;
        req.apply(ctx)
    }

    /// Signing request with query.
    pub fn sign_query(
        &self,
        req: &mut impl SignableRequest,
        expire: Duration,
        cred: &Credential,
    ) -> Result<()> {
        let ctx = self.build(req, SigningMethod::Query(expire), cred)?;
        req.apply(ctx)
    }
}

fn build_signature(
    ctx: &mut SigningContext,
    cred: &Credential,
    now: DateTime,
    expires: Duration,
) -> String {
    let key_time = format!(
        "{};{}",
        now.timestamp(),
        (now + chrono::Duration::from_std(expires).unwrap()).timestamp()
    );

    let sign_key = hex_hmac_sha1(cred.secret_key.as_bytes(), key_time.as_bytes());

    let mut params = ctx
        .query
        .iter()
        .map(|(k, v)| {
            (
                utf8_percent_encode(&k.to_lowercase(), &TENCENT_URI_ENCODE_SET).to_string(),
                utf8_percent_encode(&v.to_lowercase(), &TENCENT_URI_ENCODE_SET).to_string(),
            )
        })
        .collect::<Vec<_>>();
    params.sort();

    let param_list = params
        .iter()
        .map(|(k, _)| k.to_string())
        .collect::<Vec<_>>()
        .join(";");
    debug!("param list: {param_list}");
    let param_string = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");
    debug!("param string: {param_string}");

    let mut headers = ctx
        .header_to_vec_with_prefix("")
        .iter()
        .map(|(k, v)| {
            (
                k.to_lowercase(),
                utf8_percent_encode(v, &TENCENT_URI_ENCODE_SET).to_string(),
            )
        })
        .collect::<Vec<_>>();
    headers.sort();

    let header_list = headers
        .iter()
        .map(|(k, _)| k.to_string())
        .collect::<Vec<_>>()
        .join(";");
    debug!("header list: {header_list}");
    let header_string = headers
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");
    debug!("header string: {header_string}");

    let mut http_string = String::new();

    http_string.push_str(&ctx.method.as_str().to_ascii_lowercase());
    http_string.push('\n');
    http_string.push_str(&percent_decode_str(&ctx.path).decode_utf8_lossy());
    http_string.push('\n');
    http_string.push_str(&param_string);
    http_string.push('\n');
    http_string.push_str(&header_string);
    http_string.push('\n');
    debug!("http string: {http_string}");

    let mut string_to_sign = String::new();
    string_to_sign.push_str("sha1");
    string_to_sign.push('\n');
    string_to_sign.push_str(&key_time);
    string_to_sign.push('\n');
    string_to_sign.push_str(&hex_sha1(http_string.as_bytes()));
    string_to_sign.push('\n');
    debug!("string_to_sign: {string_to_sign}");

    let signature = hex_hmac_sha1(sign_key.as_bytes(), string_to_sign.as_bytes());

    format!("q-sign-algorithm=sha1&q-ak={}&q-sign-time={}&q-key-time={}&q-header-list={}&q-url-param-list={}&q-signature={}", cred.secret_id, key_time, key_time, header_list, param_list, signature)
}
