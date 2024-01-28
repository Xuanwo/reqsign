//! Oracle Cloud Infrastructure Singer

use anyhow::{Error, Result};
use base64::{engine::general_purpose, Engine as _};
use http::HeaderValue;
use log::debug;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

use super::credential::Credential;
use crate::ctx::SigningContext;
use crate::request::SignableRequest;
use crate::time;
use crate::time::DateTime;

/// Singer for Oracle Cloud Infrastructure using API Key.
pub struct APIKeySigner {
    tenancy: String,
    user: String,
}

impl APIKeySigner {
    /// Create a new signer
    pub fn new(tenancy: &str, user: &str) -> Self {
        Self {
            tenancy: tenancy.to_owned(),
            user: user.to_owned(),
        }
    }

    /// Building a signing context.
    fn build(&self, req: &mut impl SignableRequest, cred: &Credential) -> Result<SigningContext> {
        let now = time::now();
        let mut ctx = req.build()?;

        let string_to_sign = string_to_sign(&mut ctx, now)?;
        let private_key = if let Some(key) = &cred.private_key {
            PKey::private_key_from_pem(key.as_bytes())?
        } else {
            return Err(Error::msg("no private key"));
        };
        let mut signer = Signer::new(MessageDigest::sha256(), &private_key)?;
        signer.update(string_to_sign.as_bytes())?;
        let encoded_signature = general_purpose::STANDARD.encode(signer.sign_to_vec()?);

        ctx.headers
            .insert("Date", HeaderValue::from_str(&time::format_http_date(now))?);
        if let Some(fp) = &cred.fingerprint {
            ctx.headers.insert(
                "Authorization",
                HeaderValue::from_str(&format!("Signature version=\" 1\",headers=\"date (request-target) host\",keyId=\"{}/{}/{}\",algorithm=\"rsa-sha256\",signature=\"{}\"",
                    self.tenancy, self.user, &fp, encoded_signature))?);
        } else {
            return Err(Error::msg("no fingerprint"));
        }

        Ok(ctx)
    }

    /// Signing request with header.
    pub fn sign(&self, req: &mut impl SignableRequest, cred: &Credential) -> Result<()> {
        let ctx = self.build(req, cred)?;

        req.apply(ctx)
    }
}

/// Construct string to sign.
///
/// # Format
///
/// ```text
///   "date: {Date}" + "\n"
/// + "(request-target): {verb} {uri}" + "\n"
/// + "host: {Host}"
/// ```
fn string_to_sign(ctx: &mut SigningContext, now: DateTime) -> Result<String> {
    let s = format!(
        "date: {}\n(request-target): {} {}\nhost: {}",
        time::format_http_date(now),
        ctx.method.as_str().to_lowercase(),
        ctx.path,
        ctx.authority,
    );

    debug!("string to sign: {}", &s);
    Ok(s)
}
