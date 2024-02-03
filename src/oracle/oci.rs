//! Oracle Cloud Infrastructure Singer

use anyhow::{Error, Result};
use base64::{engine::general_purpose, Engine as _};
use http::{
    header::{AUTHORIZATION, DATE},
    HeaderValue,
};
use log::debug;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use std::fmt::Write;

use super::credential::Credential;
use crate::ctx::SigningContext;
use crate::request::SignableRequest;
use crate::time;
use crate::time::DateTime;

/// Singer for Oracle Cloud Infrastructure using API Key.
#[derive(Default)]
pub struct APIKeySigner {}

impl APIKeySigner {
    /// Building a signing context.
    fn build(&self, req: &mut impl SignableRequest, cred: &Credential) -> Result<SigningContext> {
        let now = time::now();
        let mut ctx = req.build()?;

        let string_to_sign = string_to_sign(&mut ctx, now)?;
        let private_key = if let Some(path) = &cred.key_file {
            RsaPrivateKey::read_pkcs8_pem_file(path)?
        } else {
            return Err(Error::msg("no private key"));
        };
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = signing_key.try_sign(string_to_sign.as_bytes())?;
        let encoded_signature = general_purpose::STANDARD.encode(signature.to_bytes());

        ctx.headers
            .insert(DATE, HeaderValue::from_str(&time::format_http_date(now))?);
        if let Some(fp) = &cred.fingerprint {
            let mut auth_value = String::new();
            write!(auth_value, "Signature version=\"1\",")?;
            write!(auth_value, "headers=\"date (request-target) host\",")?;
            write!(
                auth_value,
                "keyId=\"{}/{}/{}\",",
                cred.tenancy, cred.user, &fp
            )?;
            write!(auth_value, "algorithm=\"rsa-sha256\",")?;
            write!(auth_value, "signature=\"{}\"", encoded_signature)?;
            ctx.headers
                .insert(AUTHORIZATION, HeaderValue::from_str(&auth_value)?);
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
    let string_to_sign = {
        let mut f = String::new();
        writeln!(f, "date: {}", time::format_http_date(now))?;
        writeln!(
            f,
            "(request-target): {} {}",
            ctx.method.as_str().to_lowercase(),
            ctx.path
        )?;
        write!(f, "host: {}", ctx.authority)?;
        f
    };

    debug!("string to sign: {}", &string_to_sign);
    Ok(string_to_sign)
}
