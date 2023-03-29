//! Tencent COS Singer

use anyhow::anyhow;
use anyhow::Result;
use http::header::AUTHORIZATION;
use http::header::DATE;
use http::HeaderValue;
use log::debug;
use percent_encoding::percent_decode_str;
use percent_encoding::utf8_percent_encode;

use super::credential::CredentialLoader;
use crate::credential::Credential;
use crate::ctx::SigningContext;
use crate::ctx::SigningMethod;
use crate::hash::hex_hmac_sha1;
use crate::hash::hex_sha1;
use crate::request::SignableRequest;
use crate::time;
use crate::time::format_http_date;
use crate::time::DateTime;
use crate::time::Duration;

/// Builder for `Signer`
#[derive(Default)]
pub struct Builder {
    credential: Credential,
    disable_load_from_env: bool,
    disable_load_from_assume_role_with_oidc: bool,
    allow_anonymous: bool,
    time: Option<DateTime>,
}

impl Builder {
    /// Specify access key id.
    ///
    /// If not set, we will try to load via `credential_loader`.
    pub fn access_key_id(&mut self, access_key_id: &str) -> &mut Self {
        self.credential.set_access_key(access_key_id);
        self
    }

    /// Specify access key secret.
    ///
    /// If not set, we will try to load via `credential_loader`.
    pub fn access_key_secret(&mut self, access_key_secret: &str) -> &mut Self {
        self.credential.set_secret_key(access_key_secret);
        self
    }

    /// Disable load from env.
    pub fn disable_load_from_env(&mut self) -> &mut Self {
        self.disable_load_from_env = true;
        self
    }

    /// Disable load from assume role with oidc.
    pub fn disable_load_from_assume_role_with_oidc(&mut self) -> &mut Self {
        self.disable_load_from_assume_role_with_oidc = true;
        self
    }

    /// Allow anonymous request if credential is not loaded.
    pub fn allow_anonymous(&mut self) -> &mut Self {
        self.allow_anonymous = true;
        self
    }

    /// Specify the signing time.
    ///
    /// # Note
    ///
    /// We should always take current time to sign requests.
    /// Only use this function for testing.
    #[cfg(test)]
    pub fn time(&mut self, time: DateTime) -> &mut Self {
        self.time = Some(time);
        self
    }

    /// Use exising information to build a new signer.
    ///
    /// The builder should not be used anymore.
    pub fn build(&mut self) -> Result<Signer> {
        let mut cred_loader = CredentialLoader::default();
        if self.credential.is_valid() {
            cred_loader = cred_loader.with_credential(self.credential.clone());
        }
        Ok(Signer {
            credential_loader: cred_loader,
            allow_anonymous: self.allow_anonymous,
            time: self.time,
        })
    }
}

/// Singer for Tencent COS.
pub struct Signer {
    credential_loader: CredentialLoader,
    /// Allow anonymous request if credential is not loaded.
    allow_anonymous: bool,
    time: Option<DateTime>,
}

impl Signer {
    /// Load credential via credential load chain specified while building.
    ///
    /// # Note
    ///
    /// This function should never be exported to avoid credential leaking by
    /// mistake.
    fn credential(&self) -> Option<Credential> {
        self.credential_loader.load()
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
                let signature = build_signature(&mut ctx, cred, now, Duration::hours(1));

                req.insert_header(DATE, format_http_date(now).parse()?)?;
                req.insert_header(AUTHORIZATION, {
                    let mut value: HeaderValue = signature.parse()?;
                    value.set_sensitive(true);
                    value
                })?;

                if let Some(token) = cred.security_token() {
                    req.insert_header("x-cos-security-token".parse()?, {
                        let mut value: HeaderValue = token.parse()?;
                        value.set_sensitive(true);

                        value
                    })?;
                }
            }
            SigningMethod::Query(expire) => {
                let signature = build_signature(&mut ctx, cred, now, expire);

                req.insert_header(DATE, format_http_date(now).parse()?)?;
                ctx.query_append(&signature);

                if let Some(token) = cred.security_token() {
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
    pub fn sign(&self, req: &mut impl SignableRequest) -> Result<()> {
        if let Some(cred) = self.credential() {
            let ctx = self.build(req, SigningMethod::Header, &cred)?;
            return req.apply(ctx);
        }

        if self.allow_anonymous {
            debug!("credential not found and anonymous is allowed, skipping signing.");
            return Ok(());
        }

        Err(anyhow!("credential not found"))
    }

    /// Signing request with query.
    pub fn sign_query(&self, req: &mut impl SignableRequest, expire: Duration) -> Result<()> {
        if let Some(cred) = self.credential() {
            let ctx = self.build(req, SigningMethod::Query(expire), &cred)?;
            return req.apply(ctx);
        }

        if self.allow_anonymous {
            debug!("credential not found and anonymous is allowed, skipping signing.");
            return Ok(());
        }

        Err(anyhow!("credential not found"))
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
        now.unix_timestamp(),
        (now + expires).unix_timestamp()
    );

    let sign_key = hex_hmac_sha1(cred.secret_key().as_bytes(), key_time.as_bytes());

    let mut params = ctx
        .query
        .iter()
        .map(|(k, v)| {
            (
                utf8_percent_encode(&k.to_lowercase(), percent_encoding::NON_ALPHANUMERIC)
                    .to_string(),
                utf8_percent_encode(&v.to_lowercase(), percent_encoding::NON_ALPHANUMERIC)
                    .to_string(),
            )
        })
        .collect::<Vec<_>>();
    params.sort();

    let param_list = params
        .iter()
        .map(|(k, _)| k.to_string())
        .collect::<Vec<_>>()
        .join(";");

    let header_list = ctx.header_name_to_vec_sorted().join(";");

    let mut http_string = String::new();

    http_string.push_str(ctx.method.as_str());
    http_string.push('\n');
    http_string.push_str(&percent_decode_str(&ctx.path).decode_utf8_lossy());
    http_string.push('\n');
    http_string.push_str(&SigningContext::query_to_string(params, "=", "&"));
    http_string.push('\n');
    http_string.push_str(&SigningContext::header_to_string(
        ctx.header_to_vec_with_prefix(""),
        "=",
        "&",
    ));
    http_string.push('\n');

    let mut string_to_sign = String::new();
    string_to_sign.push_str("sha1");
    string_to_sign.push('\n');
    string_to_sign.push_str(&key_time);
    string_to_sign.push('\n');
    string_to_sign.push_str(&hex_sha1(http_string.as_bytes()));
    string_to_sign.push('\n');

    let signature = hex_hmac_sha1(sign_key.as_bytes(), string_to_sign.as_bytes());

    format!("q-sign-algorithm=sha1&q-ak={}&q-sign-time={}&q-key-time={}&q-header-list={}&q-url-param-list={}&q-signature={}", cred.access_key(), sign_key, key_time, header_list, param_list, signature)
}
