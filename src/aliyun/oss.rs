//! Aliyun OSS Singer

use std::collections::HashSet;
use std::fmt::Write;

use anyhow::anyhow;
use anyhow::Result;
use http::header::AUTHORIZATION;
use http::header::CONTENT_TYPE;
use http::header::DATE;
use http::HeaderValue;
use log::debug;
use once_cell::sync::Lazy;
use percent_encoding::utf8_percent_encode;

use super::credential::CredentialLoader;
use crate::credential::Credential;
use crate::ctx::SigningContext;
use crate::ctx::SigningMethod;
use crate::hash::base64_hmac_sha1;
use crate::request::SignableRequest;
use crate::time;
use crate::time::format_http_date;
use crate::time::DateTime;
use crate::time::Duration;

const CONTENT_MD5: &str = "content-md5";

/// Builder for `Signer`
#[derive(Default)]
pub struct Builder {
    bucket: String,
    credential: Credential,

    disable_load_from_env: bool,
    disable_load_from_assume_role_with_oidc: bool,
    allow_anonymous: bool,

    time: Option<DateTime>,
}

impl Builder {
    /// Specify bucket name.
    pub fn bucket(&mut self, bucket: &str) -> &mut Self {
        self.bucket = bucket.to_string();
        self
    }

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
        if self.bucket.is_empty() {
            return Err(anyhow!("bucket is required"));
        }

        let mut cred_loader = CredentialLoader::default();
        if self.credential.is_valid() {
            cred_loader = cred_loader.with_credential(self.credential.clone());
        }
        if self.disable_load_from_env {
            cred_loader = cred_loader.with_disable_env();
        }
        if self.disable_load_from_assume_role_with_oidc {
            cred_loader = cred_loader.with_disable_assume_role_with_oidc();
        }

        Ok(Signer {
            bucket: self.bucket.to_string(),
            credential_loader: cred_loader,
            allow_anonymous: self.allow_anonymous,
            time: self.time,
        })
    }
}

/// Singer for Aliyun OSS.
pub struct Signer {
    bucket: String,
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

    /// Building a signing context.
    fn build(
        &self,
        req: &mut impl SignableRequest,
        method: SigningMethod,
        cred: &Credential,
    ) -> Result<SigningContext> {
        let now = self.time.unwrap_or_else(time::now);
        let mut ctx = req.build()?;

        let string_to_sign = string_to_sign(&mut ctx, cred, now, method, &self.bucket)?;
        let signature = base64_hmac_sha1(cred.secret_key().as_bytes(), string_to_sign.as_bytes());

        match method {
            SigningMethod::Header => {
                ctx.headers.insert(DATE, format_http_date(now).parse()?);
                ctx.headers.insert(AUTHORIZATION, {
                    let mut value: HeaderValue =
                        format!("OSS {}:{}", cred.access_key(), signature).parse()?;
                    value.set_sensitive(true);

                    value
                });
            }
            SigningMethod::Query(expire) => {
                ctx.headers.insert(DATE, format_http_date(now).parse()?);
                ctx.query_push("OSSAccessKeyId", cred.access_key());
                ctx.query_push("Expires", (now + expire).unix_timestamp().to_string());
                ctx.query_push(
                    "Signature",
                    utf8_percent_encode(&signature, percent_encoding::NON_ALPHANUMERIC).to_string(),
                )
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

/// Construct string to sign.
///
/// # Format
///
/// ```text
///   VERB + "\n"
/// + Content-MD5 + "\n"
/// + Content-Type + "\n"
/// + Date + "\n"
/// + CanonicalizedOSSHeaders
/// + CanonicalizedResource
/// ```
fn string_to_sign(
    ctx: &mut SigningContext,
    cred: &Credential,
    now: DateTime,
    method: SigningMethod,
    bucket: &str,
) -> Result<String> {
    let mut s = String::new();
    s.write_str(ctx.method.as_str())?;
    s.write_str("\n")?;
    s.write_str(ctx.header_get_or_default(&CONTENT_MD5.parse()?)?)?;
    s.write_str("\n")?;
    s.write_str(ctx.header_get_or_default(&CONTENT_TYPE)?)?;
    s.write_str("\n")?;
    match method {
        SigningMethod::Header => {
            writeln!(&mut s, "{}", format_http_date(now))?;
        }
        SigningMethod::Query(expires) => {
            writeln!(&mut s, "{}", (now + expires).unix_timestamp())?;
        }
    }

    {
        let headers = canonicalize_header(ctx, method, cred)?;
        if !headers.is_empty() {
            writeln!(&mut s, "{headers}",)?;
        }
    }
    write!(
        &mut s,
        "{}",
        canonicalize_resource(ctx, bucket, method, cred)
    )?;

    debug!("string to sign: {}", &s);
    Ok(s)
}

/// Build canonicalize header
///
/// # Reference
///
/// [Building CanonicalizedOSSHeaders](https://help.aliyun.com/document_detail/31951.html#section-w2k-sw2-xdb)
fn canonicalize_header(
    ctx: &mut SigningContext,
    method: SigningMethod,
    cred: &Credential,
) -> Result<String> {
    if method == SigningMethod::Header {
        // Insert security token
        if let Some(token) = cred.security_token() {
            ctx.headers.insert("x-oss-security-token", token.parse()?);
        }
    }

    Ok(SigningContext::header_to_string(
        ctx.header_to_vec_with_prefix("x-oss-"),
        "\n",
    ))
}

/// Build canonicalize resource
///
/// # Reference
///
/// [Building CanonicalizedResource](https://help.aliyun.com/document_detail/31951.html#section-w2k-sw2-xdb)
fn canonicalize_resource(
    ctx: &mut SigningContext,
    bucket: &str,
    method: SigningMethod,
    cred: &Credential,
) -> String {
    if let SigningMethod::Query(_) = method {
        // Insert security token
        if let Some(token) = cred.security_token() {
            ctx.query
                .push(("security-token".to_string(), token.to_string()));
        };
    }

    let params = ctx.query_to_vec_with_filter(is_sub_resource);

    let params_str = SigningContext::query_to_string(params, "=", "&");

    if params_str.is_empty() {
        format!("/{bucket}{}", ctx.path_percent_decoded())
    } else {
        format!("/{bucket}{}?{params_str}", ctx.path_percent_decoded())
    }
}

fn is_sub_resource(v: &str) -> bool {
    SUB_RESOURCES.contains(&v)
}

/// This list is copied from <https://github.com/aliyun/aliyun-oss-go-sdk/blob/master/oss/conn.go>
static SUB_RESOURCES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "acl",
        "uploads",
        "location",
        "cors",
        "logging",
        "website",
        "referer",
        "lifecycle",
        "delete",
        "append",
        "tagging",
        "objectMeta",
        "uploadId",
        "partNumber",
        "security-token",
        "position",
        "img",
        "style",
        "styleName",
        "replication",
        "replicationProgress",
        "replicationLocation",
        "cname",
        "bucketInfo",
        "comp",
        "qos",
        "live",
        "status",
        "vod",
        "startTime",
        "endTime",
        "symlink",
        "x-oss-process",
        "response-content-type",
        "x-oss-traffic-limit",
        "response-content-language",
        "response-expires",
        "response-cache-control",
        "response-content-disposition",
        "response-content-encoding",
        "udf",
        "udfName",
        "udfImage",
        "udfId",
        "udfImageDesc",
        "udfApplication",
        "comp",
        "udfApplicationLog",
        "restore",
        "callback",
        "callback-var",
        "qosInfo",
        "policy",
        "stat",
        "encryption",
        "versions",
        "versioning",
        "versionId",
        "requestPayment",
        "x-oss-request-payer",
        "sequential",
        "inventory",
        "inventoryId",
        "continuation-token",
        "asyncFetch",
        "worm",
        "wormId",
        "wormExtend",
        "withHashContext",
        "x-oss-enable-md5",
        "x-oss-enable-sha1",
        "x-oss-enable-sha256",
        "x-oss-hash-ctx",
        "x-oss-md5-ctx",
        "transferAcceleration",
        "regionList",
        "cloudboxes",
        "x-oss-ac-source-ip",
        "x-oss-ac-subnet-mask",
        "x-oss-ac-vpc-id",
        "x-oss-ac-forward-allow",
        "metaQuery",
    ])
});
