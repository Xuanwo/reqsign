//! Aliyun OSS Singer

use crate::credential::{Credential, CredentialLoad, CredentialLoadChain};
use crate::hash::base64_hmac_sha1;
use crate::request::SignableRequest;
use crate::time;
use crate::time::Duration;
use crate::time::{format_http_date, DateTime};
use anyhow::{anyhow, Result};
use http::header::{HeaderName, AUTHORIZATION, CONTENT_TYPE, DATE};
use http::{HeaderMap, HeaderValue};
use log::debug;
use once_cell::sync::Lazy;
use percent_encoding::percent_decode_str;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::Write;
use std::mem;
use std::sync::{Arc, RwLock};

const CONTENT_MD5: &str = "content-md5";

/// Builder for `Signer`
#[derive(Default)]
pub struct Builder {
    credential: Credential,
    credential_load: CredentialLoadChain,
    allow_anonymous: bool,

    bucket: String,
    provider_arn: Option<String>,
    role_arn: Option<String>,
    oidc_token: Option<String>,

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

    /// Specify provider arn.
    pub fn provider_arn(&mut self, provider_arn: &str) -> &mut Self {
        self.provider_arn = Some(provider_arn.to_string());
        self
    }

    /// Specify role arn.
    pub fn role_arn(&mut self, role_arn: &str) -> &mut Self {
        self.role_arn = Some(role_arn.to_string());
        self
    }

    /// Specify oidc token.
    pub fn oidc_token(&mut self, token: &str) -> &mut Self {
        self.oidc_token = Some(token.to_string());
        self
    }

    /// Specify credential load behavior
    ///
    /// If not set, we will use the default credential loader.
    pub fn credential_loader(&mut self, credential: CredentialLoadChain) -> &mut Self {
        self.credential_load = credential;
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

        let credential = if self.credential.is_valid() {
            Some(self.credential.clone())
        } else {
            self.credential_load.load_credential()?
        };
        debug!("signer credential: {:?}", &credential);

        Ok(Signer {
            bucket: self.bucket.to_string(),
            credential: Arc::new(RwLock::new(credential)),
            credential_load: mem::take(&mut self.credential_load),
            allow_anonymous: self.allow_anonymous,
            time: self.time,
        })
    }
}

/// Singer for Aliyun OSS.
pub struct Signer {
    bucket: String,
    credential: Arc<RwLock<Option<Credential>>>,
    credential_load: CredentialLoadChain,

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
    fn credential(&self) -> Result<Option<Credential>> {
        // Return cached credential if it's valid.
        match self.credential.read().expect("lock poisoned").clone() {
            None => return Ok(None),
            Some(cred) => {
                if cred.is_valid() {
                    return Ok(Some(cred));
                }
            }
        }

        if let Some(cred) = self.credential_load.load_credential()? {
            let mut lock = self.credential.write().expect("lock poisoned");
            *lock = Some(cred.clone());
            Ok(Some(cred))
        } else {
            // We used to get credential correctly, but now we can't.
            // Something must happened in the running environment.
            Err(anyhow!("credential should be loaded but not"))
        }
    }

    /// Calculate signing requests via SignableRequest.
    fn calculate(&self, req: &impl SignableRequest, cred: &Credential) -> Result<SignedOutput> {
        let now = self.time.unwrap_or_else(time::now);
        let string_to_sign = string_to_sign(req, cred, now, &self.bucket)?;
        let signature = base64_hmac_sha1(cred.secret_key().as_bytes(), string_to_sign.as_bytes());

        Ok(SignedOutput {
            access_key_id: cred.access_key().to_string(),
            signature,
            signed_time: now,
        })
    }

    fn apply(&self, req: &mut impl SignableRequest, output: &SignedOutput) -> Result<()> {
        req.insert_header(DATE, format_http_date(output.signed_time).parse()?)?;
        req.insert_header(AUTHORIZATION, {
            let mut value: HeaderValue =
                format!("OSS {}:{}", output.access_key_id, output.signature).parse()?;
            value.set_sensitive(true);

            value
        })?;

        Ok(())
    }

    /// Signing request with header.
    pub fn sign(&self, req: &mut impl SignableRequest) -> Result<()> {
        if let Some(cred) = self.credential()? {
            let sig = self.calculate(req, &cred)?;
            return self.apply(req, &sig);
        }

        if self.allow_anonymous {
            debug!("credential not found and anonymous is allowed, skipping signing.");
            return Ok(());
        }

        Err(anyhow!("credential not found"))
    }

    /// Signing request with query.
    pub fn sign_query(&self, _: &mut impl SignableRequest, _: Duration) -> Result<()> {
        todo!()
    }
}

struct SignedOutput {
    access_key_id: String,
    signature: String,
    signed_time: DateTime,
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
    req: &impl SignableRequest,
    cred: &Credential,
    now: DateTime,
    bucket: &str,
) -> Result<String> {
    #[inline]
    fn get_or_default<'a>(h: &'a HeaderMap, key: &'a HeaderName) -> Result<&'a str> {
        match h.get(key) {
            Some(v) => Ok(v.to_str()?),
            None => Ok(""),
        }
    }

    let h = req.headers();
    let mut s = String::new();
    writeln!(&mut s, "{}", req.method().as_str())?;
    writeln!(&mut s, "{}", get_or_default(&h, &CONTENT_MD5.parse()?)?)?;
    writeln!(&mut s, "{}", get_or_default(&h, &CONTENT_TYPE)?)?;
    writeln!(&mut s, "{}", format_http_date(now))?;
    {
        let headers = canonicalize_header(req, cred)?;
        if !headers.is_empty() {
            writeln!(&mut s, "{headers}",)?;
        }
    }
    write!(&mut s, "{}", canonicalize_resource(req, bucket))?;

    debug!("string to sign: {}", &s);
    Ok(s)
}

/// Build canonicalize header
///
/// # Reference
///
/// [Building CanonicalizedOSSHeaders](https://help.aliyun.com/document_detail/31951.html#section-w2k-sw2-xdb)
fn canonicalize_header(req: &impl SignableRequest, cred: &Credential) -> Result<String> {
    let mut headers = req
        .headers()
        .iter()
        // Filter all header that starts with "x-ms-"
        .filter(|(k, _)| k.as_str().starts_with("x-oss-"))
        // Convert all header name to lowercase
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().expect("must be valid header").to_string(),
            )
        })
        .collect::<Vec<(String, String)>>();

    // Insert security token
    if let Some(token) = cred.security_token() {
        headers.push(("x-oss-security-token".to_string(), token.to_string()))
    };

    // Sort via header name.
    headers.sort_by(|x, y| x.0.cmp(&y.0));

    Ok(headers
        .iter()
        // Format into "name:value"
        .map(|(k, v)| format!("{}:{}", k, v))
        .collect::<Vec<String>>()
        // Join via "\n"
        .join("\n"))
}

/// Build canonicalize resource
///
/// # Reference
///
/// [Building CanonicalizedResource](https://help.aliyun.com/document_detail/31951.html#section-w2k-sw2-xdb)
fn canonicalize_resource(req: &impl SignableRequest, bucket: &str) -> String {
    let mut params: Vec<(Cow<'_, str>, Cow<'_, str>)> =
        form_urlencoded::parse(req.query().unwrap_or_default().as_bytes())
            .filter(|(k, _)| is_sub_resource(k))
            .collect();
    // Sort by param name
    params.sort();

    let params_str = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<String>>()
        .join("&");

    let path = percent_decode_str(req.path()).decode_utf8_lossy();
    if params_str.is_empty() {
        format!("/{bucket}{}", path)
    } else {
        format!("/{bucket}{}?{}", path, params_str)
    }
}

fn is_sub_resource(v: &str) -> bool {
    SUB_RESOURCES.contains(&v)
}

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
        "callback",
        "callback-var",
        "response-content-type",
        "response-content-language",
        "response-expires",
        "response-cache-control",
        "response-content-disposition",
        "response-content-encoding",
        "x-oss-ac-source-ip",
        "x-oss-ac-subnet-mask",
        "x-oss-ac-vpc-id",
        "x-oss-ac-forward-allow",
    ])
});
