//! Aliyun OSS Singer

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::Write;

use anyhow::anyhow;
use anyhow::Result;
use http::header::HeaderName;
use http::header::AUTHORIZATION;
use http::header::CONTENT_TYPE;
use http::header::DATE;
use http::HeaderMap;
use http::HeaderValue;
use log::debug;
use once_cell::sync::Lazy;
use percent_encoding::percent_decode_str;
use percent_encoding::utf8_percent_encode;

use super::credential::CredentialLoader;
use crate::credential::Credential;
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

    /// Calculate signing requests via SignableRequest.
    fn calculate(
        &self,
        req: &impl SignableRequest,
        method: SigningMethod,
        cred: &Credential,
    ) -> Result<SignedOutput> {
        let now = self.time.unwrap_or_else(time::now);
        let string_to_sign = string_to_sign(req, cred, now, method, &self.bucket)?;
        let signature = base64_hmac_sha1(cred.secret_key().as_bytes(), string_to_sign.as_bytes());

        Ok(SignedOutput {
            access_key_id: cred.access_key().to_string(),
            signature,
            signed_time: now,
            signing_method: method,
            security_token: cred.security_token().map(|v| v.to_string()),
        })
    }

    fn apply(&self, req: &mut impl SignableRequest, output: &SignedOutput) -> Result<()> {
        match output.signing_method {
            SigningMethod::Header => {
                req.insert_header(DATE, format_http_date(output.signed_time).parse()?)?;
                req.insert_header(AUTHORIZATION, {
                    let mut value: HeaderValue =
                        format!("OSS {}:{}", output.access_key_id, output.signature).parse()?;
                    value.set_sensitive(true);

                    value
                })?;
                if let Some(token) = &output.security_token {
                    req.insert_header("x-oss-security-token".parse()?, {
                        let mut value: HeaderValue = token.parse()?;
                        value.set_sensitive(true);

                        value
                    })?;
                }
            }
            SigningMethod::Query(expire) => {
                req.insert_header(DATE, format_http_date(output.signed_time).parse()?)?;
                let mut query = if let Some(query) = req.query() {
                    query.to_string() + "&"
                } else {
                    "".to_string()
                };

                write!(query, "OSSAccessKeyId={}", output.access_key_id)?;
                write!(
                    query,
                    "&Expires={}",
                    (output.signed_time + expire).unix_timestamp()
                )?;
                write!(
                    query,
                    "&Signature={}",
                    utf8_percent_encode(&output.signature, percent_encoding::NON_ALPHANUMERIC)
                )?;
                if let Some(token) = &output.security_token {
                    write!(
                        query,
                        "&security-token={}",
                        utf8_percent_encode(token, percent_encoding::NON_ALPHANUMERIC)
                    )?;
                }

                req.set_query(&query)?;
            }
        }

        Ok(())
    }

    /// Signing request with header.
    pub fn sign(&self, req: &mut impl SignableRequest) -> Result<()> {
        if let Some(cred) = self.credential() {
            let sig = self.calculate(req, SigningMethod::Header, &cred)?;
            return self.apply(req, &sig);
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
            let sig = self.calculate(req, SigningMethod::Query(expire), &cred)?;
            return self.apply(req, &sig);
        }

        if self.allow_anonymous {
            debug!("credential not found and anonymous is allowed, skipping signing.");
            return Ok(());
        }

        Err(anyhow!("credential not found"))
    }
}

/// SigningMethod is the method that used in signing.
#[derive(Copy, Clone)]
pub enum SigningMethod {
    /// Signing with header.
    Header,
    /// Signing with query.
    Query(Duration),
}

struct SignedOutput {
    access_key_id: String,
    signature: String,
    signed_time: DateTime,
    signing_method: SigningMethod,
    security_token: Option<String>,
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
    method: SigningMethod,
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
    match method {
        SigningMethod::Header => {
            writeln!(&mut s, "{}", format_http_date(now))?;
        }
        SigningMethod::Query(expires) => {
            writeln!(&mut s, "{}", (now + expires).unix_timestamp())?;
        }
    }

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
