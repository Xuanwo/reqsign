//! Huawei Cloud Object Storage Service (OBS) signer
use std::collections::HashSet;
use std::fmt::Debug;
use std::fmt::Formatter;
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

use super::super::constants::*;
use super::credential::CredentialLoader;
use crate::credential::Credential;
use crate::ctx::SigningContext;
use crate::ctx::SigningMethod;
use crate::hash::base64_hmac_sha1;
use crate::request::SignableRequest;
use crate::time::format_http_date;
use crate::time::DateTime;
use crate::time::Duration;
use crate::time::{self};

/// Builder for `Signer`.
#[derive(Default)]
pub struct Builder {
    credential: Credential,

    time: Option<DateTime>,
    bucket: Option<String>,
}

impl Builder {
    /// Specify access key.
    pub fn access_key(&mut self, access_key: &str) -> &mut Self {
        self.credential.set_access_key(access_key);
        self
    }

    /// Specify secret key.
    pub fn secret_key(&mut self, secret_key: &str) -> &mut Self {
        self.credential.set_secret_key(secret_key);
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

    /// Set the bucket name in canonicalized resource.
    /// The caller should guarantee the param is same with bucket name in domain.
    pub fn bucket(&mut self, bucket: &str) -> &mut Self {
        self.bucket = Some(bucket.to_string());
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

        let bucket = self
            .bucket
            .clone()
            .ok_or_else(|| anyhow!("bucket should not be none"))?;

        Ok(Signer {
            credential_loader: cred_loader,
            time: self.time,
            bucket,
        })
    }
}

/// Singer that implement Huawei Cloud Object Storage Service Authorization.
///
/// - [User Signature Authentication](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0009.html)
pub struct Signer {
    credential_loader: CredentialLoader,
    time: Option<DateTime>,
    bucket: String,
}

impl Debug for Signer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signer")
    }
}

impl Signer {
    /// Create a builder.
    pub fn builder() -> Builder {
        Builder::default()
    }

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

        let string_to_sign = string_to_sign(&mut ctx, cred, now, method, &self.bucket)?;
        let signature = base64_hmac_sha1(cred.secret_key().as_bytes(), string_to_sign.as_bytes());

        match method {
            SigningMethod::Header => {
                ctx.headers.insert(DATE, format_http_date(now).parse()?);
                ctx.headers.insert(AUTHORIZATION, {
                    let mut value: HeaderValue =
                        format!("OBS {}:{}", cred.access_key(), signature).parse()?;
                    value.set_sensitive(true);

                    value
                });
            }
            SigningMethod::Query(expire) => {
                ctx.headers.insert(DATE, format_http_date(now).parse()?);
                ctx.query_push("AccessKeyId", cred.access_key());
                ctx.query_push("Expires", (now + expire).unix_timestamp().to_string());
                ctx.query_push(
                    "Signature",
                    utf8_percent_encode(&signature, percent_encoding::NON_ALPHANUMERIC).to_string(),
                )
            }
        }

        Ok(ctx)
    }

    /// Signing request.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use anyhow::Result;
    /// use reqsign::HuaweicloudObsSigner;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     // Signer will load region and credentials from environment by default.
    ///     let signer = HuaweicloudObsSigner::builder()
    ///         .access_key("access_key")
    ///         .secret_key("123456")
    ///         .bucket("bucket")
    ///         .build()?;
    ///     // Construct request
    ///     let url = Url::parse("https://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")?;
    ///     let mut req = Request::new(http::Method::GET, url);
    ///     // Signing request with Signer
    ///     signer.sign(&mut req)?;
    ///     // Sending already signed request.
    ///     let resp = Client::new().execute(req).await?;
    ///     println!("resp got status: {}", resp.status());
    ///     Ok(())
    /// }
    /// ```
    pub fn sign(&self, req: &mut impl SignableRequest) -> Result<()> {
        if let Some(cred) = self.credential() {
            let ctx = self.build(req, SigningMethod::Header, &cred)?;
            return req.apply(ctx);
        }

        Err(anyhow!("credential not found"))
    }

    /// Signing request with query.
    pub fn sign_query(&self, req: &mut impl SignableRequest, expire: Duration) -> Result<()> {
        if let Some(cred) = self.credential() {
            let ctx = self.build(req, SigningMethod::Query(expire), &cred)?;
            return req.apply(ctx);
        }

        Err(anyhow!("credential not found"))
    }
}

/// Construct string to sign
///
/// ## Format
///
/// ```text
/// VERB + "\n" +
/// Content-MD5 + "\n" +
/// Content-Type + "\n" +
/// Date + "\n" +
/// CanonicalizedHeaders +
/// CanonicalizedResource;
/// ```
///
/// ## Reference
///
/// - [User Signature Authentication (OBS)](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0009.html)
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

/// ## Reference
///
/// - [Authentication of Signature in a Header](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0010.html)
fn canonicalize_header(
    ctx: &mut SigningContext,
    method: SigningMethod,
    cred: &Credential,
) -> Result<String> {
    if method == SigningMethod::Header {
        // Insert security token
        if let Some(token) = cred.security_token() {
            ctx.headers.insert("x-obs-security-token", token.parse()?);
        }
    }

    Ok(SigningContext::header_to_string(
        ctx.header_to_vec_with_prefix("x-obs-"),
        "\n",
    ))
}

/// ## Reference
///
/// - [Authentication of Signature in a Header](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0010.html)
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

fn is_sub_resource(param: &str) -> bool {
    SUBRESOURCES.contains(param)
}

// Please attention: the subsources are case sensitive.
static SUBRESOURCES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "CDNNotifyConfiguration",
        "acl",
        "append",
        "attname",
        "backtosource",
        "cors",
        "customdomain",
        "delete",
        "deletebucket",
        "directcoldaccess",
        "encryption",
        "inventory",
        "length",
        "lifecycle",
        "location",
        "logging",
        "metadata",
        "modify",
        "name",
        "notification",
        "partNumber",
        "policy",
        "position",
        "quota",
        "rename",
        "replication",
        "response-cache-control",
        "response-content-disposition",
        "response-content-encoding",
        "response-content-language",
        "response-content-type",
        "response-expires",
        "restore",
        "storageClass",
        "storagePolicy",
        "storageinfo",
        "tagging",
        "torrent",
        "truncate",
        "uploadId",
        "uploads",
        "versionId",
        "versioning",
        "versions",
        "website",
        "x-image-process",
        "x-image-save-bucket",
        "x-image-save-object",
        "x-obs-security-token",
    ])
});

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ::time::UtcOffset;
    use anyhow::Result;
    use http::header::HeaderName;
    use http::Uri;

    use super::*;
    use crate::time::parse_rfc2822;

    #[test]
    fn test_sign() -> Result<()> {
        let signer = Signer::builder()
            .access_key("access_key")
            .secret_key("123456")
            .bucket("bucket")
            .time(
                parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?
                    .to_offset(UtcOffset::from_hms(0, 0, 0)?),
            )
            .build()?;

        let get_req = "http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt";
        let mut req = http::Request::get(Uri::from_str(get_req)?).body(())?;
        req.insert_header(
            HeaderName::from_str("Content-MD5")?,
            HeaderValue::from_str("abc")?,
        )?;
        req.insert_header(
            HeaderName::from_str("Content-Type")?,
            HeaderValue::from_str("text/plain")?,
        )?;

        // Signing request with Signer
        signer.sign(&mut req)?;
        let headers = req.headers();
        let auth = headers.get("Authorization").unwrap();

        // calculated from Huaweicloud OBS Signature tool
        // https://obs-community.obs.cn-north-1.myhuaweicloud.com/sign/header_signature.html
        assert_eq!(
            "OBS access_key:9gUZ4ol2W19LyYcc92Bu3U0V09E=",
            auth.to_str()?,
        );

        Ok(())
    }

    #[test]
    fn test_sign_with_subresource() -> Result<()> {
        let signer = Signer::builder()
            .access_key("access_key")
            .secret_key("123456")
            .bucket("bucket")
            .time(
                parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?
                    .to_offset(UtcOffset::from_hms(0, 0, 0)?),
            )
            .build()?;

        let get_req =
            "http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt?name=hello&abc=def";
        let mut req = http::Request::get(Uri::from_str(get_req)?).body(())?;
        req.insert_header(
            HeaderName::from_str("Content-MD5")?,
            HeaderValue::from_str("abc")?,
        )?;
        req.insert_header(
            HeaderName::from_str("Content-Type")?,
            HeaderValue::from_str("text/plain")?,
        )?;

        // Signing request with Signer
        signer.sign(&mut req)?;
        let headers = req.headers();
        let auth = headers.get("Authorization").unwrap();

        // calculated from Huaweicloud OBS Signature tool
        // https://obs-community.obs.cn-north-1.myhuaweicloud.com/sign/header_signature.html
        // CanonicalizedResource: /bucket/object.txt?name=hello
        assert_eq!(
            "OBS access_key:EaTKiO1Qh5KFUvWAVvbCNGktJUY=",
            auth.to_str()?,
        );

        Ok(())
    }

    #[test]
    fn test_sign_list_objects() -> Result<()> {
        let signer = Signer::builder()
            .access_key("access_key")
            .secret_key("123456")
            .bucket("bucket")
            .time(
                parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?
                    .to_offset(UtcOffset::from_hms(0, 0, 0)?),
            )
            .build()?;

        let get_req = "http://bucket.obs.cn-north-4.myhuaweicloud.com?name=hello&abc=def";
        let mut req = http::Request::get(Uri::from_str(get_req)?).body(())?;
        req.insert_header(
            HeaderName::from_str("Content-MD5")?,
            HeaderValue::from_str("abc")?,
        )?;
        req.insert_header(
            HeaderName::from_str("Content-Type")?,
            HeaderValue::from_str("text/plain")?,
        )?;

        // Signing request with Signer
        signer.sign(&mut req)?;
        let headers = req.headers();
        let auth = headers.get("Authorization").unwrap();

        // calculated from Huaweicloud OBS Signature tool
        // https://obs-community.obs.cn-north-1.myhuaweicloud.com/sign/header_signature.html
        // CanonicalizedResource: /bucket/?name=hello
        assert_eq!(
            "OBS access_key:9OdOsf8PRdhGhpkp7IIbKE0kRvA=",
            auth.to_str()?,
        );

        Ok(())
    }
}
