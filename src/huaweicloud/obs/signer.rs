//! Huawei Cloud Object Storage Service (OBS) signer
use std::collections::HashSet;
use std::fmt::Debug;
use std::fmt::Write;
use std::time::Duration;

use anyhow::Result;
use http::header::AUTHORIZATION;
use http::header::CONTENT_TYPE;
use http::header::DATE;
use http::HeaderValue;
use log::debug;
use once_cell::sync::Lazy;
use percent_encoding::utf8_percent_encode;

use super::super::constants::*;
use super::credential::Credential;
use crate::ctx::SigningContext;
use crate::ctx::SigningMethod;
use crate::hash::base64_hmac_sha1;
use crate::request::SignableRequest;
use crate::time::format_http_date;
use crate::time::now;
use crate::time::DateTime;

/// Singer that implement Huawei Cloud Object Storage Service Authorization.
///
/// - [User Signature Authentication](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0009.html)
#[derive(Debug)]
pub struct Signer {
    bucket: String,

    time: Option<DateTime>,
}

impl Signer {
    /// Create a builder.
    pub fn new(bucket: &str) -> Self {
        Self {
            bucket: bucket.to_string(),
            time: None,
        }
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
        let now = self.time.unwrap_or_else(now);
        let mut ctx = req.build()?;

        let string_to_sign = string_to_sign(&mut ctx, cred, now, method, &self.bucket)?;
        let signature =
            base64_hmac_sha1(cred.secret_access_key.as_bytes(), string_to_sign.as_bytes());

        match method {
            SigningMethod::Header => {
                ctx.headers.insert(DATE, format_http_date(now).parse()?);
                ctx.headers.insert(AUTHORIZATION, {
                    let mut value: HeaderValue =
                        format!("OBS {}:{}", cred.access_key_id, signature).parse()?;
                    value.set_sensitive(true);

                    value
                });
            }
            SigningMethod::Query(expire) => {
                ctx.headers.insert(DATE, format_http_date(now).parse()?);
                ctx.query_push("AccessKeyId", &cred.access_key_id);
                ctx.query_push(
                    "Expires",
                    (now + chrono::Duration::from_std(expire).unwrap())
                        .timestamp()
                        .to_string(),
                );
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
    /// use reqsign::HuaweicloudObsConfig;
    /// use reqsign::HuaweicloudObsCredentialLoader;
    /// use reqsign::HuaweicloudObsSigner;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let loader = HuaweicloudObsCredentialLoader::new(HuaweicloudObsConfig::default());
    ///     let signer = HuaweicloudObsSigner::new("bucket");
    ///
    ///     // Construct request
    ///     let url = Url::parse("https://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")?;
    ///     let mut req = Request::new(http::Method::GET, url);
    ///     // Signing request with Signer
    ///     let credential = loader.load().await?.unwrap();
    ///     signer.sign(&mut req, &credential)?;
    ///     // Sending already signed request.
    ///     let resp = Client::new().execute(req).await?;
    ///     println!("resp got status: {}", resp.status());
    ///     Ok(())
    /// }
    /// ```
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
            writeln!(
                &mut s,
                "{}",
                (now + chrono::Duration::from_std(expires).unwrap()).timestamp()
            )?;
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
        if let Some(token) = &cred.security_token {
            ctx.headers.insert("x-obs-security-token", token.parse()?);
        }
    }

    Ok(SigningContext::header_to_string(
        ctx.header_to_vec_with_prefix("x-obs-"),
        ":",
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
        if let Some(token) = &cred.security_token {
            ctx.query
                .push(("security-token".to_string(), token.to_string()));
        };
    }

    let params = ctx.query_to_vec_with_filter(is_sub_resource);

    let params_str = SigningContext::query_to_string(params, "=", "&");

    if params_str.is_empty() {
        format!("/{bucket}{}", ctx.path)
    } else {
        format!("/{bucket}{}?{params_str}", ctx.path)
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

    use anyhow::Result;
    use chrono::Utc;
    use http::header::HeaderName;
    use http::Uri;

    use super::super::config::Config;
    use super::super::credential::CredentialLoader;
    use super::*;

    #[tokio::test]
    async fn test_sign() -> Result<()> {
        let config = Config {
            access_key_id: Some("access_key".to_string()),
            secret_access_key: Some("123456".to_string()),
            ..Default::default()
        };
        let loader = CredentialLoader::new(config);
        let cred = loader.load().await?.unwrap();

        let signer = Signer::new("bucket").with_time(
            chrono::DateTime::parse_from_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")
                .unwrap()
                .with_timezone(&Utc),
        );

        let get_req = "http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt";
        let mut req = http::Request::get(Uri::from_str(get_req)?).body(())?;
        req.headers_mut().insert(
            HeaderName::from_str("Content-MD5")?,
            HeaderValue::from_str("abc")?,
        );
        req.headers_mut().insert(
            HeaderName::from_str("Content-Type")?,
            HeaderValue::from_str("text/plain")?,
        );

        // Signing request with Signer
        signer.sign(&mut req, &cred)?;
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

    #[tokio::test]
    async fn test_sign_with_subresource() -> Result<()> {
        let config = Config {
            access_key_id: Some("access_key".to_string()),
            secret_access_key: Some("123456".to_string()),
            ..Default::default()
        };
        let loader = CredentialLoader::new(config);
        let cred = loader.load().await?.unwrap();

        let signer = Signer::new("bucket").with_time(
            chrono::DateTime::parse_from_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")
                .unwrap()
                .with_timezone(&Utc),
        );

        let get_req =
            "http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt?name=hello&abc=def";
        let mut req = http::Request::get(Uri::from_str(get_req)?).body(())?;
        req.headers_mut().insert(
            HeaderName::from_str("Content-MD5")?,
            HeaderValue::from_str("abc")?,
        );
        req.headers_mut().insert(
            HeaderName::from_str("Content-Type")?,
            HeaderValue::from_str("text/plain")?,
        );

        // Signing request with Signer
        signer.sign(&mut req, &cred)?;
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

    #[tokio::test]
    async fn test_sign_list_objects() -> Result<()> {
        let config = Config {
            access_key_id: Some("access_key".to_string()),
            secret_access_key: Some("123456".to_string()),
            ..Default::default()
        };
        let loader = CredentialLoader::new(config);
        let cred = loader.load().await?.unwrap();

        let signer = Signer::new("bucket").with_time(
            chrono::DateTime::parse_from_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")
                .unwrap()
                .with_timezone(&Utc),
        );

        let get_req = "http://bucket.obs.cn-north-4.myhuaweicloud.com?name=hello&abc=def";
        let mut req = http::Request::get(Uri::from_str(get_req)?).body(())?;
        req.headers_mut().insert(
            HeaderName::from_str("Content-MD5")?,
            HeaderValue::from_str("abc")?,
        );
        req.headers_mut().insert(
            HeaderName::from_str("Content-Type")?,
            HeaderValue::from_str("text/plain")?,
        );

        // Signing request with Signer
        signer.sign(&mut req, &cred)?;
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
