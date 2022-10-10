//! Huawei Cloud Object Storage Service (OBS) signer
use std::borrow::Cow;
use std::fmt::Write;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Result};
use http::header::{HeaderName, AUTHORIZATION, CONTENT_TYPE, DATE};
use http::{HeaderMap, HeaderValue};
use log::debug;

use super::constants::CONTENT_MD5;
use super::loader::EnvLoader;
use super::subresource::is_subresource_param;
use crate::credential::Credential;
use crate::credential::CredentialLoad;
use crate::credential::CredentialLoadChain;
use crate::hash::base64_hmac_sha1;
use crate::request::SignableRequest;
use crate::time::{self, DateTime};

/// Builder for `Signer`.
#[derive(Default)]
pub struct Builder {
    credential: Credential,
    credential_load: CredentialLoadChain,

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

    /// Specify credential load behavior
    ///
    /// If not set, we will use the default credential loader.
    pub fn credential_loader(&mut self, credential_load: CredentialLoadChain) -> &mut Self {
        self.credential_load = credential_load;
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
        let credential = if self.credential.is_valid() {
            Some(self.credential.clone())
        } else {
            if self.credential_load.is_empty() {
                self.credential_load.push(EnvLoader::default());
            }
            self.credential_load.load_credential()?
        };

        debug!("signer credential: {:?}", &credential);

        let bucket = self
            .bucket
            .clone()
            .ok_or_else(|| anyhow!("bucket should not be none"))?;

        match credential {
            None => Err(anyhow!("credential is none")),
            Some(cred) => {
                if cred.is_valid() {
                    Ok(Signer {
                        credential: Arc::new(RwLock::new(cred)),
                        time: self.time,
                        bucket,
                    })
                } else {
                    Err(anyhow!("credential is invalid"))
                }
            }
        }
    }
}

/// Singer that implement Huawei Cloud Object Storage Service Authorization.
///
/// - [User Signature Authentication](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0009.html)
pub struct Signer {
    credential: Arc<RwLock<Credential>>,
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

    fn credential(&self) -> Credential {
        self.credential.read().expect("lock poisoned").clone()
    }

    fn calculate(&self, req: &impl SignableRequest, cred: &Credential) -> Result<SignedOutput> {
        let string_to_sign = string_to_sign(req, cred, &self.bucket)?;
        let auth = base64_hmac_sha1(cred.secret_key().as_bytes(), string_to_sign.as_bytes());

        Ok(SignedOutput {
            access_key: cred.access_key().to_string(),
            signature: auth,
        })
    }

    fn apply_before(&self, req: &mut impl SignableRequest) -> Result<()> {
        if !req.headers().contains_key(DATE) {
            let now = self.time.unwrap_or_else(time::now);
            let now_str = time::format_http_date(now);
            req.insert_header(DATE, HeaderValue::from_str(&now_str)?)?;
        }

        Ok(())
    }

    /// Apply signed results to requests.
    fn apply(&self, req: &mut impl SignableRequest, output: &SignedOutput) -> Result<()> {
        req.insert_header(AUTHORIZATION, {
            let mut value: HeaderValue =
                format!("OBS {}:{}", &output.access_key, output.signature).parse()?;
            value.set_sensitive(true);
            value
        })?;

        Ok(())
    }

    /// Signing request.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use anyhow::Result;
    /// use reqsign::huaweicloud::obs::Signer;
    /// use reqwest::{Client, Request, Url};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     // Signer will load region and credentials from environment by default.
    ///     let signer = Signer::builder()
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
        self.apply_before(req)?;
        let cred = self.credential();
        let sig = self.calculate(req, &cred)?;
        self.apply(req, &sig)
    }
}

/// Singed output carries result of this signing.
pub struct SignedOutput {
    access_key: String,
    signature: String,
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
fn string_to_sign(req: &impl SignableRequest, _cred: &Credential, bucket: &str) -> Result<String> {
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
    writeln!(&mut s, "{}", get_or_default(&h, &DATE)?)?;
    let canonicalize_header = canonicalize_header(req)?;
    if !canonicalize_header.is_empty() {
        writeln!(&mut s, "{}", canonicalize_header)?;
    }
    write!(&mut s, "{}", canonicalize_resource(req, bucket)?)?;

    debug!("string to sign: {}", &s);

    Ok(s)
}

/// ## Reference
///
/// - [Authentication of Signature in a Header](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0010.html)
fn canonicalize_header(req: &impl SignableRequest) -> Result<String> {
    let mut headers = req
        .headers()
        .iter()
        // Filter all header that starts with "x-obs-"
        .filter(|(k, _)| k.as_str().starts_with("x-obs-"))
        // Convert all header name to lowercase
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().expect("must be valid header").to_string(),
            )
        })
        .collect::<Vec<(String, String)>>();

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

/// ## Reference
///
/// - [Authentication of Signature in a Header](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0010.html)
fn canonicalize_resource(req: &impl SignableRequest, bucket: &str) -> Result<String> {
    let mut s = String::new();

    write!(&mut s, "/{}", bucket)?;
    write!(&mut s, "{}", req.path())?;

    let mut params: Vec<(Cow<'_, str>, Cow<'_, str>)> =
        form_urlencoded::parse(req.query().unwrap_or_default().as_bytes())
            .filter(|(k, _)| is_subresource_param(k))
            .collect();
    // Sort by param name
    params.sort();

    let params_str = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<String>>()
        .join("&");

    if !params_str.is_empty() {
        write!(s, "?{}", params_str)?;
    }

    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ::time::UtcOffset;

    use crate::time::parse_rfc2822;
    use anyhow::Result;
    use http::Uri;

    use super::*;

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
