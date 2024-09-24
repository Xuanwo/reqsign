//! Azure Storage Signer

use std::fmt::Debug;
use std::fmt::Write;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Result;
use http::header::*;
use log::debug;
use percent_encoding::percent_encode;

use super::credential::Credential;
use crate::account_sas;
use crate::constants::*;
use reqsign_core::hash::base64_decode;
use reqsign_core::hash::base64_hmac_sha256;
use reqsign_core::time;
use reqsign_core::time::format_http_date;
use reqsign_core::time::DateTime;
use reqsign_core::SigningMethod;
use reqsign_core::SigningRequest;

/// Signer that implement Azure Storage Shared Key Authorization.
///
/// - [Authorize with Shared Key](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key)
#[derive(Debug, Default)]
pub struct Signer {
    time: Option<DateTime>,
}

impl Signer {
    /// Create a signer.
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
    pub fn time(&mut self, time: DateTime) -> &mut Self {
        self.time = Some(time);
        self
    }

    fn build(
        &self,
        parts: &mut http::request::Parts,
        method: SigningMethod,
        cred: &Credential,
    ) -> Result<SigningRequest> {
        let mut ctx = SigningRequest::build(parts)?;

        match cred {
            Credential::SharedAccessSignature(token) => {
                ctx.query_append(token);
                return Ok(ctx);
            }
            Credential::BearerToken(token, _) => match method {
                SigningMethod::Query(_) => {
                    return Err(anyhow!("BearerToken can't be used in query string"));
                }
                SigningMethod::Header => {
                    ctx.headers
                        .insert(X_MS_DATE, format_http_date(time::now()).parse()?);
                    ctx.headers.insert(AUTHORIZATION, {
                        let mut value: HeaderValue = format!("Bearer {}", token).parse()?;
                        value.set_sensitive(true);
                        value
                    });
                }
            },
            Credential::SharedKey(ak, sk) => match method {
                SigningMethod::Query(d) => {
                    // try sign request use account_sas token
                    let signer = account_sas::AccountSharedAccessSignature::new(
                        ak.to_string(),
                        sk.to_string(),
                        time::now() + chrono::TimeDelta::from_std(d)?,
                    );
                    let signer_token = signer.token()?;
                    signer_token.iter().for_each(|(k, v)| {
                        ctx.query_push(k, v);
                    });
                }
                SigningMethod::Header => {
                    let now = self.time.unwrap_or_else(time::now);
                    let string_to_sign = string_to_sign(&mut ctx, ak, now)?;
                    let decode_content = base64_decode(sk)?;
                    let signature = base64_hmac_sha256(&decode_content, string_to_sign.as_bytes());

                    ctx.headers.insert(AUTHORIZATION, {
                        let mut value: HeaderValue =
                            format!("SharedKey {ak}:{signature}").parse()?;
                        value.set_sensitive(true);

                        value
                    });
                }
            },
        }

        Ok(ctx)
    }

    /// Signing request.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use anyhow::Result;
    /// use reqsign_azure_storage::Config;
    /// use reqsign_azure_storage::Loader;
    /// use reqsign_azure_storage::Signer;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let config = Config {
    ///         account_name: Some("account_name".to_string()),
    ///         account_key: Some("YWNjb3VudF9rZXkK".to_string()),
    ///         ..Default::default()
    ///     };
    ///     let loader = Loader::new(config);
    ///     let signer = Signer::new();
    ///     // Construct request
    ///     let mut req = http::Request::get("https://test.blob.core.windows.net/testbucket/testblob").body(reqwest::Body::default())?;
    ///     // Signing request with Signer
    ///     let credential = loader.load().await?.unwrap();
    ///
    ///     let (mut parts, body) = req.into_parts();
    ///     signer.sign(&mut parts, &credential)?;
    ///     let req = http::Request::from_parts(parts, body).try_into()?;
    ///
    ///     // Sending already signed request.
    ///     let resp = Client::new().execute(req).await?;
    ///     println!("resp got status: {}", resp.status());
    ///     Ok(())
    /// }
    /// ```
    pub fn sign(&self, parts: &mut http::request::Parts, cred: &Credential) -> Result<()> {
        let mut ctx = self.build(parts, SigningMethod::Header, cred)?;

        for (_, v) in ctx.query.iter_mut() {
            *v = percent_encode(v.as_bytes(), &AZURE_QUERY_ENCODE_SET).to_string();
        }
        ctx.apply(parts)
    }

    /// Signing request with query.
    pub fn sign_query(
        &self,
        parts: &mut http::request::Parts,
        expire: Duration,
        cred: &Credential,
    ) -> Result<()> {
        let ctx = self.build(parts, SigningMethod::Query(expire), cred)?;
        ctx.apply(parts)
    }
}

/// Construct string to sign
///
/// ## Format
///
/// ```text
/// VERB + "\n" +
/// Content-Encoding + "\n" +
/// Content-Language + "\n" +
/// Content-Length + "\n" +
/// Content-MD5 + "\n" +
/// Content-Type + "\n" +
/// Date + "\n" +
/// If-Modified-Since + "\n" +
/// If-Match + "\n" +
/// If-None-Match + "\n" +
/// If-Unmodified-Since + "\n" +
/// Range + "\n" +
/// CanonicalizedHeaders +
/// CanonicalizedResource;
/// ```
/// ## Note
/// For sub-requests of batch API, requests should be signed without `x-ms-version` header.
/// Set the `omit_service_version` to `ture` for such.
///
/// ## Reference
///
/// - [Blob, Queue, and File Services (Shared Key authorization)](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key)
fn string_to_sign(ctx: &mut SigningRequest, ak: &str, now: DateTime) -> Result<String> {
    let mut s = String::with_capacity(128);

    writeln!(&mut s, "{}", ctx.method.as_str())?;
    writeln!(&mut s, "{}", ctx.header_get_or_default(&CONTENT_ENCODING)?)?;
    writeln!(&mut s, "{}", ctx.header_get_or_default(&CONTENT_LANGUAGE)?)?;
    writeln!(
        &mut s,
        "{}",
        ctx.header_get_or_default(&CONTENT_LENGTH)
            .map(|v| if v == "0" { "" } else { v })?
    )?;
    writeln!(
        &mut s,
        "{}",
        ctx.header_get_or_default(&CONTENT_MD5.parse()?)?
    )?;
    writeln!(&mut s, "{}", ctx.header_get_or_default(&CONTENT_TYPE)?)?;
    writeln!(&mut s, "{}", ctx.header_get_or_default(&DATE)?)?;
    writeln!(&mut s, "{}", ctx.header_get_or_default(&IF_MODIFIED_SINCE)?)?;
    writeln!(&mut s, "{}", ctx.header_get_or_default(&IF_MATCH)?)?;
    writeln!(&mut s, "{}", ctx.header_get_or_default(&IF_NONE_MATCH)?)?;
    writeln!(
        &mut s,
        "{}",
        ctx.header_get_or_default(&IF_UNMODIFIED_SINCE)?
    )?;
    writeln!(&mut s, "{}", ctx.header_get_or_default(&RANGE)?)?;
    writeln!(&mut s, "{}", canonicalize_header(ctx, now)?)?;
    write!(&mut s, "{}", canonicalize_resource(ctx, ak))?;

    debug!("string to sign: {}", &s);

    Ok(s)
}

/// ## Reference
///
/// - [Constructing the canonicalized headers string](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-headers-string)
fn canonicalize_header(ctx: &mut SigningRequest, now: DateTime) -> Result<String> {
    ctx.headers
        .insert(X_MS_DATE, format_http_date(now).parse()?);

    Ok(SigningRequest::header_to_string(
        ctx.header_to_vec_with_prefix("x-ms-"),
        ":",
        "\n",
    ))
}

/// ## Reference
///
/// - [Constructing the canonicalized resource string](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-resource-string)
fn canonicalize_resource(ctx: &mut SigningRequest, ak: &str) -> String {
    if ctx.query.is_empty() {
        return format!("/{}{}", ak, ctx.path);
    }

    let query = ctx
        .query
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    format!(
        "/{}{}\n{}",
        ak,
        ctx.path,
        SigningRequest::query_to_percent_decoded_string(query, ":", "\n")
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http::Request;

    use super::super::config::Config;
    use crate::Credential;
    use crate::Loader;
    use crate::Signer;
    use reqsign_core::time::now;

    #[tokio::test]
    async fn test_sas_url() {
        let _ = env_logger::builder().is_test(true).try_init();

        let config = Config {
            sas_token: Some("sv=2021-01-01&ss=b&srt=c&sp=rwdlaciytfx&se=2022-01-01T11:00:14Z&st=2022-01-02T03:00:14Z&spr=https&sig=KEllk4N8f7rJfLjQCmikL2fRVt%2B%2Bl73UBkbgH%2FK3VGE%3D".to_string()),
            ..Default::default()
        };

        let loader = Loader::new(config);
        let cred = loader.load().await.unwrap().unwrap();

        let signer = Signer::new();

        // Construct request
        let req = Request::builder()
            .uri("https://test.blob.core.windows.net/testbucket/testblob")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();

        // Signing request with Signer
        assert!(signer
            .sign_query(&mut parts, Duration::from_secs(1), &cred)
            .is_ok());
        assert_eq!(parts.uri, "https://test.blob.core.windows.net/testbucket/testblob?sv=2021-01-01&ss=b&srt=c&sp=rwdlaciytfx&se=2022-01-01T11:00:14Z&st=2022-01-02T03:00:14Z&spr=https&sig=KEllk4N8f7rJfLjQCmikL2fRVt%2B%2Bl73UBkbgH%2FK3VGE%3D")
    }

    #[tokio::test]
    async fn test_can_sign_request_use_bearer_token() {
        let signer = Signer::new();
        let req = Request::builder()
            .uri("https://test.blob.core.windows.net/testbucket/testblob")
            .body(())
            .unwrap();
        let cred = Credential::BearerToken("token".to_string(), now());
        let (mut parts, _) = req.into_parts();

        // Can effectively sign request with SigningMethod::Header
        assert!(signer.sign(&mut parts, &cred).is_ok());
        let authorization = parts
            .headers
            .get("Authorization")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!("Bearer token", authorization);

        // Will not sign request with SigningMethod::Query
        parts.headers = http::header::HeaderMap::new();
        assert!(signer
            .sign_query(&mut parts, Duration::from_secs(1), &cred)
            .is_err());
    }
}
