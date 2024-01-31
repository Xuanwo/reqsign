//! Azure Storage Singer

use std::fmt::Debug;
use std::fmt::Write;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Result;
use http::header::*;
use log::debug;
use percent_encoding::percent_encode;

use super::super::constants::*;
use super::credential::Credential;
use crate::azure::storage::sas::account_sas;
use crate::ctx::SigningContext;
use crate::ctx::SigningMethod;
use crate::hash::base64_decode;
use crate::hash::base64_hmac_sha256;
use crate::request::SignableRequest;
use crate::time;
use crate::time::format_http_date;
use crate::time::DateTime;

/// Singer that implement Azure Storage Shared Key Authorization.
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
        req: &mut impl SignableRequest,
        method: SigningMethod,
        cred: &Credential,
    ) -> Result<SigningContext> {
        let mut ctx = req.build()?;

        match cred {
            Credential::SharedAccessSignature(token) => {
                ctx.query_append(token);
                return Ok(ctx);
            }
            Credential::BearerToken(token) => match method {
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
                        time::now() + chrono::Duration::from_std(d)?,
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
    /// use reqsign::AzureStorageConfig;
    /// use reqsign::AzureStorageLoader;
    /// use reqsign::AzureStorageSigner;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let config = AzureStorageConfig {
    ///         account_name: Some("account_name".to_string()),
    ///         account_key: Some("YWNjb3VudF9rZXkK".to_string()),
    ///         ..Default::default()
    ///     };
    ///     let loader = AzureStorageLoader::new(config);
    ///     let signer = AzureStorageSigner::new();
    ///     // Construct request
    ///     let url = Url::parse("https://test.blob.core.windows.net/testbucket/testblob")?;
    ///     let mut req = reqwest::Request::new(http::Method::GET, url);
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
        let mut ctx = self.build(req, SigningMethod::Header, cred)?;

        for (_, v) in ctx.query.iter_mut() {
            *v = percent_encode(v.as_bytes(), &AZURE_QUERY_ENCODE_SET).to_string();
        }
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
fn string_to_sign(ctx: &mut SigningContext, ak: &str, now: DateTime) -> Result<String> {
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
fn canonicalize_header(ctx: &mut SigningContext, now: DateTime) -> Result<String> {
    ctx.headers
        .insert(X_MS_DATE, format_http_date(now).parse()?);

    Ok(SigningContext::header_to_string(
        ctx.header_to_vec_with_prefix("x-ms-"),
        ":",
        "\n",
    ))
}

/// ## Reference
///
/// - [Constructing the canonicalized resource string](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-resource-string)
fn canonicalize_resource(ctx: &mut SigningContext, ak: &str) -> String {
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
        SigningContext::query_to_percent_decoded_string(query, ":", "\n")
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http::Request;

    use super::super::config::Config;
    use crate::azure::storage::loader::Loader;
    use crate::AzureStorageCredential;
    use crate::AzureStorageSigner;

    #[tokio::test]
    async fn test_sas_url() {
        let _ = env_logger::builder().is_test(true).try_init();

        let config = Config {
            sas_token: Some("sv=2021-01-01&ss=b&srt=c&sp=rwdlaciytfx&se=2022-01-01T11:00:14Z&st=2022-01-02T03:00:14Z&spr=https&sig=KEllk4N8f7rJfLjQCmikL2fRVt%2B%2Bl73UBkbgH%2FK3VGE%3D".to_string()),
            ..Default::default()
        };

        let loader = Loader::new(config);
        let cred = loader.load().await.unwrap().unwrap();

        let signer = AzureStorageSigner::new();

        // Construct request
        let mut req = Request::builder()
            .uri("https://test.blob.core.windows.net/testbucket/testblob")
            .body(())
            .unwrap();

        // Signing request with Signer
        assert!(signer
            .sign_query(&mut req, Duration::from_secs(1), &cred)
            .is_ok());
        assert_eq!(req.uri(), "https://test.blob.core.windows.net/testbucket/testblob?sv=2021-01-01&ss=b&srt=c&sp=rwdlaciytfx&se=2022-01-01T11:00:14Z&st=2022-01-02T03:00:14Z&spr=https&sig=KEllk4N8f7rJfLjQCmikL2fRVt%2B%2Bl73UBkbgH%2FK3VGE%3D")
    }

    #[tokio::test]
    async fn test_can_sign_request_use_bearer_token() {
        let signer = AzureStorageSigner::new();
        let mut req = Request::builder()
            .uri("https://test.blob.core.windows.net/testbucket/testblob")
            .body(())
            .unwrap();
        let cred = AzureStorageCredential::BearerToken("token".to_string());

        // Can effectively sign request with SigningMethod::Header
        assert!(signer.sign(&mut req, &cred).is_ok());
        let authorization = req
            .headers()
            .get("Authorization")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!("Bearer token", authorization);

        // Will not sign request with SigningMethod::Query
        *req.headers_mut() = http::header::HeaderMap::new();
        assert!(signer
            .sign_query(&mut req, Duration::from_secs(1), &cred)
            .is_err());
    }
}
