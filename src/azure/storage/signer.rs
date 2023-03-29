//! Azure Storage Singer

use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Write;

use ::time::Duration;
use anyhow::anyhow;
use anyhow::Result;
use http::header::*;
use log::debug;

use super::super::constants::*;
use super::credential::CredentialLoader;
use crate::credential::Credential;
use crate::ctx::SigningContext;
use crate::ctx::SigningMethod;
use crate::hash::base64_decode;
use crate::hash::base64_hmac_sha256;
use crate::request::SignableRequest;
use crate::time;
use crate::time::format_http_date;
use crate::time::DateTime;

/// Builder for `Signer`.
#[derive(Default, Clone)]
pub struct Builder {
    credential: Credential,
    allow_anonymous: bool,
    omit_service_version: bool,

    time: Option<DateTime>,
}

impl Builder {
    /// Allow anonymous access
    pub fn allow_anonymous(&mut self, value: bool) -> &mut Self {
        self.allow_anonymous = value;
        self
    }

    /// Specify account name.
    pub fn account_name(&mut self, account_name: &str) -> &mut Self {
        self.credential.set_access_key(account_name);
        self
    }

    /// Specify account key.
    pub fn account_key(&mut self, account_key: &str) -> &mut Self {
        self.credential.set_secret_key(account_key);
        self
    }

    /// set the signer to omitting service version
    pub fn omit_service_version(&mut self) -> &mut Self {
        self.omit_service_version = true;
        self
    }

    /// Specify a Shared Access Signature (SAS) token.
    /// * ref: [Grant limited access to Azure Storage resources using shared access signatures (SAS)](https://docs.microsoft.com/azure/storage/common/storage-sas-overview)
    /// * ref: [Create SAS tokens for storage containers](https://docs.microsoft.com/azure/applied-ai-services/form-recognizer/create-sas-tokens)
    pub fn security_token(&mut self, security_token: &str) -> &mut Self {
        self.credential.set_security_token(security_token);
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

    /// Use existing information to build a new signer.
    ///
    /// The builder should not be used anymore.
    pub fn build(&mut self) -> Result<Signer> {
        let mut cred_loader = CredentialLoader::default();
        if self.credential.is_valid() {
            cred_loader = cred_loader.with_credential(self.credential.clone());
        }

        Ok(Signer {
            credential_loader: cred_loader,

            omit_service_version: self.omit_service_version,
            time: self.time,
            allow_anonymous: self.allow_anonymous,
        })
    }
}

/// Singer that implement Azure Storage Shared Key Authorization.
///
/// - [Authorize with Shared Key](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key)
pub struct Signer {
    credential_loader: CredentialLoader,

    /// whether to omit service version or not
    omit_service_version: bool,
    /// Allow anonymous request if credential is not loaded.
    allow_anonymous: bool,
    time: Option<DateTime>,
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
        let mut ctx = req.build()?;

        match method {
            SigningMethod::Query(_) => {
                if let Some(token) = cred.security_token() {
                    ctx.query_append(token);
                } else {
                    return Err(anyhow!("SAS token is required for query signing"));
                }
            }
            SigningMethod::Header => {
                let now = self.time.unwrap_or_else(time::now);
                let string_to_sign =
                    string_to_sign(&mut ctx, cred, now, self.omit_service_version)?;
                let signature = base64_hmac_sha256(
                    &base64_decode(cred.secret_key()),
                    string_to_sign.as_bytes(),
                );

                ctx.headers.insert(AUTHORIZATION, {
                    let mut value: HeaderValue =
                        format!("SharedKey {}:{signature}", cred.access_key()).parse()?;
                    value.set_sensitive(true);

                    value
                });
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
    /// use reqsign::AzureStorageSigner;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     // Signer will load region and credentials from environment by default.
    ///     let signer = AzureStorageSigner::builder()
    ///         .account_name("account_name")
    ///         .account_key("YWNjb3VudF9rZXkK")
    ///         .build()?;
    ///     // Construct request
    ///     let url = Url::parse("https://test.blob.core.windows.net/testbucket/testblob")?;
    ///     let mut req = reqwest::Request::new(http::Method::GET, url);
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

        if self.allow_anonymous {
            debug!("credential not found and anonymous is allowed, skipping signing.");
            return Ok(());
        }

        Err(anyhow!("credential not found"))
    }

    /// Signing request with query.
    pub fn sign_query(&self, req: &mut impl SignableRequest) -> Result<()> {
        if let Some(cred) = self.credential() {
            let ctx = self.build(req, SigningMethod::Query(Duration::seconds(1)), &cred)?;
            return req.apply(ctx);
        }

        if self.allow_anonymous {
            debug!("credential not found and anonymous is allowed, skipping signing.");
            return Ok(());
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
fn string_to_sign(
    ctx: &mut SigningContext,
    cred: &Credential,
    now: DateTime,
    omit_service_version: bool,
) -> Result<String> {
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
    writeln!(
        &mut s,
        "{}",
        canonicalize_header(ctx, now, omit_service_version)?
    )?;
    write!(&mut s, "{}", canonicalize_resource(ctx, cred))?;

    debug!("string to sign: {}", &s);

    Ok(s)
}

/// ## Reference
///
/// - [Constructing the canonicalized headers string](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-headers-string)
fn canonicalize_header(
    ctx: &mut SigningContext,
    now: DateTime,
    omit_service_version: bool,
) -> Result<String> {
    ctx.headers
        .insert(X_MS_DATE, format_http_date(now).parse()?);
    if !omit_service_version {
        // Insert x_ms_version header.
        ctx.headers
            .insert(X_MS_VERSION, AZURE_VERSION.to_string().parse()?);
    }

    Ok(SigningContext::header_to_string(
        ctx.header_to_vec_with_prefix("x-ms-"),
        ":",
        "\n",
    ))
}

/// ## Reference
///
/// - [Constructing the canonicalized resource string](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-resource-string)
fn canonicalize_resource(ctx: &mut SigningContext, cred: &Credential) -> String {
    if ctx.query.is_empty() {
        return format!("/{}{}", cred.access_key(), ctx.path);
    }

    format!(
        "/{}{}\n{}",
        cred.access_key(),
        ctx.path,
        SigningContext::query_to_string(ctx.query.clone(), ":", "\n")
    )
}

#[cfg(test)]
mod tests {
    use http::Request;

    use crate::AzureStorageSigner;

    #[test]
    pub fn test_sas_url() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = AzureStorageSigner::builder()
            .security_token("sv=2021-01-01&ss=b&srt=c&sp=rwdlaciytfx&se=2022-01-01T11:00:14Z&st=2022-01-02T03:00:14Z&spr=https&sig=KEllk4N8f7rJfLjQCmikL2fRVt%2B%2Bl73UBkbgH%2FK3VGE%3D")
            .build()
            .unwrap();
        // Construct request
        let mut req = Request::builder()
            .uri("https://test.blob.core.windows.net/testbucket/testblob")
            .body(())
            .unwrap();

        // Signing request with Signer
        assert!(signer.sign_query(&mut req).is_ok());
        assert_eq!(req.uri(), "https://test.blob.core.windows.net/testbucket/testblob?sv=2021-01-01&ss=b&srt=c&sp=rwdlaciytfx&se=2022-01-01T11:00:14Z&st=2022-01-02T03:00:14Z&spr=https&sig=KEllk4N8f7rJfLjQCmikL2fRVt%2B%2Bl73UBkbgH%2FK3VGE%3D")
    }

    #[test]
    pub fn test_anonymous() {
        let signer = AzureStorageSigner::builder()
            .allow_anonymous(true)
            .build()
            .unwrap();
        // Construct request
        let mut req = Request::builder()
            .uri("https://test.blob.core.windows.net/testbucket/testblob")
            .body(())
            .unwrap();

        // Signing request with Signer
        assert!(signer.sign(&mut req).is_ok());
        assert_eq!(
            req.uri(),
            "https://test.blob.core.windows.net/testbucket/testblob"
        )
    }
}
