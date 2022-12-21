//! Azure Storage Singer

use std::borrow::Cow;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Write;

use anyhow::anyhow;
use anyhow::Result;
use http::header::*;
use http::HeaderMap;
use log::debug;

use super::super::constants::*;
use super::credential::CredentialLoader;
use crate::credential::Credential;
use crate::hash::base64_decode;
use crate::hash::base64_hmac_sha256;
use crate::request::SignableRequest;
use crate::time::format_http_date;
use crate::time::DateTime;
use crate::time::{self};

/// Builder for `Signer`.
#[derive(Default)]
pub struct Builder {
    credential: Credential,

    time: Option<DateTime>,
}

impl Builder {
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

            time: self.time,
            allow_anonymous: false,
        })
    }
}

/// Singer that implement Azure Storage Shared Key Authorization.
///
/// - [Authorize with Shared Key](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key)
pub struct Signer {
    credential_loader: CredentialLoader,

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

    /// Calculate signing requests via SignableRequest.
    pub fn calculate(&self, req: &impl SignableRequest, cred: &Credential) -> Result<SignedOutput> {
        let now = self.time.unwrap_or_else(time::now);
        let string_to_sign = string_to_sign(req, cred, now)?;
        let auth = base64_hmac_sha256(&base64_decode(cred.secret_key()), string_to_sign.as_bytes());

        Ok(SignedOutput {
            account_name: cred.access_key().to_string(),
            signed_time: now,
            signature: auth,
        })
    }

    /// Apply signed results to requests.
    pub fn apply(&self, req: &mut impl SignableRequest, output: &SignedOutput) -> Result<()> {
        req.insert_header(
            HeaderName::from_static(X_MS_DATE),
            format_http_date(output.signed_time).parse()?,
        )?;
        req.insert_header(
            HeaderName::from_static(X_MS_VERSION),
            AZURE_VERSION.parse()?,
        )?;
        req.insert_header(AUTHORIZATION, {
            let mut value: HeaderValue =
                format!("SharedKey {}:{}", &output.account_name, &output.signature).parse()?;
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
            let sig = self.calculate(req, &cred)?;
            return self.apply(req, &sig);
        }

        if self.allow_anonymous {
            debug!("credential not found and anonymous is allowed, skipping signing.");
            return Ok(());
        }

        Err(anyhow!("credential not found"))
    }
}

/// Singed output carries result of this signing.
pub struct SignedOutput {
    account_name: String,
    signed_time: DateTime,
    signature: String,
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
///
/// ## Reference
///
/// - [Blob, Queue, and File Services (Shared Key authorization)](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key)
fn string_to_sign(req: &impl SignableRequest, cred: &Credential, now: DateTime) -> Result<String> {
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
    writeln!(&mut s, "{}", get_or_default(&h, &CONTENT_ENCODING)?)?;
    writeln!(&mut s, "{}", get_or_default(&h, &CONTENT_LANGUAGE)?)?;
    writeln!(
        &mut s,
        "{}",
        get_or_default(&h, &CONTENT_LENGTH).map(|v| if v == "0" { "" } else { v })?
    )?;
    writeln!(&mut s, "{}", get_or_default(&h, &CONTENT_MD5.parse()?)?)?;
    writeln!(&mut s, "{}", get_or_default(&h, &CONTENT_TYPE)?)?;
    writeln!(&mut s, "{}", get_or_default(&h, &DATE)?)?;
    writeln!(&mut s, "{}", get_or_default(&h, &IF_MODIFIED_SINCE)?)?;
    writeln!(&mut s, "{}", get_or_default(&h, &IF_MATCH)?)?;
    writeln!(&mut s, "{}", get_or_default(&h, &IF_NONE_MATCH)?)?;
    writeln!(&mut s, "{}", get_or_default(&h, &IF_UNMODIFIED_SINCE)?)?;
    writeln!(&mut s, "{}", get_or_default(&h, &RANGE)?)?;
    writeln!(&mut s, "{}", canonicalize_header(req, now)?)?;
    write!(&mut s, "{}", canonicalize_resource(req, cred))?;

    debug!("string to sign: {}", &s);

    Ok(s)
}

/// ## Reference
///
/// - [Constructing the canonicalized headers string](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-headers-string)
fn canonicalize_header(req: &impl SignableRequest, now: DateTime) -> Result<String> {
    let mut headers = req
        .headers()
        .iter()
        // Filter all header that starts with "x-ms-"
        .filter(|(k, _)| k.as_str().starts_with("x-ms-"))
        // Convert all header name to lowercase
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().expect("must be valid header").to_string(),
            )
        })
        .collect::<Vec<(String, String)>>();

    // Insert x_ms_date header.
    headers.push((X_MS_DATE.to_lowercase(), format_http_date(now)));

    // Insert x_ms_version header.
    headers.push((X_MS_VERSION.to_lowercase(), AZURE_VERSION.to_string()));

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
/// - [Constructing the canonicalized resource string](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-resource-string)
fn canonicalize_resource(req: &impl SignableRequest, cred: &Credential) -> String {
    if req.query().is_none() {
        return format!("/{}{}", cred.access_key(), req.path());
    }

    let mut params: Vec<(Cow<'_, str>, Cow<'_, str>)> =
        form_urlencoded::parse(req.query().unwrap_or_default().as_bytes()).collect();
    // Sort by param name
    params.sort();

    format!(
        "/{}{}\n{}",
        cred.access_key(),
        req.path(),
        params
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<String>>()
            .join("\n")
    )
}