use std::borrow::Cow;
use std::fmt::Write;
use std::fmt::{Debug, Formatter};
use std::mem;
use std::sync::Arc;
use std::time::SystemTime;

use crate::hash::{base64_decode, base64_hmac_sha256};
use anyhow::{anyhow, Result};
use http::header::*;
use http::HeaderMap;
use log::debug;
use tokio::sync::RwLock;

use super::constants::*;
use super::credential::Credential;
use super::loader::*;
use crate::request::SignableRequest;
use crate::time::format;
use crate::time::RFC2822;

#[derive(Default)]
pub struct Builder {
    credential: Credential,
    credential_load: CredentialLoadChain,
}

impl Builder {
    pub fn account_key(&mut self, account_key: &str) -> &mut Self {
        self.credential.set_account_key(account_key);
        self
    }

    pub fn account_name(&mut self, account_name: &str) -> &mut Self {
        self.credential.set_account_name(account_name);
        self
    }

    pub fn credential_loader(&mut self, credential_load: CredentialLoadChain) -> &mut Self {
        self.credential_load = credential_load;
        self
    }

    pub async fn build(&mut self) -> Result<Signer> {
        let credential = if self.credential.is_valid() {
            Some(self.credential.clone())
        } else {
            // Make sure credential load chain has been set before checking.
            if self.credential_load.is_empty() {
                self.credential_load.push(EnvLoader::default());
            }

            self.credential_load.load_credential().await?
        };
        debug!("credential has been set to: {:?}", &credential);
        Ok(Signer {
            credential: Arc::new(RwLock::new(credential)),
            credential_load: mem::take(&mut self.credential_load),

            allow_anonymous: false,
        })
    }
}

#[derive(Default)]
pub struct Signer {
    credential: Arc<RwLock<Option<Credential>>>,
    credential_load: CredentialLoadChain,

    allow_anonymous: bool,
}

impl Debug for Signer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signer")
    }
}

impl Signer {
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Load credential via credential load chain specified while building.
    async fn credential(&self) -> Result<Option<Credential>> {
        // Return cached credential if it's valid.
        match self.credential.read().await.clone() {
            None => return Ok(None),
            Some(cred) => {
                if cred.is_valid() {
                    return Ok(Some(cred));
                }
            }
        }

        if let Some(cred) = self.credential_load.load_credential().await? {
            let mut lock = self.credential.write().await;
            *lock = Some(cred.clone());
            Ok(Some(cred))
        } else {
            // We used to get credential correctly, but now we can't.
            // Something must happened in the running environment.
            Err(anyhow!("credential should be loaded but not"))
        }
    }

    pub fn calculate(&self, req: &impl SignableRequest, cred: &Credential) -> Result<SignedOutput> {
        let string_to_sign = string_to_sign(req, cred)?;
        let auth = base64_hmac_sha256(
            &base64_decode(cred.account_key()),
            string_to_sign.as_bytes(),
        );

        Ok(SignedOutput {
            account_name: cred.account_key().to_string(),
            signed_time: SystemTime::now(),
            signature: auth,
        })
    }

    pub fn apply(&self, req: &mut impl SignableRequest, output: &SignedOutput) -> Result<()> {
        req.apply_header(
            HeaderName::from_static(super::constants::X_MS_DATE),
            &format(output.signed_time, &RFC2822 {}),
        )?;
        req.apply_header(
            HeaderName::from_static(super::constants::X_MS_VERSION),
            AZURE_VERSION,
        )?;
        req.apply_header(
            AUTHORIZATION,
            &format!("SharedKey {}:{}", &output.account_name, &output.signature),
        )?;

        Ok(())
    }

    pub async fn sign(&self, req: &mut impl SignableRequest) -> Result<()> {
        if let Some(cred) = self.credential().await? {
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

pub struct SignedOutput {
    account_name: String,
    signed_time: SystemTime,
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
fn string_to_sign(req: &impl SignableRequest, cred: &Credential) -> Result<String> {
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
    writeln!(&mut s, "{}", get_or_default(h, &CONTENT_ENCODING)?)?;
    writeln!(&mut s, "{}", get_or_default(h, &CONTENT_LANGUAGE)?)?;
    writeln!(
        &mut s,
        "{}",
        get_or_default(h, &CONTENT_LENGTH).map(|v| if v == "0" { "" } else { v })?
    )?;
    writeln!(&mut s, "{}", get_or_default(h, &CONTENT_MD5.parse()?)?)?;
    writeln!(&mut s, "{}", get_or_default(h, &CONTENT_TYPE)?)?;
    writeln!(&mut s, "{}", get_or_default(h, &DATE)?)?;
    writeln!(&mut s, "{}", get_or_default(h, &IF_MODIFIED_SINCE)?)?;
    writeln!(&mut s, "{}", get_or_default(h, &IF_MATCH)?)?;
    writeln!(&mut s, "{}", get_or_default(h, &IF_NONE_MATCH)?)?;
    writeln!(&mut s, "{}", get_or_default(h, &IF_UNMODIFIED_SINCE)?)?;
    writeln!(&mut s, "{}", get_or_default(h, &RANGE)?)?;
    writeln!(&mut s, "{}", canonicalize_header(req)?)?;
    write!(&mut s, "{}", canonicalize_resource(req, cred))?;

    Ok(s)
}

pub fn add_if_exists<K: AsHeaderName>(h: &HeaderMap, key: K) -> &str {
    match h.get(key) {
        Some(ce) => ce.to_str().unwrap(),
        None => "",
    }
}

/// ## Reference
///
/// - [Constructing the canonicalized headers string](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-headers-string)
fn canonicalize_header(req: &impl SignableRequest) -> Result<String> {
    let mut headers = req
        .headers()
        .iter()
        // Filter all header that starts with "x-ms-"
        .filter(|(k, _)| k.as_str().starts_with("x-ms-"))
        // Convert all header name to lowercase
        .map(|(k, v)| (k.as_str().to_lowercase(), v.clone()))
        .collect::<Vec<(String, HeaderValue)>>();
    // Sort via header name.
    headers.sort_by(|x, y| x.0.cmp(&y.0));

    Ok(headers
        .iter()
        // Format into "name:value"
        .map(|(k, v)| format!("{}:{}", k, v.to_str().expect("must be value header")))
        .collect::<Vec<String>>()
        // Join via "\n"
        .join("\n"))
}

/// ## Reference
///
/// - [Constructing the canonicalized resource string](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-resource-string)
fn canonicalize_resource(req: &impl SignableRequest, cred: &Credential) -> String {
    if req.query().is_none() {
        return format!("/{}{}", cred.account_name(), req.path());
    }

    let mut params: Vec<(Cow<'_, str>, Cow<'_, str>)> =
        form_urlencoded::parse(req.query().unwrap_or_default().as_bytes()).collect();
    // Sort by param name
    params.sort();

    format!(
        "/{}{}\n{}",
        cred.account_name(),
        req.path(),
        params
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<String>>()
            .join("\n")
    )
}
