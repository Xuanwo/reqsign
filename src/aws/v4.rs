//! AWS service sigv4 signer

use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Write;

use anyhow::anyhow;
use anyhow::Result;
use http::header;
use http::HeaderValue;
use log::debug;
use percent_encoding::percent_decode_str;
use percent_encoding::utf8_percent_encode;

use super::config::ConfigLoader;
use super::constants::AWS_QUERY_ENCODE_SET;
use super::constants::X_AMZ_CONTENT_SHA_256;
use super::constants::X_AMZ_DATE;
use super::constants::X_AMZ_SECURITY_TOKEN;
use super::credential::CredentialLoader;
use super::region::RegionLoader;
use crate::credential::Credential;
use crate::ctx::SigningContext;
use crate::ctx::SigningMethod;
use crate::hash::hex_hmac_sha256;
use crate::hash::hex_sha256;
use crate::hash::hmac_sha256;
use crate::request::SignableRequest;
use crate::time::format_date;
use crate::time::format_iso8601;
use crate::time::DateTime;
use crate::time::Duration;
use crate::time::{self};

/// Builder for `Signer`.
#[derive(Default)]
pub struct Builder {
    service: Option<String>,

    config_loader: ConfigLoader,
    credential_loader: Option<CredentialLoader>,
    allow_anonymous: bool,

    time: Option<DateTime>,
}

impl Builder {
    /// Specify service like "s3".
    pub fn service(&mut self, service: &str) -> &mut Self {
        self.service = Some(service.to_string());
        self
    }

    /// Set the config loader used by builder.
    ///
    /// # Notes
    ///
    /// Signer will only read data from it, it's your responsible to decide
    /// whether or not to call `ConfigLoader::load()`.
    ///
    /// If `load` is called, ConfigLoader will load config from current env.
    /// If not, ConfigLoader will only use static config that set by users.
    pub fn config_loader(&mut self, cfg: ConfigLoader) -> &mut Self {
        self.config_loader = cfg;
        self
    }

    /// Allow anonymous request if credential is not loaded.
    pub fn allow_anonymous(&mut self) -> &mut Self {
        self.allow_anonymous = true;
        self
    }

    /// Set credential loader
    pub fn credential_loader(&mut self, cred: CredentialLoader) -> &mut Self {
        self.credential_loader = Some(cred);
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
        let service = self
            .service
            .as_ref()
            .ok_or_else(|| anyhow!("service is required"))?;
        debug!("signer: service: {:?}", service);

        let cred_loader = match self.credential_loader.take() {
            Some(cred) => cred,
            None => {
                let mut loader = CredentialLoader::new(self.config_loader.clone());
                if self.allow_anonymous {
                    loader = loader.with_allow_anonymous();
                }
                loader
            }
        };

        let region_loader = RegionLoader::new(self.config_loader.clone());

        let region = region_loader
            .load()
            .ok_or_else(|| anyhow!("region is missing"))?;
        debug!("signer region: {}", &region);

        Ok(Signer {
            service: service.to_string(),
            region,
            credential_loader: cred_loader,
            allow_anonymous: self.allow_anonymous,
            time: self.time,
        })
    }
}

/// Singer that implement AWS SigV4.
///
/// - [Signature Version 4 signing process](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
pub struct Signer {
    service: String,
    region: String,
    credential_loader: CredentialLoader,

    /// Allow anonymous request if credential is not loaded.
    allow_anonymous: bool,

    time: Option<DateTime>,
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
        let now = self.time.unwrap_or_else(time::now);
        let mut ctx = req.build()?;

        // canonicalize context
        canonicalize_header(&mut ctx, method, cred, now)?;
        canonicalize_query(&mut ctx, method, cred, now, &self.service, &self.region)?;

        // build canonical request and string to sign.
        let creq = canonical_request_string(&mut ctx)?;
        let encoded_req = hex_sha256(creq.as_bytes());

        // Scope: "20220313/<region>/<service>/aws4_request"
        let scope = format!(
            "{}/{}/{}/aws4_request",
            format_date(now),
            self.region,
            self.service
        );
        debug!("calculated scope: {scope}");

        // StringToSign:
        //
        // AWS4-HMAC-SHA256
        // 20220313T072004Z
        // 20220313/<region>/<service>/aws4_request
        // <hashed_canonical_request>
        let string_to_sign = {
            let mut f = String::new();
            writeln!(f, "AWS4-HMAC-SHA256")?;
            writeln!(f, "{}", format_iso8601(now))?;
            writeln!(f, "{}", &scope)?;
            write!(f, "{}", &encoded_req)?;
            f
        };
        debug!("calculated string to sign: {string_to_sign}");

        let signing_key = generate_signing_key(cred.secret_key(), now, &self.region, &self.service);
        let signature = hex_hmac_sha256(&signing_key, string_to_sign.as_bytes());

        match method {
            SigningMethod::Header => {
                let mut authorization = HeaderValue::from_str(&format!(
                    "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
                    cred.access_key(),
                    scope,
                    ctx.header_names_to_vec_sorted().join(";"),
                    signature
                ))?;
                authorization.set_sensitive(true);

                ctx.headers
                    .insert(http::header::AUTHORIZATION, authorization);
            }
            SigningMethod::Query(_) => {
                ctx.query.push(("X-Amz-Signature".into(), signature));
            }
        }

        Ok(ctx)
    }

    /// Get the region of this signer.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Signing request with header.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use anyhow::Result;
    /// use reqsign::AwsConfigLoader;
    /// use reqsign::AwsV4Signer;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     // Signer will load region and credentials from environment by default.
    ///     let signer = AwsV4Signer::builder()
    ///         .config_loader(AwsConfigLoader::with_loaded())
    ///         .service("s3")
    ///         .allow_anonymous()
    ///         .build()?;
    ///     // Construct request
    ///     let url = Url::parse("https://s3.amazonaws.com/testbucket")?;
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
    ///
    /// # Example
    ///
    /// ```no_run
    /// use anyhow::Result;
    /// use reqsign::AwsConfigLoader;
    /// use reqsign::AwsV4Signer;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
    /// use time::Duration;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     // Signer will load region and credentials from environment by default.
    ///     let signer = AwsV4Signer::builder()
    ///         .config_loader(AwsConfigLoader::with_loaded())
    ///         .service("s3")
    ///         .allow_anonymous()
    ///         .build()?;
    ///     // Construct request
    ///     let url = Url::parse("https://s3.amazonaws.com/testbucket")?;
    ///     let mut req = reqwest::Request::new(http::Method::GET, url);
    ///     // Signing request with Signer
    ///     signer.sign_query(&mut req, Duration::hours(1))?;
    ///     // Sending already signed request.
    ///     let resp = Client::new().execute(req).await?;
    ///     println!("resp got status: {}", resp.status());
    ///     Ok(())
    /// }
    /// ```
    pub fn sign_query(&self, req: &mut impl SignableRequest, expire: Duration) -> Result<()> {
        if let Some(cred) = self.credential() {
            let ctx = self.build(req, SigningMethod::Query(expire), &cred)?;
            return req.apply(ctx);
        }

        if self.allow_anonymous {
            debug!("credential not found and anonymous is allowed, skipping signing.");
            return Ok(());
        }

        Err(anyhow!("credential not found"))
    }
}

impl Debug for Signer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Signer {{ region: {}, service: {}, allow_anonymous: {} }}",
            self.region, self.service, self.allow_anonymous
        )
    }
}

fn canonical_request_string(ctx: &mut SigningContext) -> Result<String> {
    // 256 is specially chosen to avoid reallocation for most requests.
    let mut f = String::with_capacity(256);

    // Insert method
    writeln!(f, "{}", ctx.method)?;
    // Insert encoded path
    let path = percent_decode_str(&ctx.path).decode_utf8()?;
    writeln!(
        f,
        "{}",
        utf8_percent_encode(&path, &super::constants::AWS_URI_ENCODE_SET)
    )?;
    // Insert query
    writeln!(
        f,
        "{}",
        ctx.query
            .iter()
            .map(|(k, v)| { format!("{k}={v}") })
            .collect::<Vec<_>>()
            .join("&")
    )?;
    // Insert signed headers
    let signed_headers = ctx.header_names_to_vec_sorted();
    for header in signed_headers.iter() {
        let value = &ctx.headers[*header];
        writeln!(
            f,
            "{}:{}",
            header,
            value.to_str().expect("header value must be valid")
        )?;
    }
    writeln!(f)?;
    writeln!(f, "{}", signed_headers.join(";"))?;
    // TODO: we should support user specify payload hash.
    write!(f, "UNSIGNED-PAYLOAD")?;

    Ok(f)
}

fn canonicalize_header(
    ctx: &mut SigningContext,
    method: SigningMethod,
    cred: &Credential,
    now: DateTime,
) -> Result<()> {
    // Header names and values need to be normalized according to Step 4 of https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    for (_, value) in ctx.headers.iter_mut() {
        SigningContext::header_value_normalize(value)
    }

    // Insert HOST header if not present.
    if ctx.headers.get(header::HOST).is_none() {
        ctx.headers
            .insert(header::HOST, ctx.authority.as_str().parse()?);
    }

    if method == SigningMethod::Header {
        // Insert DATE header if not present.
        if ctx.headers.get(X_AMZ_DATE).is_none() {
            let date_header = HeaderValue::try_from(format_iso8601(now))?;
            ctx.headers.insert(X_AMZ_DATE, date_header);
        }

        // Insert X_AMZ_CONTENT_SHA_256 header if not present.
        if ctx.headers.get(X_AMZ_CONTENT_SHA_256).is_none() {
            ctx.headers.insert(
                X_AMZ_CONTENT_SHA_256,
                HeaderValue::from_static("UNSIGNED-PAYLOAD"),
            );
        }

        // Insert X_AMZ_SECURITY_TOKEN header if security token exists.
        if let Some(token) = cred.security_token() {
            let mut value = HeaderValue::from_str(token)?;
            // Set token value sensitive to valid leaking.
            value.set_sensitive(true);

            ctx.headers.insert(X_AMZ_SECURITY_TOKEN, value);
        }
    }

    Ok(())
}

fn canonicalize_query(
    ctx: &mut SigningContext,
    method: SigningMethod,
    cred: &Credential,
    now: DateTime,
    service: &str,
    region: &str,
) -> Result<()> {
    if let SigningMethod::Query(expire) = method {
        ctx.query
            .push(("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()));
        ctx.query.push((
            "X-Amz-Credential".into(),
            format!(
                "{}/{}/{}/{}/aws4_request",
                cred.access_key(),
                format_date(now),
                region,
                service
            ),
        ));
        ctx.query.push(("X-Amz-Date".into(), format_iso8601(now)));
        ctx.query
            .push(("X-Amz-Expires".into(), expire.whole_seconds().to_string()));
        ctx.query.push((
            "X-Amz-SignedHeaders".into(),
            ctx.header_names_to_vec_sorted().join(";"),
        ));

        if let Some(token) = cred.security_token() {
            ctx.query
                .push(("X-Amz-Security-Token".into(), token.into()));
        }
    }

    // Return if query is empty.
    if ctx.query.is_empty() {
        return Ok(());
    }

    // Sort by param name
    ctx.query.sort();

    ctx.query = ctx
        .query
        .iter()
        .map(|(k, v)| {
            (
                utf8_percent_encode(k, &AWS_QUERY_ENCODE_SET).to_string(),
                utf8_percent_encode(v, &AWS_QUERY_ENCODE_SET).to_string(),
            )
        })
        .collect();

    Ok(())
}

fn generate_signing_key(secret: &str, time: DateTime, region: &str, service: &str) -> Vec<u8> {
    // Sign secret
    let secret = format!("AWS4{secret}");
    // Sign date
    let sign_date = hmac_sha256(secret.as_bytes(), format_date(time).as_bytes());
    // Sign region
    let sign_region = hmac_sha256(sign_date.as_slice(), region.as_bytes());
    // Sign service
    let sign_service = hmac_sha256(sign_region.as_slice(), service.as_bytes());
    // Sign request
    let sign_request = hmac_sha256(sign_service.as_slice(), "aws4_request".as_bytes());

    sign_request
}
