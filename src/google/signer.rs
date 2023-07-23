use std::borrow::Cow;
use std::time::Duration;

use anyhow::Result;
use http::header;
use log::debug;
use percent_encoding::percent_decode_str;
use percent_encoding::utf8_percent_encode;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::RandomizedSigner;

use super::constants::GOOG_QUERY_ENCODE_SET;
use super::credential::Credential;
use super::credential::ServiceAccount;
use super::token::Token;
use crate::ctx::SigningContext;
use crate::ctx::SigningMethod;
use crate::hash::hex_sha256;
use crate::request::SignableRequest;
use crate::time;
use crate::time::format_date;
use crate::time::format_iso8601;
use crate::time::DateTime;

/// Singer that implement Google OAuth2 Authentication.
///
/// ## Reference
///
/// -  [Authenticating as a service account](https://cloud.google.com/docs/authentication/production)
pub struct Signer {
    service: String,
    region: String,
    time: Option<DateTime>,
}

impl Signer {
    /// Create a builder of Signer.
    pub fn new(service: &str) -> Self {
        Self {
            service: service.to_string(),
            region: "auto".to_string(),
            time: None,
        }
    }

    /// Set the region name that used for google v4 signing.
    ///
    /// Default to `auto`
    pub fn region(&mut self, region: &str) -> &mut Self {
        self.region = region.to_string();
        self
    }

    /// Specify the signing time.
    ///
    /// # Note
    ///
    /// We should always take current time to sign requests.
    /// Only use this function for testing.
    #[cfg(test)]
    pub fn time(mut self, time: DateTime) -> Self {
        self.time = Some(time);
        self
    }

    fn build_header(
        &self,
        req: &mut impl SignableRequest,
        token: &Token,
    ) -> Result<SigningContext> {
        let mut ctx = req.build()?;

        ctx.headers.insert(header::AUTHORIZATION, {
            let mut value: http::HeaderValue =
                format!("Bearer {}", token.access_token()).parse()?;
            value.set_sensitive(true);

            value
        });

        Ok(ctx)
    }

    fn build_query(
        &self,
        req: &mut impl SignableRequest,
        expire: Duration,
        cred: &ServiceAccount,
    ) -> Result<SigningContext> {
        let mut ctx = req.build()?;

        let now = self.time.unwrap_or_else(time::now);

        // canonicalize context
        canonicalize_header(&mut ctx)?;
        canonicalize_query(
            &mut ctx,
            SigningMethod::Query(expire),
            cred,
            now,
            &self.service,
            &self.region,
        )?;

        // build canonical request and string to sign.
        let creq = canonical_request_string(&mut ctx)?;
        let encoded_req = hex_sha256(creq.as_bytes());

        // Scope: "20220313/<region>/<service>/goog4_request"
        let scope = format!(
            "{}/{}/{}/goog4_request",
            format_date(now),
            self.region,
            self.service
        );
        debug!("calculated scope: {scope}");

        // StringToSign:
        //
        // GOOG4-RSA-SHA256
        // 20220313T072004Z
        // 20220313/<region>/<service>/goog4_request
        // <hashed_canonical_request>
        let string_to_sign = {
            let mut f = String::new();
            f.push_str("GOOG4-RSA-SHA256");
            f.push('\n');
            f.push_str(&format_iso8601(now));
            f.push('\n');
            f.push_str(&scope);
            f.push('\n');
            f.push_str(&encoded_req);

            f
        };
        debug!("calculated string to sign: {string_to_sign}");

        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(&cred.private_key)?;
        let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
        let signature = signing_key.sign_with_rng(&mut rng, string_to_sign.as_bytes());

        ctx.query
            .push(("X-Goog-Signature".to_string(), signature.to_string()));

        Ok(ctx)
    }

    /// Signing request.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use anyhow::Result;
    /// use reqsign::GoogleSigner;
    /// use reqsign::GoogleTokenLoader;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     // Signer will load region and credentials from environment by default.
    ///     let token_loader = GoogleTokenLoader::new(
    ///         "https://www.googleapis.com/auth/devstorage.read_only",
    ///         Client::new(),
    ///     );
    ///     let signer = GoogleSigner::new("storage");
    ///
    ///     // Construct request
    ///     let url = Url::parse("https://storage.googleapis.com/storage/v1/b/test")?;
    ///     let mut req = reqwest::Request::new(http::Method::GET, url);
    ///
    ///     // Signing request with Signer
    ///     let token = token_loader.load().await?.unwrap();
    ///     signer.sign(&mut req, &token)?;
    ///
    ///     // Sending already signed request.
    ///     let resp = Client::new().execute(req).await?;
    ///     println!("resp got status: {}", resp.status());
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # TODO
    ///
    /// we can also send API via signed JWT: [Addendum: Service account authorization without OAuth](https://developers.google.com/identity/protocols/oauth2/service-account#jwt-auth)
    pub fn sign(&self, req: &mut impl SignableRequest, token: &Token) -> Result<()> {
        let ctx = self.build_header(req, token)?;
        req.apply(ctx)
    }

    /// Sign the query with a duration.
    ///
    /// # Example
    /// ```rust,no_run
    /// use std::time::Duration;
    ///
    /// use anyhow::Result;
    /// use reqsign::GoogleCredentialLoader;
    /// use reqsign::GoogleSigner;
    /// use reqwest::Client;
    /// use reqwest::Url;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     // Signer will load region and credentials from environment by default.
    ///     let credential_loader = GoogleCredentialLoader::default();
    ///     let signer = GoogleSigner::new("stroage");
    ///
    ///     // Construct request
    ///     let url = Url::parse("https://storage.googleapis.com/testbucket-reqsign/CONTRIBUTING.md")?;
    ///     let mut req = reqwest::Request::new(http::Method::GET, url);
    ///
    ///     // Signing request with Signer
    ///     let credential = credential_loader.load()?.unwrap();
    ///     signer.sign_query(&mut req, Duration::from_secs(3600), &credential)?;
    ///
    ///     println!("signed request: {:?}", req);
    ///     // Sending already signed request.
    ///     let resp = Client::new().execute(req).await?;
    ///     println!("resp got status: {}", resp.status());
    ///     println!("resp got body: {}", resp.text().await?);
    ///     Ok(())
    /// }
    /// ```
    pub fn sign_query(
        &self,
        req: &mut impl SignableRequest,
        duration: Duration,
        cred: &Credential,
    ) -> Result<()> {
        let Some(cred) = &cred.service_account else {
            anyhow::bail!("expected service account credential, got external account");
        };

        let ctx = self.build_query(req, duration, cred)?;
        req.apply(ctx)
    }
}

fn canonical_request_string(ctx: &mut SigningContext) -> Result<String> {
    // 256 is specially chosen to avoid reallocation for most requests.
    let mut f = String::with_capacity(256);

    // Insert method
    f.push_str(ctx.method.as_str());
    f.push('\n');

    // Insert encoded path
    let path = percent_decode_str(&ctx.path).decode_utf8()?;
    f.push_str(&Cow::from(utf8_percent_encode(
        &path,
        &super::constants::GOOG_URI_ENCODE_SET,
    )));
    f.push('\n');

    // Insert query
    f.push_str(&SigningContext::query_to_string(
        ctx.query.clone(),
        "=",
        "&",
    ));
    f.push('\n');

    // Insert signed headers
    let signed_headers = ctx.header_name_to_vec_sorted();
    for header in signed_headers.iter() {
        let value = &ctx.headers[*header];
        f.push_str(header);
        f.push(':');
        f.push_str(value.to_str().expect("header value must be valid"));
        f.push('\n');
    }
    f.push('\n');
    f.push_str(&signed_headers.join(";"));
    f.push('\n');
    f.push_str("UNSIGNED-PAYLOAD");

    debug!("string to sign: {}", f);
    Ok(f)
}

fn canonicalize_header(ctx: &mut SigningContext) -> Result<()> {
    for (_, value) in ctx.headers.iter_mut() {
        SigningContext::header_value_normalize(value)
    }

    // Insert HOST header if not present.
    if ctx.headers.get(header::HOST).is_none() {
        ctx.headers
            .insert(header::HOST, ctx.authority.as_str().parse()?);
    }

    Ok(())
}

fn canonicalize_query(
    ctx: &mut SigningContext,
    method: SigningMethod,
    cred: &ServiceAccount,
    now: DateTime,
    service: &str,
    region: &str,
) -> Result<()> {
    if let SigningMethod::Query(expire) = method {
        ctx.query
            .push(("X-Goog-Algorithm".into(), "GOOG4-RSA-SHA256".into()));
        ctx.query.push((
            "X-Goog-Credential".into(),
            format!(
                "{}/{}/{}/{}/goog4_request",
                &cred.client_email,
                format_date(now),
                region,
                service
            ),
        ));
        ctx.query.push(("X-Goog-Date".into(), format_iso8601(now)));
        ctx.query
            .push(("X-Goog-Expires".into(), expire.as_secs().to_string()));
        ctx.query.push((
            "X-Goog-SignedHeaders".into(),
            ctx.header_name_to_vec_sorted().join(";"),
        ));
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
                utf8_percent_encode(k, &GOOG_QUERY_ENCODE_SET).to_string(),
                utf8_percent_encode(v, &GOOG_QUERY_ENCODE_SET).to_string(),
            )
        })
        .collect();

    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use pretty_assertions::assert_eq;

    use super::super::credential::CredentialLoader;
    use super::*;

    #[tokio::test]
    async fn test_sign_query() -> Result<()> {
        let credential_path = format!(
            "{}/testdata/services/google/testbucket_credential.json",
            std::env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );

        let loader = CredentialLoader::default().with_path(&credential_path);
        let cred = loader.load()?.unwrap();

        let signer = Signer::new("storage");

        let mut req = http::Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "https://storage.googleapis.com/testbucket-reqsign/CONTRIBUTING.md"
            .parse()
            .expect("url must be valid");

        signer.sign_query(&mut req, Duration::from_secs(3600), &cred)?;

        let query = req.uri().query().unwrap();
        assert!(query.contains("X-Goog-Algorithm=GOOG4-RSA-SHA256"));
        assert!(query.contains("X-Goog-Credential"));

        Ok(())
    }

    #[tokio::test]
    async fn test_sign_query_deterministic() -> Result<()> {
        let credential_path = format!(
            "{}/testdata/services/google/testbucket_credential.json",
            std::env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );

        let loader = CredentialLoader::default().with_path(&credential_path);
        let cred = loader.load()?.unwrap();

        let mut req = http::Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "https://storage.googleapis.com/testbucket-reqsign/CONTRIBUTING.md"
            .parse()
            .expect("url must be valid");

        let time_offset = chrono::DateTime::parse_from_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")
            .unwrap()
            .with_timezone(&Utc);

        let signer = Signer::new("storage").time(time_offset);

        signer.sign_query(&mut req, Duration::from_secs(3600), &cred)?;

        let query = req.uri().query().unwrap();
        assert!(query.contains("X-Goog-Algorithm=GOOG4-RSA-SHA256"));
        assert!(query.contains("X-Goog-Credential"));
        assert_eq!(query, "X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=testbucket-reqsign-account%40iam-testbucket-reqsign-project.iam.gserviceaccount.com%2F20220815%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20220815T165012Z&X-Goog-Expires=3600&X-Goog-SignedHeaders=host&X-Goog-Signature=9F423139DB223D818F2D4D6BCA4916DD1EE5AEB8E72D99EC60E8B903DC3CF0586C27A0F821C8CB20C6BB76C776E63134DAFF5957E7862BB89926F18E0D3618E4EE40EF8DBEC64D87F5AD4CAF6FE4C2BC3239E1076A33BE3113D6E0D1AF263C16FA5E1C9590C8F8E4E2CA2FED11533607B5AFE84B53E2E00CB320E0BC853C138EBBDCFEC3E9219C73551478EE12AABBD2576686F887738A21DC5AE00DFF3D481BD08F642342C8CCB476E74C8FEA0C02BA6FEFD61300218D6E216EAD4B59F3351E456601DF38D1CC1B4CE639D2748739933672A08B5FEBBED01B5BC0785E81A865EE0252A0C5AE239061F3F5DB4AFD8CC676646750C762A277FBFDE70A85DFDF33");
        Ok(())
    }
}
