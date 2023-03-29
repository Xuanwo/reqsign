use std::borrow::Cow;

use anyhow::anyhow;
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
use super::credential::CredentialLoader;
use super::credential::Token;
use super::credential::TokenLoad;
use crate::ctx::SigningContext;
use crate::ctx::SigningMethod;
use crate::hash::hex_sha256;
use crate::request::SignableRequest;
use crate::time;
use crate::time::format_date;
use crate::time::format_iso8601;
use crate::time::DateTime;
use crate::time::Duration;

/// Builder for Signer.
#[derive(Default)]
pub struct Builder {
    scope: Option<String>,
    service_account: Option<String>,

    credential_path: Option<String>,
    credential_content: Option<String>,

    service: Option<String>,
    region: Option<String>,
    time: Option<DateTime>,

    allow_anonymous: bool,
    disable_load_from_env: bool,
    disable_load_from_well_known_location: bool,
    disable_load_from_vm_metadata: bool,
    customed_token_loader: Option<Box<dyn TokenLoad>>,
}

impl Builder {
    /// Specify scope for Signer.
    ///
    /// For example, valid scopes for google cloud services should be
    ///
    /// - read-only: `https://www.googleapis.com/auth/devstorage.read_only`
    /// - read-write: `https://www.googleapis.com/auth/devstorage.read_write`
    /// - full-control: `https://www.googleapis.com/auth/devstorage.full_control`
    ///
    /// Reference: [Cloud Storage authentication](https://cloud.google.com/storage/docs/authentication)
    pub fn scope(&mut self, scope: &str) -> &mut Self {
        self.scope = Some(scope.to_string());
        self
    }

    /// Specify service account for Signer.
    ///
    /// If not set, use `default` instead.
    pub fn service_account(&mut self, service_account: &str) -> &mut Self {
        self.service_account = Some(service_account.to_string());
        self
    }

    /// Load credential from path.
    ///
    /// The credential should be generated by Google Cloud Platform.
    ///
    /// # Notes
    ///
    /// We will load from default credential by default, `credential_path`
    /// only used to for user customed credential path.
    ///
    /// Read more in [Authenticating as a service account](https://cloud.google.com/docs/authentication/production)
    pub fn credential_path(&mut self, path: &str) -> &mut Self {
        self.credential_path = Some(path.to_string());
        self
    }

    /// Load credential from base64 content.
    ///
    /// The credential should be generated by Google Cloud Platform.
    ///
    /// # Notes
    ///
    /// We will load from default credential by default, `credential_content`
    /// only used to for user customed credential content.
    ///
    /// Read more in [Authenticating as a service account](https://cloud.google.com/docs/authentication/production)
    pub fn credential_content(&mut self, credential: &str) -> &mut Self {
        self.credential_content = Some(credential.to_string());
        self
    }

    /// Set customed token loader for builder.
    ///
    /// We will load token from customed_token_loader first if set.
    pub fn customed_token_loader(&mut self, f: impl TokenLoad) -> &mut Self {
        self.customed_token_loader = Some(Box::new(f));
        self
    }

    /// Set the service name that used for google v4 signing.
    ///
    /// Default to `storage`
    pub fn service(&mut self, service: &str) -> &mut Self {
        self.service = Some(service.to_string());
        self
    }

    /// Set the region name that used for google v4 signing.
    ///
    /// Default to `auto`
    pub fn region(&mut self, region: &str) -> &mut Self {
        self.region = Some(region.to_string());
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
    ///
    /// The builder should not be used anymore.
    pub fn build(&mut self) -> Result<Signer> {
        let scope = match &self.scope {
            Some(v) => v.clone(),
            None => return Err(anyhow!("google signer requires scope, but not set")),
        };

        let mut cred_loader = if let Some(path) = &self.credential_path {
            CredentialLoader::from_path(path)?
        } else if let Some(content) = &self.credential_content {
            CredentialLoader::from_base64(content)?
        } else {
            CredentialLoader::default()
        };
        cred_loader = cred_loader.with_scope(&scope);

        if self.disable_load_from_env {
            cred_loader = cred_loader.with_disable_env();
        }
        if self.disable_load_from_well_known_location {
            cred_loader = cred_loader.with_disable_well_known_location();
        }
        if self.disable_load_from_vm_metadata {
            cred_loader = cred_loader.with_disable_vm_metadata();
        }
        if self.allow_anonymous {
            cred_loader = cred_loader.with_allow_anonymous();
        }
        if let Some(acc) = &self.service_account {
            cred_loader = cred_loader.with_service_account(acc);
        }
        if let Some(f) = self.customed_token_loader.take() {
            cred_loader = cred_loader.with_customed_token_loader(f);
        }

        Ok(Signer {
            credential_loader: cred_loader,
            allow_anonymous: self.allow_anonymous,
            service: self
                .service
                .clone()
                .unwrap_or_else(|| "storage".to_string()),
            region: self.region.clone().unwrap_or_else(|| "auto".to_string()),
            time: self.time,
        })
    }
}

/// Singer that implement Google OAuth2 Authentication.
///
/// ## Reference
///
/// -  [Authenticating as a service account](https://cloud.google.com/docs/authentication/production)
pub struct Signer {
    credential_loader: CredentialLoader,

    /// Allow anonymous request if credential is not loaded.
    allow_anonymous: bool,

    service: String,
    region: String,
    time: Option<DateTime>,
}

impl Signer {
    /// Create a builder of Signer.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Load credential via credential load chain specified while building.
    ///
    /// # Note
    ///
    /// This function should never be exported to avoid credential leaking by
    /// mistake.
    fn token(&self) -> Option<Token> {
        self.credential_loader.load()
    }

    fn credential(&self) -> Option<Credential> {
        self.credential_loader.load_credential()
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
        cred: &Credential,
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
            f.push_str(&format_iso8601(now));
            f.push_str(&scope);
            f.push_str(&encoded_req);
            f
        };
        debug!("calculated string to sign: {string_to_sign}");

        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(cred.private_key())?;
        let signing_key = SigningKey::<rsa::sha2::Sha256>::new_with_prefix(private_key);
        let signature = signing_key.sign_with_rng(&mut rng, string_to_sign.as_bytes());

        ctx.query
            .push(("X-Goog-Signature".to_string(), signature.to_string()));

        Ok(ctx)
    }

    /// Signing request.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use anyhow::Result;
    /// use reqsign::GoogleSigner;
    /// use reqwest::Client;
    /// use reqwest::Request;
    /// use reqwest::Url;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     // Signer will load region and credentials from environment by default.
    ///     let signer = GoogleSigner::builder()
    ///         .scope("https://www.googleapis.com/auth/devstorage.read_only")
    ///         .build()?;
    ///
    ///     // Construct request
    ///     let url = Url::parse("https://storage.googleapis.com/storage/v1/b/test")?;
    ///     let mut req = reqwest::Request::new(http::Method::GET, url);
    ///
    ///     // Signing request with Signer
    ///     signer.sign(&mut req)?;
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
    pub fn sign(&self, req: &mut impl SignableRequest) -> Result<()> {
        if let Some(token) = self.token() {
            let ctx = self.build_header(req, &token)?;
            return req.apply(ctx);
        }

        if self.allow_anonymous {
            debug!("credential not found and anonymous is allowed, skipping signing.");
            return Ok(());
        }

        Err(anyhow!("token not found"))
    }

    /// Sign the query with a duration.
    ///
    /// # Example
    /// ```no_run
    /// use time::Duration;
    /// use anyhow::Result;
    /// use reqsign::GoogleSigner;
    /// use reqwest::{Client, Url};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     // Signer will load region and credentials from environment by default.
    ///     let signer = GoogleSigner::builder()
    ///         .credential_path("/Users/wolfv/Downloads/noted-throne-361708-bf95cdbf3fea.json")
    ///         .scope("storage")
    ///         .build()?;
    ///
    ///     // Construct request
    ///     let url = Url::parse("https://storage.googleapis.com/testbucket-reqsign/CONTRIBUTING.md")?;
    ///     let mut req = reqwest::Request::new(http::Method::GET, url);
    ///
    ///     // Signing request with Signer
    ///     signer.sign_query(&mut req, Duration::hours(1))?;
    ///
    ///     println!("signed request: {:?}", req);
    ///     // Sending already signed request.
    ///     let resp = Client::new().execute(req).await?;
    ///     println!("resp got status: {}", resp.status());
    ///     println!("resp got body: {}", resp.text().await?);
    ///     Ok(())
    /// }
    /// ```
    pub fn sign_query(&self, req: &mut impl SignableRequest, duration: Duration) -> Result<()> {
        if let Some(cred) = self.credential() {
            let ctx = self.build_query(req, duration, &cred)?;
            return req.apply(ctx);
        }

        if self.allow_anonymous {
            debug!("credential not found and anonymous is allowed, skipping signing.");
            return Ok(());
        }

        Err(anyhow!("token not found"))
    }
}

fn canonical_request_string(ctx: &mut SigningContext) -> Result<String> {
    // 256 is specially chosen to avoid reallocation for most requests.
    let mut f = String::with_capacity(256);

    // Insert method
    f.push_str(ctx.method.as_str());
    // Insert encoded path
    let path = percent_decode_str(&ctx.path).decode_utf8()?;
    f.push_str(&Cow::from(utf8_percent_encode(
        &path,
        &super::constants::GOOG_URI_ENCODE_SET,
    )));
    // Insert query
    f.push_str(&SigningContext::query_to_string(
        ctx.query.clone(),
        "=",
        "&",
    ));

    // Insert signed headers
    let signed_headers = ctx.header_name_to_vec_sorted();
    for header in signed_headers.iter() {
        let value = &ctx.headers[*header];
        f.push_str(header);
        f.push(':');
        f.push_str(value.to_str().expect("header value must be valid"));
    }
    f.push('\n');
    f.push_str(&signed_headers.join(";"));
    f.push_str("UNSIGNED-PAYLOAD");

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
    cred: &Credential,
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
                cred.client_email(),
                format_date(now),
                region,
                service
            ),
        ));
        ctx.query.push(("X-Goog-Date".into(), format_iso8601(now)));
        ctx.query
            .push(("X-Goog-Expires".into(), expire.whole_seconds().to_string()));
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
    use reqwest::blocking::Client;

    use crate::time::parse_rfc2822;
    use pretty_assertions::assert_eq;

    use super::*;

    #[derive(Debug)]
    struct TestLoader {
        client: Client,
    }

    impl TokenLoad for TestLoader {
        fn load_token(&self) -> Result<Option<Token>> {
            self.client.get("https://xuanwo.io").send()?;
            Ok(None)
        }
    }

    #[test]
    fn test_with_customed_token_loader() -> Result<()> {
        let client = Client::default();

        let _ = Builder::default()
            .scope("test")
            .customed_token_loader(TestLoader { client })
            .build()?;

        Ok(())
    }

    #[test]
    fn test_sign_query() -> Result<()> {
        let credential_path = format!(
            "{}/testdata/services/google/testbucket_credential.json",
            std::env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );

        let signer = Signer::builder()
            .credential_path(&credential_path)
            .scope("storage")
            .build()?;

        let mut req = http::Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "https://storage.googleapis.com/testbucket-reqsign/CONTRIBUTING.md"
            .parse()
            .expect("url must be valid");

        signer.sign_query(&mut req, time::Duration::hours(1))?;

        let query = req.query().unwrap();
        assert!(query.contains("X-Goog-Algorithm=GOOG4-RSA-SHA256"));
        assert!(query.contains("X-Goog-Credential"));

        Ok(())
    }

    #[test]
    fn test_sign_query_deterministic() -> Result<()> {
        let credential_path = format!(
            "{}/testdata/services/google/testbucket_credential.json",
            std::env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );

        let mut req = http::Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "https://storage.googleapis.com/testbucket-reqsign/CONTRIBUTING.md"
            .parse()
            .expect("url must be valid");

        let time_offset =
            parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?.to_offset(::time::UtcOffset::UTC);

        let signer = Signer::builder()
            .credential_path(&credential_path)
            .scope("storage")
            .time(time_offset)
            .build()?;

        signer.sign_query(&mut req, time::Duration::hours(1))?;

        let query = req.query().unwrap();
        assert!(query.contains("X-Goog-Algorithm=GOOG4-RSA-SHA256"));
        assert!(query.contains("X-Goog-Credential"));
        assert_eq!(query, "X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=testbucket-reqsign-account%40iam-testbucket-reqsign-project.iam.gserviceaccount.com%2F20220815%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20220815T165012Z&X-Goog-Expires=3600&X-Goog-SignedHeaders=host&X-Goog-Signature=9F423139DB223D818F2D4D6BCA4916DD1EE5AEB8E72D99EC60E8B903DC3CF0586C27A0F821C8CB20C6BB76C776E63134DAFF5957E7862BB89926F18E0D3618E4EE40EF8DBEC64D87F5AD4CAF6FE4C2BC3239E1076A33BE3113D6E0D1AF263C16FA5E1C9590C8F8E4E2CA2FED11533607B5AFE84B53E2E00CB320E0BC853C138EBBDCFEC3E9219C73551478EE12AABBD2576686F887738A21DC5AE00DFF3D481BD08F642342C8CCB476E74C8FEA0C02BA6FEFD61300218D6E216EAD4B59F3351E456601DF38D1CC1B4CE639D2748739933672A08B5FEBBED01B5BC0785E81A865EE0252A0C5AE239061F3F5DB4AFD8CC676646750C762A277FBFDE70A85DFDF33");
        Ok(())
    }
}
