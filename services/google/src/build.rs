use std::time::Duration;
use anyhow::Result;
use http::header;
use log::debug;
use percent_encoding::{percent_decode_str, utf8_percent_encode};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::RandomizedSigner;
use rand::thread_rng;
use std::borrow::Cow;

use reqsign_core::{
    hash::hex_sha256, time::*, Build as BuildTrait, Context, SigningMethod, SigningRequest,
};

use crate::constants::{GOOG_QUERY_ENCODE_SET, GOOG_URI_ENCODE_SET};
use crate::key::{Credential, ServiceAccount, Token};

/// Builder for Google service requests.
#[derive(Debug)]
pub struct Builder {
    service: String,
    region: String,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            service: String::new(),
            region: "auto".to_string(),
        }
    }
}

impl Builder {
    /// Create a new builder with the specified service.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            region: "auto".to_string(),
        }
    }

    /// Set the region for the builder.
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = region.into();
        self
    }

    fn build_token_auth(
        &self,
        parts: &mut http::request::Parts,
        token: &Token,
    ) -> Result<SigningRequest> {
        let mut req = SigningRequest::build(parts)?;

        req.headers.insert(header::AUTHORIZATION, {
            let mut value: http::HeaderValue =
                format!("Bearer {}", &token.access_token).parse()?;
            value.set_sensitive(true);
            value
        });

        Ok(req)
    }

    fn build_signed_query(
        &self,
        _ctx: &Context,
        parts: &mut http::request::Parts,
        service_account: &ServiceAccount,
        expires_in: Duration,
    ) -> Result<SigningRequest> {
        let mut req = SigningRequest::build(parts)?;
        let now = now();

        // Canonicalize headers
        canonicalize_header(&mut req)?;
        
        // Canonicalize query
        canonicalize_query(
            &mut req,
            SigningMethod::Query(expires_in),
            service_account,
            now,
            &self.service,
            &self.region,
        )?;

        // Build canonical request string
        let creq = canonical_request_string(&mut req)?;
        let encoded_req = hex_sha256(creq.as_bytes());

        // Build scope
        let scope = format!(
            "{}/{}/{}/goog4_request",
            format_date(now),
            self.region,
            self.service
        );
        debug!("calculated scope: {scope}");

        // Build string to sign
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

        // Sign the string
        let mut rng = thread_rng();
        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(&service_account.private_key)?;
        let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
        let signature = signing_key.sign_with_rng(&mut rng, string_to_sign.as_bytes());

        req.query
            .push(("X-Goog-Signature".to_string(), signature.to_string()));

        Ok(req)
    }
}

#[async_trait::async_trait]
impl BuildTrait for Builder {
    type Key = Credential;

    async fn build(
        &self,
        ctx: &Context,
        req: &mut http::request::Parts,
        key: Option<&Self::Key>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let key = key.ok_or_else(|| anyhow::anyhow!("missing credential"))?;

        let signing_req = match (key, expires_in) {
            (Credential::Token(token), None) => {
                // Use token authentication
                self.build_token_auth(req, token)?
            }
            (Credential::ServiceAccount(sa), Some(expires)) => {
                // Use signed query for service account with expiration
                self.build_signed_query(ctx, req, sa, expires)?
            }
            (Credential::ServiceAccount(_), None) => {
                return Err(anyhow::anyhow!(
                    "service account requires expires_in for signing"
                ));
            }
            (Credential::Token(_), Some(_)) => {
                return Err(anyhow::anyhow!(
                    "token authentication does not support expires_in"
                ));
            }
        };

        signing_req.apply(req)
    }
}

fn canonical_request_string(req: &mut SigningRequest) -> Result<String> {
    // 256 is specially chosen to avoid reallocation for most requests.
    let mut f = String::with_capacity(256);

    // Insert method
    f.push_str(req.method.as_str());
    f.push('\n');

    // Insert encoded path
    let path = percent_decode_str(&req.path).decode_utf8()?;
    f.push_str(&Cow::from(utf8_percent_encode(&path, &GOOG_URI_ENCODE_SET)));
    f.push('\n');

    // Insert query
    f.push_str(&SigningRequest::query_to_string(
        req.query.clone(),
        "=",
        "&",
    ));
    f.push('\n');

    // Insert signed headers
    let signed_headers = req.header_name_to_vec_sorted();
    for header in signed_headers.iter() {
        let value = &req.headers[*header];
        f.push_str(header);
        f.push(':');
        f.push_str(value.to_str().expect("header value must be valid"));
        f.push('\n');
    }
    f.push('\n');
    f.push_str(&signed_headers.join(";"));
    f.push('\n');
    f.push_str("UNSIGNED-PAYLOAD");

    debug!("canonical request string: {}", f);
    Ok(f)
}

fn canonicalize_header(req: &mut SigningRequest) -> Result<()> {
    for (_, value) in req.headers.iter_mut() {
        SigningRequest::header_value_normalize(value)
    }

    // Insert HOST header if not present.
    if req.headers.get(header::HOST).is_none() {
        req.headers
            .insert(header::HOST, req.authority.as_str().parse()?);
    }

    Ok(())
}

fn canonicalize_query(
    req: &mut SigningRequest,
    method: SigningMethod,
    cred: &ServiceAccount,
    now: DateTime,
    service: &str,
    region: &str,
) -> Result<()> {
    if let SigningMethod::Query(expire) = method {
        req.query
            .push(("X-Goog-Algorithm".into(), "GOOG4-RSA-SHA256".into()));
        req.query.push((
            "X-Goog-Credential".into(),
            format!(
                "{}/{}/{}/{}/goog4_request",
                &cred.client_email,
                format_date(now),
                region,
                service
            ),
        ));
        req.query.push(("X-Goog-Date".into(), format_iso8601(now)));
        req.query
            .push(("X-Goog-Expires".into(), expire.as_secs().to_string()));
        req.query.push((
            "X-Goog-SignedHeaders".into(),
            req.header_name_to_vec_sorted().join(";"),
        ));
    }

    // Return if query is empty.
    if req.query.is_empty() {
        return Ok(());
    }

    // Sort by param name
    req.query.sort();

    req.query = req
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