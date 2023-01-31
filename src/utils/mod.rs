use http::header::HeaderName;
use http::HeaderValue;
use rsa::signature::RandomizedSigner;
use rsa::{pkcs1v15::SigningKey, pkcs8::DecodePrivateKey};

use crate::{
    hash::hmac_sha256,
    time::{format_date, DateTime},
};

use std::borrow::Cow;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Write;
use std::str::FromStr;

use anyhow::Result;
use http::HeaderMap;
use log::debug;
use percent_encoding::utf8_percent_encode;
use percent_encoding::{percent_decode_str, AsciiSet, NON_ALPHANUMERIC};

use crate::credential::Credential;
use crate::hash::hex_hmac_sha256;
use crate::hash::hex_sha256;
use crate::request::SignableRequest;
use crate::time::format_iso8601;
use crate::time::Duration;
use crate::time::{self};

/// AsciiSet for [AWS UriEncode](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html)
///
/// - URI encode every byte except the unreserved characters: 'A'-'Z', 'a'-'z', '0'-'9', '-', '.', '_', and '~'.
pub static AWS_URI_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// AsciiSet for [AWS UriEncode](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html)
///
/// But used in query.
pub static AWS_QUERY_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub fn normalize_header_value(header_value: &HeaderValue) -> HeaderValue {
    let bs = header_value.as_bytes();

    let starting_index = bs.iter().position(|b| *b != b' ').unwrap_or(0);
    let ending_offset = bs.iter().rev().position(|b| *b != b' ').unwrap_or(0);
    let ending_index = bs.len() - ending_offset;

    // This can't fail because we started with a valid HeaderValue and then only trimmed spaces
    HeaderValue::from_bytes(&bs[starting_index..ending_index]).expect("invalid header value")
}

pub enum SigningKeyFlavor {
    Aws,
    Google,
}

pub fn generate_signing_key(
    secret: &str,
    time: DateTime,
    region: &str,
    service: &str,
    signing_key_flavor: SigningKeyFlavor,
) -> Vec<u8> {
    // Sign secret
    let secret = match signing_key_flavor {
        SigningKeyFlavor::Aws => format!("AWS4{}", secret),
        SigningKeyFlavor::Google => format!("GOOG4{}", secret),
    };
    // Sign date
    let sign_date = hmac_sha256(secret.as_bytes(), format_date(time).as_bytes());
    // Sign region
    let sign_region = hmac_sha256(sign_date.as_slice(), region.as_bytes());
    // Sign service
    let sign_service = hmac_sha256(sign_region.as_slice(), service.as_bytes());
    // Sign request
    let sign_request = match signing_key_flavor {
        SigningKeyFlavor::Aws => hmac_sha256(sign_service.as_slice(), "aws4_request".as_bytes()),
        SigningKeyFlavor::Google => {
            hmac_sha256(sign_service.as_slice(), "goog4_request".as_bytes())
        }
    };

    sign_request
}

/// SigningMethod is the method that used in signing.
#[derive(Copy, Clone)]
pub enum SigningMethod {
    /// Signing with header.
    Header,
    /// Signing with query.
    Query(Duration),
}

#[derive(Clone)]
pub(crate) enum SigningAlgorithm {
    Aws4Hmac,
    Goog4Hmac,
    Goog4Rsa,
}

#[derive(Clone)]
pub(crate) struct CanonicalRequest {
    pub(crate) method: http::Method,
    pub(crate) path: String,
    pub(crate) query: Option<String>,
    pub(crate) headers: HeaderMap,

    pub(crate) region: String,
    pub(crate) service: String,
    pub(crate) scope: String,
    pub(crate) signing_host: String,
    pub(crate) signing_method: SigningMethod,
    pub(crate) signing_time: DateTime,
    pub(crate) algorithm: SigningAlgorithm,
}

impl CanonicalRequest {
    pub(crate) fn new(
        req: &impl SignableRequest,
        method: SigningMethod,
        now: Option<DateTime>,
        algorithm: SigningAlgorithm,
        region: String,
        service: String,
    ) -> Result<Self> {
        let mut canonical_headers = HeaderMap::with_capacity(req.headers().len());
        // Header names and values need to be normalized according to Step 4 of https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        // Using append instead of insert means this will not clobber headers that have the same lowercase name
        for (name, value) in req.headers().iter() {
            // The user agent header should not be canonical because it may be altered by proxies
            if name == http::header::USER_AGENT {
                continue;
            }
            canonical_headers.append(name, normalize_header_value(value));
        }

        let now = now.unwrap_or_else(time::now);

        let req_type = match algorithm {
            SigningAlgorithm::Aws4Hmac => "aws4_request",
            SigningAlgorithm::Goog4Hmac | SigningAlgorithm::Goog4Rsa => "goog4_request",
        };

        let scope = format!("{}/{}/{}/{}", format_date(now), region, service, req_type);

        Ok(CanonicalRequest {
            method: req.method(),
            path: percent_decode_str(req.path()).decode_utf8()?.to_string(),
            query: req.query().map(|v| v.to_string()),
            headers: req.headers(),

            signing_host: req.host_port(),
            signing_method: method,
            signing_time: now,
            algorithm,
            scope,
            region,
            service,
        })
    }

    fn format_header(&self, header_name: &str) -> String {
        let prefix = match self.algorithm {
            SigningAlgorithm::Aws4Hmac => "Amz",
            SigningAlgorithm::Goog4Hmac => "Goog",
            SigningAlgorithm::Goog4Rsa => "Goog",
        };
        format!("X-{prefix}-{header_name}")
    }

    pub(crate) fn build_headers(&mut self, cred: &Credential) -> Result<()> {
        // Insert HOST header if not present.
        if self.headers.get(&http::header::HOST).is_none() {
            let header = HeaderValue::try_from(self.signing_host.to_string())?;
            self.headers.insert(http::header::HOST, header);
        }

        if matches!(self.signing_method, SigningMethod::Header) {
            // Insert DATE header if not present.
            let date_header_key = self.format_header("date");
            if self.headers.get(&date_header_key).is_none() {
                let date_header = HeaderValue::try_from(format_iso8601(self.signing_time))?;
                self.headers
                    .insert(HeaderName::from_str(&date_header_key)?, date_header);
            }

            // Insert X_AMZ_CONTENT_SHA_256 header if not present.
            let content_sha256_key = self.format_header("content-sha256");
            if self.headers.get(&content_sha256_key).is_none() {
                self.headers.insert(
                    HeaderName::from_str(&content_sha256_key)?,
                    HeaderValue::from_static("UNSIGNED-PAYLOAD"),
                );
            }

            // Insert X_AMZ_SECURITY_TOKEN header if security token exists.
            if let Some(token) = cred.security_token() {
                let mut value = HeaderValue::from_str(token)?;
                // Set token value sensitive to valid leaking.
                value.set_sensitive(true);
                let key = self.format_header("security-token");
                self.headers.insert(HeaderName::from_str(&key)?, value);
            }
        }

        Ok(())
    }

    pub(crate) fn signed_headers(&self) -> Vec<&str> {
        let mut signed_headers = self.headers.keys().map(|v| v.as_str()).collect::<Vec<_>>();
        signed_headers.sort_unstable();

        signed_headers
    }

    fn format_algorithm(&self) -> &str {
        match self.algorithm {
            SigningAlgorithm::Aws4Hmac => "AWS4-HMAC-SHA256",
            SigningAlgorithm::Goog4Hmac => "GOOG4-HMAC-SHA256",
            SigningAlgorithm::Goog4Rsa => "GOOG4-RSA-SHA256",
        }
    }

    pub(crate) fn build_query(&mut self, cred: &Credential) -> Result<()> {
        let query = self.query.take().unwrap_or_default();
        let mut params: Vec<_> = form_urlencoded::parse(query.as_bytes()).collect();

        if let SigningMethod::Query(expire) = self.signing_method {
            params.push((
                self.format_header("Algorithm").into(),
                self.format_algorithm().into(),
            ));
            params.push((
                self.format_header("Credential").into(),
                Cow::Owned(format!(
                    "{}/{}/{}/{}/{}",
                    cred.access_key(),
                    format_date(self.signing_time),
                    self.region,
                    self.service,
                    match self.algorithm {
                        SigningAlgorithm::Aws4Hmac => "aws4_request",
                        SigningAlgorithm::Goog4Hmac | SigningAlgorithm::Goog4Rsa => "goog4_request",
                    }
                )),
            ));
            params.push((
                self.format_header("Date").into(),
                Cow::Owned(format_iso8601(self.signing_time)),
            ));
            params.push((
                self.format_header("Expires").into(),
                Cow::Owned(expire.whole_seconds().to_string()),
            ));
            params.push((
                self.format_header("SignedHeaders").into(),
                self.signed_headers().join(";").into(),
            ));

            if let Some(token) = cred.security_token() {
                params.push((self.format_header("Security-Token").into(), token.into()));
            }
        }
        // Sort by param name
        params.sort();

        if params.is_empty() {
            return Ok(());
        }

        let param = params
            .iter()
            .map(|(k, v)| {
                (
                    utf8_percent_encode(k, &AWS_QUERY_ENCODE_SET),
                    utf8_percent_encode(v, &AWS_QUERY_ENCODE_SET),
                )
            })
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<String>>()
            .join("&");
        self.query = Some(param);

        Ok(())
    }

    /// Calculate signing requests via SignableRequest.
    pub(crate) fn calculate_signature(
        &mut self,
        cred: &Credential,
        region: &str,
        service: &str,
    ) -> Result<String, anyhow::Error> {
        let encoded_req = hex_sha256(self.to_string().as_bytes());

        // NOTE: google also allows /auto/storage/ ... (no region)
        // Scope: "20220313/<region>/<service>/aws4_request"

        debug!("calculated scope: {}", self.scope);

        // StringToSign:
        //
        // GOOG4-HMAC-SHA256
        // 20220313T072004Z
        // 20220313/<region>/<service>/aws4_request
        // <hashed_canonical_request>
        let string_to_sign = {
            let mut f = String::new();
            writeln!(f, "{}", self.format_algorithm())?;
            writeln!(f, "{}", format_iso8601(self.signing_time))?;
            writeln!(f, "{}", &self.scope)?;
            write!(f, "{}", &encoded_req)?;
            f
        };
        debug!("calculated string to sign: {string_to_sign}");

        let signature = match &self.algorithm {
            SigningAlgorithm::Goog4Rsa => {
                let mut rng = rand::thread_rng();
                let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(cred.secret_key())?;
                let signing_key = SigningKey::<rsa::sha2::Sha256>::new_with_prefix(private_key);
                let signature = signing_key.sign_with_rng(&mut rng, string_to_sign.as_bytes());
                signature.to_string()
            }
            SigningAlgorithm::Aws4Hmac | SigningAlgorithm::Goog4Hmac => {
                let signing_key = generate_signing_key(
                    cred.secret_key(),
                    self.signing_time,
                    region,
                    service,
                    SigningKeyFlavor::Google,
                );
                hex_hmac_sha256(&signing_key, string_to_sign.as_bytes())
            }
        };
        Ok(signature)
    }
}

impl Display for CanonicalRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.method)?;
        writeln!(
            f,
            "{}",
            utf8_percent_encode(&self.path, &AWS_URI_ENCODE_SET)
        )?;
        writeln!(f, "{}", self.query.as_ref().unwrap_or(&"".to_string()))?;

        let signed_headers = self.signed_headers();
        for header in signed_headers.iter() {
            let value = &self.headers[*header];
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

        Ok(())
    }
}
