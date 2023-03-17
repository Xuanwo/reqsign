//! Tencent COS Singer

use std::collections::HashMap;
use std::fmt::Write;

use super::credential::CredentialLoader;
use crate::credential::Credential;
use crate::request::SignableRequest;
use crate::time;
use crate::time::format_http_date;
use crate::time::DateTime;
use crate::time::Duration;
use anyhow::anyhow;
use anyhow::Result;
use hmac::Hmac;
use hmac::Mac;
use http::header::AUTHORIZATION;
use http::header::DATE;
use http::HeaderMap;
use http::HeaderValue;
use log::debug;
use percent_encoding::{percent_decode_str, utf8_percent_encode};
use sha1::{Digest, Sha1};

/// Builder for `Signer`
#[derive(Default)]
pub struct Builder {
    credential: Credential,
    disable_load_from_env: bool,
    disable_load_from_assume_role_with_oidc: bool,
    allow_anonymous: bool,
    time: Option<DateTime>,
}

impl Builder {
    /// Specify access key id.
    ///
    /// If not set, we will try to load via `credential_loader`.
    pub fn access_key_id(&mut self, access_key_id: &str) -> &mut Self {
        self.credential.set_access_key(access_key_id);
        self
    }

    /// Specify access key secret.
    ///
    /// If not set, we will try to load via `credential_loader`.
    pub fn access_key_secret(&mut self, access_key_secret: &str) -> &mut Self {
        self.credential.set_secret_key(access_key_secret);
        self
    }

    /// Disable load from env.
    pub fn disable_load_from_env(&mut self) -> &mut Self {
        self.disable_load_from_env = true;
        self
    }

    /// Disable load from assume role with oidc.
    pub fn disable_load_from_assume_role_with_oidc(&mut self) -> &mut Self {
        self.disable_load_from_assume_role_with_oidc = true;
        self
    }

    /// Allow anonymous request if credential is not loaded.
    pub fn allow_anonymous(&mut self) -> &mut Self {
        self.allow_anonymous = true;
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
            allow_anonymous: self.allow_anonymous,
            time: self.time,
        })
    }
}

/// Singer for Tencent COS.
pub struct Signer {
    credential_loader: CredentialLoader,
    /// Allow anonymous request if credential is not loaded.
    allow_anonymous: bool,
    time: Option<DateTime>,
}

impl Signer {
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
    fn calculate(
        &self,
        req: &impl SignableRequest,
        method: SigningMethod,
        cred: &Credential,
    ) -> Result<SignedOutput> {
        let now = self.time.unwrap_or_else(time::now);
        let signature = self.get_signature(req, cred.secret_key(), cred.access_key(), 60);
        debug!("signature: {}", signature);
        Ok(SignedOutput {
            signature,
            signed_time: now,
            signing_method: method,
            security_token: cred.security_token().map(|v| v.to_string()),
        })
    }

    fn apply(&self, req: &mut impl SignableRequest, output: &SignedOutput) -> Result<()> {
        match output.signing_method {
            SigningMethod::Header => {
                req.insert_header(DATE, format_http_date(output.signed_time).parse()?)?;
                req.insert_header(AUTHORIZATION, {
                    let mut value: HeaderValue = output.signature.to_string().parse()?;
                    value.set_sensitive(true);
                    value
                })?;
                if let Some(token) = &output.security_token {
                    req.insert_header("x-cos-security-token".parse()?, {
                        let mut value: HeaderValue = token.parse()?;
                        value.set_sensitive(true);

                        value
                    })?;
                }
            }
            SigningMethod::Query(_expire) => {
                req.insert_header(DATE, format_http_date(output.signed_time).parse()?)?;
                let mut query = if let Some(query) = req.query() {
                    query.to_string() + "&"
                } else {
                    "".to_string()
                };
                write!(query, "&{}", &output.signature)?;

                if let Some(token) = &output.security_token {
                    write!(
                        query,
                        "&x-cos-security-token={}",
                        utf8_percent_encode(token, percent_encoding::NON_ALPHANUMERIC)
                    )?;
                }

                req.set_query(&query)?;
            }
        }

        Ok(())
    }

    /// Signing request with header.
    pub fn sign(&self, req: &mut impl SignableRequest) -> Result<()> {
        if let Some(cred) = self.credential() {
            let sig = self.calculate(req, SigningMethod::Header, &cred)?;
            return self.apply(req, &sig);
        }

        if self.allow_anonymous {
            debug!("credential not found and anonymous is allowed, skipping signing.");
            return Ok(());
        }

        Err(anyhow!("credential not found"))
    }

    /// Signing request with query.
    pub fn sign_query(&self, req: &mut impl SignableRequest, expire: Duration) -> Result<()> {
        if let Some(cred) = self.credential() {
            let sig = self.calculate(req, SigningMethod::Query(expire), &cred)?;
            return self.apply(req, &sig);
        }

        if self.allow_anonymous {
            debug!("credential not found and anonymous is allowed, skipping signing.");
            return Ok(());
        }

        Err(anyhow!("credential not found"))
    }

    fn get_key_time(&self, valid_seconds: u32) -> String {
        let start = time::now().unix_timestamp();
        let end = start + valid_seconds as i64;
        format!("{};{}", start, end)
    }

    fn get_sign_key(&self, data: &str, sign_key: &str) -> String {
        let mut h = Hmac::<Sha1>::new_from_slice(sign_key.as_bytes()).expect("invalid key length");
        h.update(data.as_bytes());
        let signature = h.finalize().into_bytes().to_vec();
        let s: Vec<String> = signature
            .into_iter()
            .map(|x| format!("{:02x?}", x))
            .collect();
        s.join("")
    }

    fn encode_data(&self, data: &HeaderMap) -> HashMap<String, String> {
        let mut res = HashMap::new();
        for (k, v) in data.iter() {
            res.insert(
                utf8_percent_encode(k.as_str(), percent_encoding::NON_ALPHANUMERIC)
                    .to_string()
                    .to_lowercase(),
                utf8_percent_encode(v.to_str().unwrap(), percent_encoding::NON_ALPHANUMERIC)
                    .to_string()
                    .to_lowercase(),
            );
        }
        res
    }

    fn encode_map(&self, data: &HashMap<String, String>) -> HashMap<String, String> {
        let mut res: HashMap<String, String> = HashMap::new();
        for (k, v) in data.iter() {
            res.insert(
                utf8_percent_encode(k, percent_encoding::NON_ALPHANUMERIC).to_string(),
                utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC).to_string(),
            );
        }
        res
    }

    fn get_url_param_list(&self, req: &impl SignableRequest) -> String {
        let option = req.query();
        if option.is_none() {
            return "".to_string();
        }
        let query = option.unwrap();
        let mut keys: Vec<String> = Vec::new();
        let mut m = HashMap::new();
        let _ = form_urlencoded::parse(query.as_bytes()).map(|(key, val)| {
            m.insert(
                key.to_string().to_lowercase(),
                val.to_string().to_lowercase(),
            )
        });
        let encoded_data = self.encode_map(&m);
        for k in encoded_data.keys() {
            keys.push(k.to_string());
        }
        keys.sort();
        keys.join(";")
    }

    fn get_http_parameters(&self, req: &impl SignableRequest) -> String {
        let option = req.query();
        if option.is_none() {
            return "".to_string();
        }
        let query = option.unwrap();
        let mut keys: Vec<String> = Vec::new();
        let mut m = HashMap::new();
        let _ = form_urlencoded::parse(query.as_bytes()).map(|(key, val)| {
            m.insert(
                key.to_string().to_lowercase(),
                val.to_string().to_lowercase(),
            )
        });
        let encoded_data = self.encode_map(&m);
        for k in encoded_data.keys() {
            keys.push(k.to_string());
        }
        keys.sort();
        let mut res: Vec<String> = Vec::new();
        for key in keys {
            let v = encoded_data.get(&key).unwrap();
            res.push(vec![key, v.to_string()].join("="));
        }
        res.join("&")
    }

    fn get_header_list(&self, req: &impl SignableRequest) -> String {
        let mut keys: Vec<String> = Vec::new();
        let encoded_data = self.encode_data(&req.headers());
        for k in encoded_data.keys() {
            keys.push(k.to_string());
        }
        keys.sort();
        keys.join(";")
    }

    fn get_heades(&self, req: &impl SignableRequest) -> String {
        let mut keys: Vec<String> = Vec::new();
        let encoded_data = self.encode_data(&req.headers());
        for k in encoded_data.keys() {
            keys.push(k.to_string());
        }
        keys.sort();
        let mut res: Vec<String> = Vec::new();
        for key in keys {
            let v = encoded_data.get(&key).unwrap();
            res.push(vec![key, v.to_string()].join("="));
        }
        res.join("&")
    }

    fn get_http_string(&self, req: &impl SignableRequest) -> String {
        let path = percent_decode_str(req.path())
            .decode_utf8_lossy()
            .to_string();
        let s = vec![
            req.method().to_string().to_lowercase(),
            path,
            self.get_http_parameters(req),
            self.get_heades(req),
        ];
        s.join("\n") + "\n"
    }

    fn get_string_to_sign(&self, http_string: &str, key_time: &str) -> String {
        let mut s = vec!["sha1".to_string(), key_time.to_string()];
        let mut hasher = Sha1::new();
        hasher.update(http_string);
        let result = hasher.finalize();
        let digest: Vec<String> = result
            .as_slice()
            .iter()
            .map(|x| format!("{:02x?}", x))
            .collect();
        s.push(digest.join(""));
        s.join("\n") + "\n"
    }
    /// Set customed credential loader.
    /// https://cloud.tencent.com/document/product/436/7778
    /// This loader will be used first.
    pub fn get_signature(
        &self,
        req: &impl SignableRequest,
        secret_key: &str,
        secret_id: &str,
        valid_seconds: u32,
    ) -> String {
        let key_time = self.get_key_time(valid_seconds);
        debug!("key_time: {}", key_time);
        let sign_key = self.get_sign_key(&key_time, secret_key);
        debug!("sign_key: {}", sign_key);

        //UrlParamList
        let param_list = self.get_url_param_list(req);
        debug!("param_list: {}", param_list);
        //HttpParameters
        let header_list = self.get_header_list(req);
        debug!("header_list: {}", header_list);
        let http_string = self.get_http_string(req);
        debug!("http_string: {}", http_string);

        let string_to_sign = self.get_string_to_sign(&http_string, &key_time);
        debug!("string_to_sign: {}", string_to_sign);
        let signature = self.get_sign_key(&string_to_sign, &sign_key);
        debug!("signature: {}", signature);
        format!("q-sign-algorithm=sha1&q-ak={}&q-sign-time={}&q-key-time={}&q-header-list={}&q-url-param-list={}&q-signature={}", secret_id, key_time, key_time, header_list, param_list, signature)
    }
}

/// SigningMethod is the method that used in signing.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum SigningMethod {
    /// Signing with header.
    Header,
    /// Signing with query.
    Query(Duration),
}

struct SignedOutput {
    signature: String,
    signed_time: DateTime,
    signing_method: SigningMethod,
    security_token: Option<String>,
}
