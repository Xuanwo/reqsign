use super::constants::*;
use super::credential::Credential;
use super::loader::*;
use base64::encode;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use anyhow::{anyhow, Result};

use http::{header::*, method::Method};
use http::HeaderMap;
use log::debug;
use std::fmt::{Debug, Display, Formatter};
use std::mem;

use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use url::Url;

use crate::request::SignableRequest;

#[derive(Default)]
pub struct Builder {
    credential: Credential,
    credential_load: CredentialLoadChain,
    time: Option<SystemTime>,
}

impl Builder {
    pub fn credential_loader(&mut self, credential_load: CredentialLoadChain) -> &mut Self {
        self.credential_load = credential_load;
        self
    }

    pub fn access_key(&mut self, access_key: &str) -> &mut Self {
        self.credential.set_access_key(access_key);
        self
    }

    pub fn access_acount(&mut self, access_acount: &str) -> &mut Self {
        self.credential.set_access_acount(access_acount);
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
            time: self.time,
        })
    }
}
#[derive(Default)]
pub struct Signer {
    credential: Arc<RwLock<Option<Credential>>>,
    credential_load: CredentialLoadChain,
    time: Option<SystemTime>,
}
impl Debug for Signer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
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

    pub async fn sign(&self, request: &mut impl SignableRequest) -> Result<()>{
        let headers = request.headers();
        let uri = Url::parse(request.path())?;
        let method = request.method();
        let account = self
            .credential()
            .await?
            .unwrap()
            .access_acount()
            .to_string();
        let key = self.credential().await?.unwrap().access_key().to_string();

        dbg!(&headers);
        dbg!(&uri);
        dbg!(&method);
        dbg!(&account);
        dbg!(&key);

        let str_to_sign = string_to_sign(headers, &uri, method, &account);

        // debug!("\nstr_to_sign == {:?}\n", str_to_sign);
        // debug!("str_to_sign == {}", str_to_sign);

        let auth = sign(&str_to_sign, &key).unwrap();
        // debug!("auth == {:?}", auth);
        request.apply_header(AUTHORIZATION,&auth);
        Ok(())

    }
}
// alias  to use core::client::storage_account_client::generate_authorization
#[derive(Debug, Clone, Copy)]
pub enum ServiceType {
    Blob,
    // Queue,
    // File,
    Table,
}

#[allow(unknown_lints)]
pub fn string_to_sign(h: &HeaderMap, u: &url::Url, method: &Method, account: &str) -> String {
    // content lenght must only be specified if != 0
    // this is valid from 2015-02-21
    let cl = h
        .get(CONTENT_LENGTH)
        .map(|s| if s == "0" { "" } else { s.to_str().unwrap() })
        .unwrap_or("");
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}{}",
        method.as_str(),
        add_if_exists(h, CONTENT_ENCODING),
        add_if_exists(h, CONTENT_LANGUAGE),
        cl,
        add_if_exists(h, CONTENT_MD5),
        add_if_exists(h, CONTENT_TYPE),
        add_if_exists(h, DATE),
        add_if_exists(h, IF_MODIFIED_SINCE),
        add_if_exists(h, IF_MATCH),
        add_if_exists(h, IF_NONE_MATCH),
        add_if_exists(h, IF_UNMODIFIED_SINCE),
        add_if_exists(h, RANGE),
        canonicalize_header(h),
        canonicalized_resource(account, u)
    )
    // expected
    // GET\n /*HTTP Verb*/
    // \n    /*Content-Encoding*/
    // \n    /*Content-Language*/
    // \n    /*Content-Length (include value when zero)*/
    // \n    /*Content-MD5*/
    // \n    /*Content-Type*/
    // \n    /*Date*/
    // \n    /*If-Modified-Since */
    // \n    /*If-Match*/
    // \n    /*If-None-Match*/
    // \n    /*If-Unmodified-Since*/
    // \n    /*Range*/
    // x-ms-date:Sun, 11 Oct 2009 21:49:13 GMT\nx-ms-version:2009-09-19\n
    //                                  /*CanonicalizedHeaders*/
    // /myaccount /mycontainer\ncomp:metadata\nrestype:container\ntimeout:20
    //                                  /*CanonicalizedResource*/
    //
    //
}

pub fn add_if_exists<K: AsHeaderName>(h: &HeaderMap, key: K) -> &str {
    match h.get(key) {
        Some(ce) => ce.to_str().unwrap(),
        None => "",
    }
}

pub fn canonicalize_header(h: &HeaderMap) -> String {
    let mut v_headers = h
        .iter()
        .filter(|(k, _v)| k.as_str().starts_with("x-ms"))
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>();
    v_headers.sort_unstable();

    let mut can = String::new();

    for header_name in v_headers {
        let s = h.get(header_name).unwrap().to_str().unwrap();
        can = can + header_name + ":" + s + "\n";
    }
    can
}

pub fn canonicalized_resource_table(account: &str, u: &url::Url) -> String {
    format!("/{}{}", account, u.path())
}

pub fn canonicalized_resource(account: &str, u: &url::Url) -> String {
    let mut can_res: String = String::new();
    can_res += "/";
    can_res += account;

    let paths = u.path_segments().unwrap();

    for p in paths {
        can_res.push('/');
        can_res.push_str(&*p);
    }
    can_res += "\n";

    // query parameters
    let query_pairs = u.query_pairs(); //.into_owned();
    {
        let mut qps = Vec::new();
        {
            for (q, _p) in query_pairs {
                // add only once
                if !(qps.iter().any(|x: &String| x == q.as_ref())) {
                    qps.push(q.into_owned());
                }
            }
        }

        qps.sort();

        for qparam in qps {
            // find correct parameter
            let ret = lexy_sort(&query_pairs, &qparam);

            // debug!("adding to can_res {:?}", ret);

            can_res = can_res + &qparam.to_lowercase() + ":";

            for (i, item) in ret.iter().enumerate() {
                if i > 0 {
                    can_res += ","
                }
                can_res += item;
            }

            can_res += "\n";
        }
    };

    can_res[0..can_res.len() - 1].to_owned()
}

pub fn lexy_sort<'a>(
    vec: &'a url::form_urlencoded::Parse,
    query_param: &str,
) -> Vec<std::borrow::Cow<'a, str>> {
    let mut v_values = Vec::new();

    for item in vec.filter(|x| x.0 == *query_param) {
        v_values.push(item.1)
    }
    v_values.sort();

    v_values
}
pub fn sign(data: &str, key: &str) -> Result<String> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(&base64::decode(key)?)?;
    hmac.update(data.as_bytes());
    let signature = hmac.finalize().into_bytes();
    Ok(encode(&signature))
}

#[cfg(test)]
mod tests {
    use crate::services::azure::credential;

    use super::*;
    use anyhow::Result;
    fn test_get_request() -> http::Request<&'static str> {
        let mut req = http::Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "http://127.0.0.1:9000/hello"
            .parse()
            .expect("url must be valid");

        req
    }

    // #[tokio::test]
    // async fn test_calculate() -> Result<()>
    // {
    //     use crate::services::azure::constants::*;

    //     let mut request = test_get_request();
    //     let dt = chrono::Utc::now();
    //     let time = format!("{}", dt.format("%a, %d %h %Y %T GMT"));

    //     request.headers_mut().insert(
    //         MS_DATE,
    //         HeaderValue::from_str(&time)?,
    //     );
    //     request.headers_mut().insert(
    //         HEADER_VERSION,
    //         HeaderValue::from_str(&AZURE_VERSION)?,
    //     );

    //     let auth = generate_authorization(
    //         request,
    //         credential
    //     );
    //     request.header(AUTHORIZATION, auth)

    //     Ok(())
    // }
}
