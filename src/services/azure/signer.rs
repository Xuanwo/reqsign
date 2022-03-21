use super::constants::*;
use super::credential::Credential;
use super::loader::*;

use base64::encode;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::time::format;
use std::time::SystemTime;
use time::format_description::well_known::Rfc2822;

use anyhow::{anyhow, Result};
use http::HeaderMap;
use http::{header::*, method::Method};
use log::debug;
use std::fmt::{Debug, Formatter};
use std::mem;

use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

use crate::request::SignableRequest;

#[derive(Default)]
pub struct Builder {
    credential: Credential,
    credential_load: CredentialLoadChain,
}

impl Builder {
    pub fn credential_loader(&mut self, credential_load: CredentialLoadChain) -> &mut Self {
        self.credential_load = credential_load;
        self
    }

    pub fn shared_key(&mut self, shared_key: &str) -> &mut Self {
        self.credential.set_shared_key(shared_key);
        self
    }

    pub fn access_name(&mut self, access_name: &str) -> &mut Self {
        self.credential.set_access_name(access_name);
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
        })
    }
}
#[derive(Default)]
pub struct Signer {
    credential: Arc<RwLock<Option<Credential>>>,
    credential_load: CredentialLoadChain,
}

//since access_account and shared_key should be kept secret,so debug trait is unimplemented
impl Debug for Signer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signer {{ unimplement!}}")
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

    pub async fn sign(&self, request: &mut impl SignableRequest) -> Result<()> {
        let host = request.host();
        let path = request.path();
        let url = Url::parse(&format!("https://{}{}", host, path)).expect("parsing url success");

        let method = request.method().clone();

        // account = credential.access_name, keep variable nameaccount aligning with azure sdk for rust
        // refer https://github.com/Azure/azure-sdk-for-rust/blob/main/sdk/storage/src/core/clients/storage_account_client.rs
        let account = self.credential().await?.unwrap().access_name().to_string();
        // key = credential.shared_key, keep variable name key aligning with azure sdk for rust
        // refer https://github.com/Azure/azure-sdk-for-rust/blob/main/sdk/storage/src/core/clients/storage_account_client.rs
        let key = self.credential().await?.unwrap().shared_key().to_string();
        
        let now = SystemTime::now();
        // time = Sun, 20 Mar 2022 01:45:13 +0000
        let time = format(now, &Rfc2822);
        // convert time to Sun, 20 Mar 2022 01:45:13 GMT
        let time = str::replace(&time, "+0000", "GMT");
        
        request.apply_header(HeaderName::from_static(super::constants::MS_DATE), &time)?;
        request.apply_header(
            HeaderName::from_static(super::constants::HEADER_VERSION),
            AZURE_VERSION,
        )?; 
        let header = request.headers().clone();

        println!("time :{:?}",time);
        println!("url :{:?}",url);
        println!("method :{:?}",method);
        println!("account :{:?}",account);
        println!("key :{:?}",key);
        println!("header :{:?}",header);

        let str_to_sign = string_to_sign(&header, &url, &method, &account);

        let auth = sign(&str_to_sign, &key).unwrap();

        let auth = format!("SharedKey {}:{}", account, auth);

        request.apply_header(AUTHORIZATION, &auth)?;
        Ok(())
    }
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
