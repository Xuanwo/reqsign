use super::credential::Credential;
use super::loader::CredentialLoadChain;
use base64::encode;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use std::fmt::{Debug, Display, Formatter};
use std::mem;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;
use anyhow::{anyhow, Result};
use http::header::HeaderName;
use http::{HeaderMap, HeaderValue};
use log::debug;
use tokio::sync::{OnceCell, RwLock};
#[derive(Default)]
pub struct Builder {
    bucket:String,
    blob:String,
    credential:Credential,
    credential_load:CredentialLoadChain,
    time:Option<SystemTime>,
}

impl Builder {
    pub fn bucket(&mut self, bucket: &str) -> &mut Self {
        self.bucket = bucket.to_string();
        self
    }

    pub fn blob(&mut self, blob: &str) -> &mut Self {
        self.blob = blob.to_string();
        self
    }

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



}

pub fn sign(data: &str, key: &str) -> Result<String> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(&base64::decode(key)?)?;
    hmac.update(data.as_bytes());
    let signature = hmac.finalize().into_bytes();
    Ok(encode(&signature))
}