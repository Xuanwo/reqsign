use std::fmt;

pub mod account_sas;

/// Specifies the protocol permitted for a request made with the SAS ([Azure documentation](https://docs.microsoft.com/rest/api/storageservices/create-service-sas#specifying-the-http-protocol)).
#[derive(Copy, Clone)]
#[allow(dead_code)]
pub enum Protocol {
    Https,
    HttpHttps,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Protocol::Https => write!(f, "https"),
            Protocol::HttpHttps => write!(f, "http,https"),
        }
    }
}

fn urlencoded(s: String) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
