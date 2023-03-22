use http::{HeaderMap, Method};

pub struct SigningContext {
    pub method: Method,
    pub host: String,
    pub port: Option<usize>,
    pub path: String,
    pub query: Option<String>,
    pub headers: HeaderMap,
}

impl SigningContext {
    pub fn host_port(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{}", self.host, port),
            None => self.host.clone(),
        }
    }
}
