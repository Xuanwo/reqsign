#[derive(Default, Clone)]
pub struct Credential {
    access_key: String,
    secret_key: String,
}

impl Credential {
    pub fn new(access_key: &str, secret_key: &str) -> Self {
        Self {
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
        }
    }

    pub fn access_key(&self) -> &str {
        &self.access_key
    }

    pub fn set_access_key(&mut self, access_key: &str) -> &mut Self {
        self.access_key = access_key.to_string();
        self
    }

    pub fn secret_key(&self) -> &str {
        &self.secret_key
    }

    pub fn set_secret_key(&mut self, secret_key: &str) -> &mut Self {
        self.secret_key = secret_key.to_string();
        self
    }

    pub fn is_valid(&self) -> bool {
        if self.access_key.is_empty() || self.secret_key.is_empty() {
            return false;
        }

        true
    }
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Credential {{ access_key: {}, secret_key: {}}}",
            redact(&self.access_key),
            redact(&self.secret_key),
        )
    }
}

fn redact(v: &str) -> &str {
    if v.is_empty() {
        "<empty>"
    } else {
        "<redacted>"
    }
}
