use crate::azure::storage::sas::{urlencoded, Protocol};
use crate::time::DateTime;
use crate::{hash, time};
use bitflags::bitflags;
use std::fmt;

bitflags! {
    /// Specifies the signed services that are accessible with the account SAS
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct AccountSasResource: u8 {
        const Blob = 0b0001;  // Blob(b)
        const Queue = 0b0010; // Queue(q)
        const Table = 0b0100; // Table(t)
        const File = 0b1000;  // File(f)
    }

    /// Specifies the signed resource types that are accessible with the account SAS
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct AccountSasResourceType: u8 {
        const Service = 0b0001;   // Service(s)
        const Container = 0b0010; // Container(c)
        const Object = 0b0100;    // Object(o)
    }

    /// Specifies the signed permissions for the account SAS. Permissions are valid only if they match the specified signed resource type
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct AccountSasPermissions: u8 {
        // NOTE: order *must* be `racwdxltmeop` per documentation:
        // https://docs.microsoft.com/en-us/rest/api/storageservices/create-service-sas#specifying-permissions
        const READ = 0x01<<0;
        const ADD = 0x01<<1;
        const CREATE = 0x01<<2;
        const WRITE = 0x01<<3;
        const DELETE = 0x01<<4;
        const LIST = 0x01<<5;
        const UPDATE = 0x01<<6;
        const PROCESS = 0x01<<7;
        const ALL = 0xFF;
    }
}

/// Service version of the shared access signature ([Azure documentation](https://learn.microsoft.com/en-us/rest/api/storageservices/create-account-sas#specify-the-account-sas-parameters)).
#[derive(Copy, Clone)]
pub enum AccountSasVersion {
    V20181109,
}

impl fmt::Display for AccountSasVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::V20181109 => write!(f, "2018-11-09"),
        }
    }
}

impl fmt::Display for AccountSasResource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.iter()
            .map(|flag| match flag {
                Self::Blob => "b",
                Self::Queue => "q",
                Self::Table => "t",
                Self::File => "f",
                _ => "",
            })
            .collect::<Vec<&str>>()
            .join("")
            .fmt(f)
    }
}

impl fmt::Display for AccountSasResourceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.iter()
            .map(|flag| match flag {
                Self::Service => "s",
                Self::Container => "c",
                Self::Object => "o",
                _ => "",
            })
            .collect::<Vec<&str>>()
            .join("")
            .fmt(f)
    }
}

impl fmt::Display for AccountSasPermissions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.iter()
            .map(|flag| match flag {
                Self::READ => "r",
                Self::ADD => "a",
                Self::CREATE => "c",
                Self::WRITE => "w",
                Self::DELETE => "d",
                Self::LIST => "l",
                Self::UPDATE => "u",
                Self::PROCESS => "p",
                _ => "",
            })
            .collect::<Vec<&str>>()
            .join("")
            .fmt(f)
    }
}

pub struct AccountSharedAccessSignature {
    account: String,
    key: String,
    version: AccountSasVersion,
    resource: AccountSasResource,
    resource_type: AccountSasResourceType,
    permissions: AccountSasPermissions,
    expiry: DateTime,
    start: Option<DateTime>,
    ip: Option<String>,
    protocol: Option<Protocol>,
}

impl AccountSharedAccessSignature {
    /// Creates a new `AccountSharedAccessSignature` with the given parameters.
    pub fn new(
        account: String,
        key: String,
        resource: AccountSasResource,
        resource_type: AccountSasResourceType,
        permissions: AccountSasPermissions,
        expiry: DateTime,
    ) -> Self {
        Self {
            account,
            key,
            version: AccountSasVersion::V20181109,
            resource,
            resource_type,
            permissions,
            expiry,
            start: None,
            ip: None,
            protocol: None,
        }
    }

    /// Specifies the starting time for this SAS token.
    #[allow(dead_code)]
    pub fn start(&mut self, start: DateTime) -> &mut Self {
        self.start = Some(start);
        self
    }

    /// Specifies the IP address or a range of IP addresses from which to accept requests. [Azure documentation](https://learn.microsoft.com/en-us/rest/api/storageservices/create-account-sas#specify-an-ip-address-or-ip-range)
    #[allow(dead_code)]
    pub fn ip(&mut self, ip: String) -> &mut Self {
        self.ip = Some(ip);
        self
    }

    /// Specifies the protocol permitted for a request made with the account SAS. [Azure documentation](https://learn.microsoft.com/en-us/rest/api/storageservices/create-account-sas#specify-the-http-protocol)
    pub fn protocol(&mut self, protocol: Protocol) -> &mut Self {
        self.protocol = Some(protocol);
        self
    }

    // Azure documentation: https://learn.microsoft.com/en-us/rest/api/storageservices/create-account-sas#construct-the-signature-string
    fn signature(&self) -> String {
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.account,
            self.permissions,
            self.resource,
            self.resource_type,
            self.start
                .as_ref()
                .map_or("".to_string(), |v| urlencoded(time::format_rfc3339(*v))),
            time::format_rfc3339(self.expiry),
            self.ip.clone().unwrap_or_default(),
            self.protocol
                .as_ref()
                .map_or("".to_string(), |v| v.to_string()),
            self.version,
        );

        hash::base64_hmac_sha256(
            &hash::base64_decode(self.key.clone().as_str()),
            string_to_sign.as_bytes(),
        )
    }

    /// [Example](https://docs.microsoft.com/rest/api/storageservices/create-service-sas#service-sas-example) from Azure documentation.
    pub fn token(&self) -> Vec<(String, String)> {
        let expiry = time::format_rfc3339(self.expiry);
        let mut elements: Vec<(String, String)> = vec![
            ("sv".to_string(), self.version.to_string()),
            ("ss".to_string(), self.resource.to_string()),
            ("srt".to_string(), self.resource_type.to_string()),
            ("se".to_string(), urlencoded(expiry)),
            ("sp".to_string(), self.permissions.to_string()),
        ];

        if let Some(start) = &self.start {
            elements.push(("st".to_string(), urlencoded(time::format_rfc3339(*start))))
        }
        if let Some(ip) = &self.ip {
            elements.push(("sip".to_string(), ip.to_string()))
        }
        if let Some(protocol) = &self.protocol {
            elements.push(("spr".to_string(), protocol.to_string()))
        }

        let sig = AccountSharedAccessSignature::signature(self);
        elements.push(("sig".to_string(), urlencoded(sig)));

        elements
    }

    #[allow(dead_code)]
    fn token_string(&self) -> String {
        self.token()
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join("&")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn test_time() -> DateTime {
        DateTime::from_str("2022-03-01T08:12:34Z").unwrap()
    }

    #[test]
    fn test_account_sas_resource() {
        let resource = AccountSasResource::Blob | AccountSasResource::Queue;
        assert_eq!(resource.to_string(), "bq");

        let resource = AccountSasResource::Blob
            | AccountSasResource::Queue
            | AccountSasResource::Table
            | AccountSasResource::File;
        assert_eq!(resource.to_string(), "bqtf");

        // the order should be always the bqtf
        let resource =
            AccountSasResource::Table | AccountSasResource::Queue | AccountSasResource::File;
        assert_eq!(resource.to_string(), "qtf");
    }

    #[test]
    fn test_account_sas_resource_type() {
        let resource_type = AccountSasResourceType::Service;
        assert_eq!(resource_type.to_string(), "s");

        let resource_type = AccountSasResourceType::Service | AccountSasResourceType::Container;
        assert_eq!(resource_type.to_string(), "sc");

        // the order should be always the sco
        let resource_type = AccountSasResourceType::Object
            | AccountSasResourceType::Container
            | AccountSasResourceType::Service;
        assert_eq!(resource_type.to_string(), "sco");
    }

    #[test]
    fn test_account_sas_permissions() {
        // the order should be always the racwdlup
        let permissions = AccountSasPermissions::PROCESS
            | AccountSasPermissions::UPDATE
            | AccountSasPermissions::LIST
            | AccountSasPermissions::DELETE
            | AccountSasPermissions::WRITE
            | AccountSasPermissions::CREATE
            | AccountSasPermissions::ADD
            | AccountSasPermissions::READ;
        assert_eq!(permissions.to_string(), "racwdlup");
    }

    #[test]
    fn test_can_generate_sas_token() {
        let key = hash::base64_encode("key".as_bytes());
        let sign = AccountSharedAccessSignature::new(
            "account".to_string(),
            key,
            AccountSasResource::Blob,
            AccountSasResourceType::Service,
            AccountSasPermissions::READ,
            time::add_minutes(test_time(), 5),
        );
        let token = sign.token_string();

        assert_eq!(token, "sv=2018-11-09&ss=b&srt=s&se=2022-03-01T08%3A17%3A34Z&sp=r&sig=2TFrGZvSgKK9uvZAJV7ptAYrOFQrjB8PErxAxcjuysU%3D");
    }

    #[test]
    fn test_can_generate_sas_token_with_option_parameters() {
        let key = hash::base64_encode("key".as_bytes());
        let mut sign = AccountSharedAccessSignature::new(
            "account".to_string(),
            key,
            AccountSasResource::Blob,
            AccountSasResourceType::Service,
            AccountSasPermissions::READ,
            time::add_minutes(test_time(), 5),
        );

        sign.start(time::sub_minutes(test_time(), 10))
            .ip("168.1.5.60-168.1.5.70".to_string())
            .protocol(Protocol::HttpHttps);

        let token = sign.token_string();

        assert_eq!(token, "sv=2018-11-09&ss=b&srt=s&se=2022-03-01T08%3A17%3A34Z&sp=r&st=2022-03-01T08%3A02%3A34Z&sip=168.1.5.60-168.1.5.70&spr=http,https&sig=oiZsRHwqKJxAzPYjZAcklqcIBxRmWORdXGx%2BlPVliVg%3D");
    }
}
