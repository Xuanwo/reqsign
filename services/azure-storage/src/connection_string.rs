use std::collections::HashMap;

use anyhow::{anyhow, Result};

use crate::{Config, Credential, Service};

/// Parses an [Azure connection string][1].
///
/// [1]: https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string
pub(crate) fn parse(conn_str: &str, storage: &Service) -> Result<Config> {
    let key_values = parse_into_key_values(conn_str)?;

    if storage == &Service::Blob {
        // Try to read development storage configuration.
        if let Some(development_config) = collect_blob_development_config(&key_values, storage) {
            return Ok(Config {
                account_name: Some(development_config.account_name),
                account_key: Some(development_config.account_key),
                endpoint: Some(development_config.endpoint),
                ..Default::default()
            });
        }
    }

    let mut config = Config {
        account_name: key_values.get("AccountName").cloned(),
        endpoint: collect_endpoint(&key_values, storage)?,
        ..Default::default()
    };

    if let Some(creds) = collect_credentials(&key_values) {
        set_credentials(&mut config, creds);
    };

    Ok(config)
}

fn parse_into_key_values(conn_str: &str) -> Result<HashMap<String, String>> {
    conn_str
        .trim()
        .replace("\n", "")
        .split(';')
        .filter(|&field| !field.is_empty())
        .map(|field| {
            let (key, value) = field.trim().split_once('=').ok_or(anyhow!(
                "Invalid connection string, expected '=' in field: {}",
                field
            ))?;
            Ok((key.to_string(), value.to_string()))
        })
        .collect()
}

fn collect_blob_development_config(
    key_values: &HashMap<String, String>,
    storage: &Service,
) -> Option<DevelopmentStorageConfig> {
    debug_assert!(
        storage == &Service::Blob,
        "Azurite Development Storage only supports Blob Storage"
    );

    // Azurite defaults.
    const AZURITE_DEFAULT_STORAGE_ACCOUNT_NAME: &str = "devstoreaccount1";
    const AZURITE_DEFAULT_STORAGE_ACCOUNT_KEY: &str =
        "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

    const AZURITE_DEFAULT_BLOB_URI: &str = "http://127.0.0.1:10000";

    if key_values.get("UseDevelopmentStorage") != Some(&"true".to_string()) {
        return None; // Not using development storage
    }

    let account_name = key_values
        .get("AccountName")
        .cloned()
        .unwrap_or(AZURITE_DEFAULT_STORAGE_ACCOUNT_NAME.to_string());
    let account_key = key_values
        .get("AccountKey")
        .cloned()
        .unwrap_or(AZURITE_DEFAULT_STORAGE_ACCOUNT_KEY.to_string());
    let development_proxy_uri = key_values
        .get("DevelopmentStorageProxyUri")
        .cloned()
        .unwrap_or(AZURITE_DEFAULT_BLOB_URI.to_string());

    Some(DevelopmentStorageConfig {
        endpoint: format!("{development_proxy_uri}/{account_name}"),
        account_name,
        account_key,
    })
}

/// Helper struct to hold development storage aka Azurite configuration.
struct DevelopmentStorageConfig {
    account_name: String,
    account_key: String,
    endpoint: String,
}

/// Parses an endpoint from the key-value pairs if possible.
///
/// Users are still able to later supplement configuration with an endpoint,
/// so endpoint-related fields aren't enforced.
fn collect_endpoint(
    key_values: &HashMap<String, String>,
    service: &Service,
) -> Result<Option<String>> {
    if let Some(key) = endpoint_key(service) {
        if let Some(endpoint) = key_values.get(key) {
            // If the endpoint is specified in the connection string, we use it directly.
            return Ok(Some(endpoint.clone()));
        }
    }

    // Fall back to building the endpoint string from individual parameters.
    if let Some(dfs_endpoint) = collect_endpoint_from_parts(key_values, service)? {
        Ok(Some(dfs_endpoint.clone()))
    } else {
        Ok(None)
    }
}

fn collect_credentials(key_values: &HashMap<String, String>) -> Option<Credential> {
    if let Some(token) = key_values.get("SharedAccessSignature") {
        Some(Credential::SasToken {
            token: token.clone(),
        })
    } else if let (Some(account_name), Some(account_key)) =
        (key_values.get("AccountName"), key_values.get("AccountKey"))
    {
        Some(Credential::SharedKey {
            account_name: account_name.clone(),
            account_key: account_key.clone(),
        })
    } else {
        // We default to no authentication. This is not an error because e.g.
        // Azure Active Directory configuration is typically not passed via
        // connection strings.
        // Users may also set credentials manually on the configuration.
        None
    }
}

fn set_credentials(config: &mut Config, creds: Credential) {
    match creds {
        Credential::SasToken { token } => {
            config.sas_token = Some(token);
        }
        Credential::SharedKey {
            account_name,
            account_key,
        } => {
            config.account_name = Some(account_name);
            config.account_key = Some(account_key);
        }
        Credential::BearerToken {
            token: _,
            expires_in: _,
        } => {
            // Bearer tokens shouldn't be passed via connection strings.
        }
    }
}

fn endpoint_key(service: &Service) -> Option<&str> {
    match service {
        Service::Blob => Some("BlobEndpoint"),
        Service::File => Some("FileEndpoint"),
        Service::Table => Some("TableEndpoint"),
        Service::Queue => Some("QueueEndpoint"),
        Service::Adls => None, // ADLS doesn't have a dedicated endpoint key
    }
}

fn collect_endpoint_from_parts(
    key_values: &HashMap<String, String>,
    service: &Service,
) -> Result<Option<String>> {
    let (account_name, endpoint_suffix) = match (
        key_values.get("AccountName"),
        key_values.get("EndpointSuffix"),
    ) {
        (Some(name), Some(suffix)) => (name, suffix),
        _ => return Ok(None), // Can't build an endpoint if one of them is missing
    };

    let protocol = key_values
        .get("DefaultEndpointsProtocol")
        .map(String::as_str)
        .unwrap_or("https"); // Default to HTTPS if not specified
    if protocol != "http" && protocol != "https" {
        return Err(anyhow!("Invalid DefaultEndpointsProtocol: {}", protocol,));
    }

    let service_endpoint_name = service.endpoint_name();

    Ok(Some(format!(
        "{protocol}://{account_name}.{service_endpoint_name}.{endpoint_suffix}"
    )))
}

#[cfg(test)]
mod tests {
    use crate::Config;

    use super::{parse, Service};

    #[test]
    fn test_parse() {
        let test_cases = vec![
            ("minimal fields",
                (Service::Blob, "BlobEndpoint=https://testaccount.blob.core.windows.net/"),
                Some(Config{
                    endpoint: Some("https://testaccount.blob.core.windows.net/".to_string()),
                    ..Default::default()
                }),
            ),
            ("basic creds and blob endpoint",
                (Service::Blob, "AccountName=testaccount;AccountKey=testkey;BlobEndpoint=https://testaccount.blob.core.windows.net/"),
                Some(Config{
                    account_name: Some("testaccount".to_string()),
                    account_key: Some("testkey".to_string()),
                    endpoint: Some("https://testaccount.blob.core.windows.net/".to_string()),
                     ..Default::default()
                    }),
            ),
            ("SAS token",
                (Service::Blob, "SharedAccessSignature=blablabla"),
                Some(Config{
                    sas_token: Some("blablabla".to_string()),
                    ..Default::default()
                }),
            ),
            ("endpoint from parts",
                (Service::Blob, "AccountName=testaccount;EndpointSuffix=core.windows.net;DefaultEndpointsProtocol=https"),
                Some(Config{
                    endpoint: Some("https://testaccount.blob.core.windows.net".to_string()),
                    account_name: Some("testaccount".to_string()),
                    ..Default::default()
                }),
            ),
            ("endpoint from parts and no protocol",
                (Service::Blob, "AccountName=testaccount;EndpointSuffix=core.windows.net"),
                Some(Config{
                    // Defaults to https
                    endpoint: Some("https://testaccount.blob.core.windows.net".to_string()),
                    account_name: Some("testaccount".to_string()),
                    ..Default::default()
                }),
            ),
            ("adls endpoint from parts",
                (Service::Adls, "AccountName=testaccount;EndpointSuffix=core.windows.net;DefaultEndpointsProtocol=https"),
                Some(Config{
                    account_name: Some("testaccount".to_string()),
                    endpoint: Some("https://testaccount.dfs.core.windows.net".to_string()),
                    ..Default::default()
                }),
            ),
            ("file endpoint from field",
                (Service::File, "FileEndpoint=https://testaccount.file.core.windows.net"),
                Some(Config{
                    endpoint: Some("https://testaccount.file.core.windows.net".to_string()),
                    ..Default::default()
                })
            ),
            ("file endpoint from parts",
                (Service::File, "AccountName=testaccount;EndpointSuffix=core.windows.net"),
                Some(Config{
                    account_name: Some("testaccount".to_string()),
                    endpoint: Some("https://testaccount.file.core.windows.net".to_string()),
                    ..Default::default()
                }),
            ),
            ("prefers sas over key",
                (Service::Blob, "AccountName=testaccount;AccountKey=testkey;SharedAccessSignature=sas_token"),
                Some(Config{
                    sas_token: Some("sas_token".to_string()),
                    account_name: Some("testaccount".to_string()),
                    ..Default::default()
                }),
            ),
            ("development storage",
                (Service::Blob, "UseDevelopmentStorage=true",),
                Some(Config{
                    account_name: Some("devstoreaccount1".to_string()),
                    account_key: Some("Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==".to_string()),
                    endpoint: Some("http://127.0.0.1:10000/devstoreaccount1".to_string()),
                    ..Default::default()
                }),
            ),
            ("development storage with custom account values",
                (Service::Blob, "UseDevelopmentStorage=true;AccountName=myAccount;AccountKey=myKey"),
                Some(Config {
                    endpoint: Some("http://127.0.0.1:10000/myAccount".to_string()),
                    account_name: Some("myAccount".to_string()),
                    account_key: Some("myKey".to_string()),
                    ..Default::default()
                }),
            ),
            ("development storage with custom uri",
                (Service::Blob, "UseDevelopmentStorage=true;DevelopmentStorageProxyUri=http://127.0.0.1:12345"),
                Some(Config {
                    endpoint: Some("http://127.0.0.1:12345/devstoreaccount1".to_string()),
                    account_name: Some("devstoreaccount1".to_string()),
                    account_key: Some("Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==".to_string()),
                    ..Default::default()
                }),
            ),
            ("unknown key is ignored",
                (Service::Blob, "SomeUnknownKey=123;BlobEndpoint=https://testaccount.blob.core.windows.net/"),
                Some(Config{
                    endpoint: Some("https://testaccount.blob.core.windows.net/".to_string()),
                    ..Default::default()
                }),
            ),
            ("leading and trailing `;`",
                (Service::Blob, ";AccountName=testaccount;"),
                Some(Config {
                    account_name: Some("testaccount".to_string()),
                    ..Default::default()
                }),
            ),
            ("line breaks",
                (Service::Blob, r#"
                    AccountName=testaccount;
                    AccountKey=testkey;
                    EndpointSuffix=core.windows.net;
                    DefaultEndpointsProtocol=https"#),
                Some(Config {
                    account_name: Some("testaccount".to_string()),
                    account_key: Some("testkey".to_string()),
                    endpoint: Some("https://testaccount.blob.core.windows.net".to_string()),
                    ..Default::default()
                }),
            ),
            ("missing equals",
                (Service::Blob, "AccountNameexample;AccountKey=example;EndpointSuffix=core.windows.net;DefaultEndpointsProtocol=https",),
                None, // This should fail due to missing '='
            ),
            ("with invalid protocol",
                (Service::Blob, "DefaultEndpointsProtocol=ftp;AccountName=example;EndpointSuffix=core.windows.net",),
                None, // This should fail due to invalid protocol
            ),
            ("azdls development storage",
                (Service::Adls, "UseDevelopmentStorage=true"),
                Some(Config::default()), // Azurite doesn't support ADLSv2, so we ignore this case
            ),
        ];

        for (name, (storage, conn_str), expected) in test_cases {
            let actual = parse(conn_str, &storage);

            if let Some(expected) = expected {
                assert!(actual.is_ok(), "Failed for case: {}", name);
                assert_eq!(actual.unwrap(), expected, "Failed for case: {}", name);
            } else {
                assert!(actual.is_err(), "Expected error for case: {}", name);
            }
        }
    }
}
