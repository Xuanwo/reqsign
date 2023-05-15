use http::{HeaderValue, Method, Request};
use reqwest::{Client, Url};
use serde::Deserialize;
use std::str;

const MSI_API_VERSION: &str = "2019-08-01";
const MSI_ENDPOINT: &str = "http://169.254.169.254/metadata/identity/oauth2/token";

/// Attempts authentication using a managed identity that has been assigned to the deployment environment.
///
/// This authentication type works in Azure VMs, App Service and Azure Functions applications, as well as the Azure Cloud Shell
///
/// Built up from docs at [https://docs.microsoft.com/azure/app-service/overview-managed-identity#using-the-rest-protocol](https://docs.microsoft.com/azure/app-service/overview-managed-identity#using-the-rest-protocol)
#[derive(Clone, Debug)]
pub struct ImdsCredential {
    object_id: Option<String>,
    client_id: Option<String>,
    msi_res_id: Option<String>,
    msi_secret: Option<String>,
    endpoint: Option<String>,
}

impl Default for ImdsCredential {
    fn default() -> Self {
        Self::new()
    }
}

impl ImdsCredential {
    /// Creates a new instance of the ImdsCredential with default parameters.
    pub fn new() -> Self {
        Self {
            object_id: None,
            client_id: None,
            msi_res_id: None,
            msi_secret: None,
            endpoint: None,
        }
    }

    /// Specifies the endpoint from which the identity should be retrieved.
    ///
    /// If not specified, the default endpoint of `http://169.254.169.254/metadata/identity/oauth2/token` will be used.
    pub fn with_endpoint<A>(mut self, endpoint: A) -> Self
    where
        A: Into<String>,
    {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Specifies the header that should be used to retrieve the access token.
    ///
    /// This header mitigates server-side request forgery (SSRF) attacks.
    pub fn with_msi_secret<A>(mut self, msi_secret: A) -> Self
    where
        A: Into<String>,
    {
        self.msi_secret = Some(msi_secret.into());
        self
    }

    /// Specifies the object id associated with a user assigned managed service identity resource that should be used to retrieve the access token.
    ///
    /// The values of client_id and msi_res_id are discarded, as only one id parameter may be set when getting a token.
    pub fn with_object_id<A>(mut self, object_id: A) -> Self
    where
        A: Into<String>,
    {
        self.object_id = Some(object_id.into());
        self.client_id = None;
        self.msi_res_id = None;
        self
    }

    /// Specifies the application id (client id) associated with a user assigned managed service identity resource that should be used to retrieve the access token.
    ///
    /// The values of object_id and msi_res_id are discarded, as only one id parameter may be set when getting a token.
    pub fn with_client_id<A>(mut self, client_id: A) -> Self
    where
        A: Into<String>,
    {
        self.client_id = Some(client_id.into());
        self.object_id = None;
        self.msi_res_id = None;
        self
    }

    /// Specifies the ARM resource id of the user assigned managed service identity resource that should be used to retrieve the access token.
    ///
    /// The values of object_id and client_id are discarded, as only one id parameter may be set when getting a token.
    pub fn with_identity<A>(mut self, msi_res_id: A) -> Self
    where
        A: Into<String>,
    {
        self.msi_res_id = Some(msi_res_id.into());
        self.object_id = None;
        self.client_id = None;
        self
    }

    /// Gets an access token for the specified resource.
    pub async fn get_token(&self, resource: &str) -> anyhow::Result<AccessToken> {
        let endpoint = self.endpoint.as_deref().unwrap_or(MSI_ENDPOINT);
        let mut query_items = vec![("api-version", MSI_API_VERSION), ("resource", resource)];

        match (
            self.object_id.as_ref(),
            self.client_id.as_ref(),
            self.msi_res_id.as_ref(),
        ) {
            (Some(object_id), None, None) => query_items.push(("object_id", object_id)),
            (None, Some(client_id), None) => query_items.push(("client_id", client_id)),
            (None, None, Some(msi_res_id)) => query_items.push(("msi_res_id", msi_res_id)),
            _ => (),
        }

        let url = Url::parse_with_params(endpoint, &query_items)?;
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(url.to_string())
            .body("")?;

        req.headers_mut()
            .insert("metadata", HeaderValue::from_static("true"));

        if let Some(secret) = &self.msi_secret {
            req.headers_mut()
                .insert("x-identity-header", HeaderValue::from_str(secret)?);
        };

        let res = Client::new().execute(req.try_into()?).await?;
        let rsp_status = res.status();
        let rsp_body = res.text().await?;

        if !rsp_status.is_success() {
            return Err(anyhow::anyhow!("Failed to get token from IMDS endpoint"));
        }

        let token: AccessToken = serde_json::from_str(&rsp_body)?;
        println!("token = {:?}", token);

        Ok(token)
    }
}

// NOTE: expires_on is a String version of unix epoch time, not an integer.
// https://docs.microsoft.com/en-us/azure/app-service/overview-managed-identity?tabs=dotnet#rest-protocol-examples
#[derive(Debug, Clone, Deserialize)]
#[allow(unused)]
pub struct AccessToken {
    pub access_token: String,
    pub expires_on: String,
    pub token_type: String,
    pub resource: String,
}
