use crate::Config;
use reqsign_core::{Error, Result};

/// Get the sts endpoint.
///
/// The returning format may look like `sts.{region}.amazonaws.com`
///
/// # Notes
///
/// AWS could have different sts endpoint based on it's region.
/// We can check them by region name.
///
/// ref: https://github.com/awslabs/aws-sdk-rust/blob/31cfae2cf23be0c68a47357070dea1aee9227e3a/sdk/sts/src/aws_endpoint.rs
pub fn sts_endpoint(config: &Config) -> Result<String> {
    // use regional sts if sts_regional_endpoints has been set.
    if config.sts_regional_endpoints == "regional" {
        let region = config.region.clone().ok_or_else(|| {
            Error::config_invalid("sts_regional_endpoints set to regional, but region is not set")
        })?;
        if region.starts_with("cn-") {
            Ok(format!("sts.{region}.amazonaws.com.cn"))
        } else {
            Ok(format!("sts.{region}.amazonaws.com"))
        }
    } else {
        let region = config.region.clone().unwrap_or_default();
        if region.starts_with("cn") {
            // TODO: seems aws china doesn't support global sts?
            Ok("sts.amazonaws.com.cn".to_string())
        } else {
            Ok("sts.amazonaws.com".to_string())
        }
    }
}
