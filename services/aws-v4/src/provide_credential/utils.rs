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
pub fn sts_endpoint(region: Option<&str>, use_regional: bool) -> Result<String> {
    // use regional sts if use_regional has been set.
    if use_regional {
        let region =
            region.ok_or_else(|| Error::config_invalid("regional STS endpoint requires region"))?;
        if region.starts_with("cn-") {
            Ok(format!("sts.{region}.amazonaws.com.cn"))
        } else {
            Ok(format!("sts.{region}.amazonaws.com"))
        }
    } else {
        let region = region.unwrap_or_default();
        if region.starts_with("cn") {
            // TODO: seems aws china doesn't support global sts?
            Ok("sts.amazonaws.com.cn".to_string())
        } else {
            Ok("sts.amazonaws.com".to_string())
        }
    }
}
