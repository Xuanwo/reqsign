use percent_encoding::AsciiSet;
use percent_encoding::NON_ALPHANUMERIC;

// Headers used in aws services.
pub const X_AMZ_CONTENT_SHA_256: &str = "x-amz-content-sha256";
pub const X_AMZ_DATE: &str = "x-amz-date";
pub const X_AMZ_SECURITY_TOKEN: &str = "x-amz-security-token";

// Env values used in aws services.
pub const AWS_ACCESS_KEY_ID: &str = "AWS_ACCESS_KEY_ID";
pub const AWS_SECRET_ACCESS_KEY: &str = "AWS_SECRET_ACCESS_KEY";
pub const AWS_SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";
pub const AWS_REGION: &str = "AWS_REGION";
pub const AWS_PROFILE: &str = "AWS_PROFILE";
pub const AWS_CONFIG_FILE: &str = "AWS_CONFIG_FILE";
pub const AWS_SHARED_CREDENTIALS_FILE: &str = "AWS_SHARED_CREDENTIALS_FILE";
pub const AWS_WEB_IDENTITY_TOKEN_FILE: &str = "AWS_WEB_IDENTITY_TOKEN_FILE";
pub const AWS_ROLE_ARN: &str = "AWS_ROLE_ARN";
pub const AWS_ROLE_SESSION_NAME: &str = "AWS_ROLE_SESSION_NAME";
pub const AWS_STS_REGIONAL_ENDPOINTS: &str = "AWS_STS_REGIONAL_ENDPOINTS";
pub const AWS_EC2_METADATA_DISABLED: &str = "AWS_EC2_METADATA_DISABLED";

/// AsciiSet for [AWS UriEncode](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html)
///
/// - URI encode every byte except the unreserved characters: 'A'-'Z', 'a'-'z', '0'-'9', '-', '.', '_', and '~'.
pub static AWS_URI_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// AsciiSet for [AWS UriEncode](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html)
///
/// But used in query.
pub static AWS_QUERY_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
