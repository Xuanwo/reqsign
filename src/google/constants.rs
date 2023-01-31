use percent_encoding::AsciiSet;
use percent_encoding::NON_ALPHANUMERIC;

// Env values used in google services.
pub const GOOGLE_APPLICATION_CREDENTIALS: &str = "GOOGLE_APPLICATION_CREDENTIALS";

pub const X_GOOG_DATE: &str = "x-goog-date";
pub const X_GOOG_CONTENT_SHA_256: &str = "x-goog-content-sha256";
pub const X_GOOG_SECURITY_TOKEN: &str = "x-goog-security-token";

/// AsciiSet for [AWS UriEncode](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html)
///
/// - URI encode every byte except the unreserved characters: 'A'-'Z', 'a'-'z', '0'-'9', '-', '.', '_', and '~'.
pub static GOOG_URI_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// AsciiSet for [AWS UriEncode](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html)
///
/// But used in query.
pub static GOOG_QUERY_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
