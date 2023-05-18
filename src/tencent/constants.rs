use percent_encoding::AsciiSet;
use percent_encoding::NON_ALPHANUMERIC;

/// AsciiSet for [Tencent UriEncode](https://cloud.tencent.com/document/product/436/7778)
pub static TENCENT_URI_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
