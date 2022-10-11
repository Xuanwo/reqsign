use std::collections::HashSet;

use once_cell::sync::Lazy;

// Please attention: the subsources are case sensitive.
static SUBRESOURCES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "CDNNotifyConfiguration",
        "acl",
        "append",
        "attname",
        "backtosource",
        "cors",
        "customdomain",
        "delete",
        "deletebucket",
        "directcoldaccess",
        "encryption",
        "inventory",
        "length",
        "lifecycle",
        "location",
        "logging",
        "metadata",
        "modify",
        "name",
        "notification",
        "partNumber",
        "policy",
        "position",
        "quota",
        "rename",
        "replication",
        "response-cache-control",
        "response-content-disposition",
        "response-content-encoding",
        "response-content-language",
        "response-content-type",
        "response-expires",
        "restore",
        "storageClass",
        "storagePolicy",
        "storageinfo",
        "tagging",
        "torrent",
        "truncate",
        "uploadId",
        "uploads",
        "versionId",
        "versioning",
        "versions",
        "website",
        "x-image-process",
        "x-image-save-bucket",
        "x-image-save-object",
        "x-obs-security-token",
    ])
});

pub(crate) fn is_subresource_param(param: &str) -> bool {
    SUBRESOURCES.contains(param)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a() {
        assert!(is_subresource_param("CDNNotifyConfiguration"));
        assert!(is_subresource_param("acl"));
        assert!(!is_subresource_param("delimiter"));
    }
}
