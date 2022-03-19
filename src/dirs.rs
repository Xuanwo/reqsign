//! Directory related utils.

/// Expand `~` in input path.
///
/// - If path not starts with `~/` or `~\\`, returns `Some(path)` directly.
/// - Otherwise, replace `~` with home dir instead.
/// - If home_dir is not found, returns `None`.
pub fn expand_homedir(path: &str) -> Option<String> {
    if !path.starts_with("~/") && !path.starts_with("~\\") {
        Some(path.to_string())
    } else {
        dirs::home_dir().map(|home| path.replace('~', &home.to_string_lossy()))
    }
}
