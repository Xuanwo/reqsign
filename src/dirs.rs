pub fn expand_homedir(path: &str) -> Option<String> {
    if !path.starts_with("~/") && !path.starts_with("~\\") {
        Some(path.to_string())
    } else {
        dirs::home_dir().map(|home| path.replace('~', &home.to_string_lossy()))
    }
}
