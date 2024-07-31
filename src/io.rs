pub async fn read_file_to_string(path: &str) -> std::io::Result<String> {
    #[cfg(target_arch = "wasm32")]
    return std::fs::read_to_string(path);
    #[cfg(not(target_arch = "wasm32"))]
    return tokio::fs::read_to_string(path).await;
}
