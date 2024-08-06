pub async fn read_file_to_string(path: &str) -> std::io::Result<String> {
    #[cfg(any(target_arch = "wasm32", feature = "blocking_io"))]
    return std::fs::read_to_string(path);
    #[cfg(all(
        not(target_arch = "wasm32"),
        all(feature = "tokio_fs", not(feature = "blocking_io"))
    ))]
    return tokio::fs::read_to_string(path).await;
}
