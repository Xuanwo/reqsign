use anyhow::Result;
#[tokio::test]
async fn test_get_object() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    Ok(())
}
