//! Loader is used to load credential or region from env.
//!
//! - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION
//! - The default credentials files located in ~/.aws/config and ~/.aws/credentials (location can vary per platform)
//! - Web Identity Token credentials from the environment or container (including EKS)
//! - ECS Container Credentials (IAM roles for tasks)
//! - EC2 Instance Metadata Service (IAM Roles attached to instance)

use std::sync::Arc;
use std::sync::RwLock;

use crate::aws::config::ConfigLoader;

/// RegionLoader will load region from different sources.
#[cfg_attr(test, derive(Debug))]
pub struct RegionLoader {
    region: Arc<RwLock<Option<String>>>,

    config_loader: ConfigLoader,
}

impl RegionLoader {
    /// Create a new region loader.
    pub fn new(cfg: ConfigLoader) -> Self {
        Self {
            region: Arc::default(),
            config_loader: cfg,
        }
    }

    /// Load region.
    pub fn load(&self) -> Option<String> {
        // Return cached credential if it's valid.
        if let Some(region) = self.region.read().expect("lock poisoned").clone() {
            return Some(region);
        }

        self.load_via_config().map(|region| {
            let mut lock = self.region.write().expect("lock poisoned");
            *lock = Some(region.clone());

            region
        })
    }

    fn load_via_config(&self) -> Option<String> {
        self.config_loader.region()
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;
    use crate::aws::constants::*;

    #[test]
    fn test_region_env_loader_without_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars_unset(vec![AWS_REGION], || {
            let l = RegionLoader::new(ConfigLoader::with_loaded());
            let x = l.load();
            assert!(x.is_none());
        });
    }

    #[test]
    fn test_region_env_loader_with_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(vec![(AWS_REGION, Some("test"))], || {
            let l = RegionLoader::new(ConfigLoader::with_loaded());
            let x = l.load().expect("load must success");
            assert_eq!("test", x);
        });
    }

    #[test]
    fn test_region_profile_loader() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![(
                AWS_CONFIG_FILE,
                Some(format!(
                    "{}/testdata/services/aws/default_config",
                    env::current_dir()
                        .expect("current_dir must exist")
                        .to_string_lossy()
                )),
            )],
            || {
                let l = RegionLoader::new(ConfigLoader::with_loaded());
                let x = l.load().expect("load must success");
                assert_eq!("test", x);
            },
        );
    }
}
