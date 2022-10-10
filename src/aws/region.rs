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
#[derive(Default)]
#[cfg_attr(test, derive(Debug))]
pub struct RegionLoader {
    region: Arc<RwLock<Option<String>>>,

    disable_env: bool,
    disable_profile: bool,

    config_loader: ConfigLoader,
}

impl RegionLoader {
    /// Disable load from env.
    pub fn with_disable_env(mut self) -> Self {
        self.disable_env = true;
        self
    }

    /// Disable load from profile.
    pub fn with_disable_profile(mut self) -> Self {
        self.disable_profile = true;
        self
    }

    /// Set static region.
    pub fn with_region(self, region: &str) -> Self {
        *self.region.write().expect("lock poisoned") = Some(region.to_string());

        self
    }

    /// Set config loader
    pub fn with_config_loader(mut self, cfg: ConfigLoader) -> Self {
        self.config_loader = cfg;
        self
    }

    /// Load region.
    pub fn load(&self) -> Option<String> {
        // Return cached credential if it's valid.
        if let Some(region) = self.region.read().expect("lock poisoned").clone() {
            return Some(region);
        }

        self.load_via_env()
            .or_else(|| self.load_via_profile())
            .map(|region| {
                let mut lock = self.region.write().expect("lock poisoned");
                *lock = Some(region.clone());

                region
            })
    }

    fn load_via_env(&self) -> Option<String> {
        if self.disable_env {
            return None;
        }

        self.config_loader.load_via_env();

        self.config_loader.region()
    }

    fn load_via_profile(&self) -> Option<String> {
        if self.disable_profile {
            return None;
        }

        self.config_loader.load_via_profile();

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
            let l = RegionLoader::default();
            let x = l.load();
            assert!(x.is_none());
        });
    }

    #[test]
    fn test_region_env_loader_with_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(vec![(AWS_REGION, Some("test"))], || {
            let l = RegionLoader::default();
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
                let l = RegionLoader::default();
                let x = l.load().expect("load must success");
                assert_eq!("test", x);
            },
        );
    }
}
