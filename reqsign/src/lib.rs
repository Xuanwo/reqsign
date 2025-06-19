#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub use reqsign_core::*;

#[cfg(all(feature = "default-context", not(target_arch = "wasm32")))]
mod context;
#[cfg(all(feature = "default-context", not(target_arch = "wasm32")))]
pub use context::DefaultContext;

#[cfg(feature = "aliyun")]
pub mod aliyun {
    pub use reqsign_aliyun_oss::*;
}

#[cfg(feature = "aws")]
pub mod aws {
    pub use reqsign_aws_v4::*;
}

#[cfg(feature = "azure")]
pub mod azure {
    pub use reqsign_azure_storage::*;
}

#[cfg(feature = "google")]
pub mod google {
    pub use reqsign_google::*;
}

#[cfg(feature = "huaweicloud")]
pub mod huaweicloud {
    pub use reqsign_huaweicloud_obs::*;
}

#[cfg(feature = "oracle")]
pub mod oracle {
    pub use reqsign_oracle::*;
}

#[cfg(feature = "tencent")]
pub mod tencent {
    pub use reqsign_tencent_cos::*;
}
