//! Provide common request trait for signing.

use std::mem;
use std::str::FromStr;

use anyhow::anyhow;
use anyhow::Result;
use http::uri::PathAndQuery;
use http::uri::Scheme;
use http::Uri;

use crate::ctx::SigningContext;

/// Trait for all signable request.
///
/// Any request type that implement this trait can be used by signers as input.
/// Different requests may have different uri implementations, so we return detailed
/// uri components instead of a complete struct.
pub trait SignableRequest {
    fn build(&mut self) -> Result<SigningContext>;

    fn apply(&mut self, _ctx: SigningContext) -> Result<()>;
}
