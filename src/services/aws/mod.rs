//! AWS service signer

pub mod v4;

mod constants;
mod credential;
mod loader;

#[cfg(test)]
mod tests;
