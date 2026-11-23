//! Unofficial, pure-Rust client for 1Password accounts.
//!
//! **Not affiliated with, endorsed by, or supported by AgileBits Inc. / 1Password.**
//! 1Password's server API is not publicly documented; this crate implements the cryptography
//! described in the *1Password Security Design* white paper and in 1Password's open-source SRP
//! library, plus a reverse-engineered transport. It may stop working at any time.
//! For production use, prefer the official `op` CLI or the official SDKs.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod b64;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod secret_key;
pub mod srp;

pub use secret_key::SecretKey;

pub use error::{Error, Result};
