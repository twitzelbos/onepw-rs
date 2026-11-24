#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)] // exceptions: `locked` (mlock) and `touchid` (macOS FFI)
#![warn(missing_docs)]

pub(crate) mod b64;
pub mod client;
pub mod error;
pub mod kdf;
pub mod keys;
mod locked;
pub mod mac;
pub mod secret_key;
pub mod srp;
#[cfg(all(feature = "touchid", target_os = "macos"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "touchid", target_os = "macos"))))]
#[allow(unsafe_code)]
pub mod touchid;

pub use client::{
    Account, ClientIdentity, Credentials, Details, Field, Item, SecretReference, SignInOptions,
    UnlockKeys, Vault,
};
pub use secret_key::SecretKey;

pub use error::{Error, Result};
