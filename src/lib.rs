#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub(crate) mod b64;
pub mod client;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod mac;
pub mod secret_key;
pub mod srp;

pub use client::{
    Account, ClientIdentity, Credentials, Field, Item, SecretReference, SignInOptions, Vault,
};
pub use secret_key::SecretKey;

pub use error::{Error, Result};
