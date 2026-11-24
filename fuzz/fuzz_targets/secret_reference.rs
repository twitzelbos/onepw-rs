//! `op://vault/item/field` parsing (environment variables, `.env` files).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = onepw::SecretReference::parse(data);
});
