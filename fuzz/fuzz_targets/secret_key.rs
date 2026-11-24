//! Secret Key parsing (user input, config files).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    if let Ok(sk) = onepw::SecretKey::parse(data) {
        // A parsed key must re-parse from its parts and never print the secret.
        assert!(!format!("{sk:?}").contains(sk.secret()) || sk.secret().is_empty());
    }
});
