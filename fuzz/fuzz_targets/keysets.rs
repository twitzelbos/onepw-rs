//! The keyset chain from `v1/account/keysets` (AES- and RSA-wrapped keys).
#![no_main]
use libfuzzer_sys::fuzz_target;
use onepw::keys::{EncryptedKeyset, SymmetricKey, decrypt_keysets};

fuzz_target!(|data: &[u8]| {
    if let Ok(sets) = serde_json::from_slice::<Vec<EncryptedKeyset>>(data) {
        let auk = SymmetricKey::new("mp", [1; 32]);
        let _ = decrypt_keysets(&sets, &auk);
    }
});
