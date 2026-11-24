//! JWK parsing into AES and RSA keys (RSA component decoding, key validation).
#![no_main]
use libfuzzer_sys::fuzz_target;
use onepw::keys::{EncryptedObject, Jwk, PrivateKey, SymmetricKey};

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return; // real JWKs are < 4 KiB; keep RSA validation fast
    }
    let Ok(jwk) = serde_json::from_slice::<Jwk>(data) else { return };
    let _ = SymmetricKey::from_jwk(&jwk);
    if let Ok(key) = PrivateKey::from_jwk(&jwk) {
        let _ = key.decrypt(&data[..data.len().min(256)]);
        let obj = EncryptedObject {
            kid: key.kid().into(),
            enc: "RSA-OAEP".into(),
            cty: "b5+jwk+json".into(),
            iv: String::new(),
            data: "AAAA".into(),
            alg: None,
            p2s: None,
            p2c: None,
        };
        let _ = key.decrypt_object_jwk(&obj);
    }
});
