//! The server's SRP value B (hex on the wire) through validation and the session-key maths.
#![no_main]
use libfuzzer_sys::fuzz_target;
use onepw::srp;

fuzz_target!(|data: &str| {
    let Ok(b) = srp::from_server_hex(data) else { return };
    let client = srp::Client::standard_with_ephemeral(srp::rfc5054_4096(), &[3; 32], &[5; 38]);
    if let Ok(key) = client.session_key(&b) {
        let id = srp::identity("a@b.example", "ABCDEF");
        let m1 = client.client_proof(&b, &key, &id, b"salt");
        let _ = client.verify_server_confirmation(&m1, &key, data.as_bytes());
    }
});
