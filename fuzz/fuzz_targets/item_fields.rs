//! Flattening decrypted item details into fields (`fields()`, `field()`).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&[u8], &str)| {
    onepw::client::fuzzing::item_fields(input.0, input.1);
});
