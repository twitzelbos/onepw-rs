//! Interpreting a server response body (JSON, encrypted envelopes, error objects).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    onepw::client::fuzzing::decode_response(data);
});
