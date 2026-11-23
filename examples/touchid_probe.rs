//! Diagnostics for the `touchid` feature: availability and which protection level this build gets.
//! `cargo run --example touchid_probe --features touchid` (no prompt; stores and deletes a dummy item).
fn main() {
    #[cfg(all(feature = "touchid", target_os = "macos"))]
    {
        use onepw::touchid;
        println!("Touch ID available: {}", touchid::is_available());
        let dummy = onepw::UnlockKeys::from_bytes(&[7u8; 64]).unwrap();
        match touchid::save("__onepw_probe__", &dummy) {
            Ok(p) => println!("this build stores keys with protection: {p:?}"),
            Err(e) => println!("save failed: {e}"),
        }
        let _ = touchid::delete("__onepw_probe__");
    }
    #[cfg(not(all(feature = "touchid", target_os = "macos")))]
    println!("build with --features touchid on macOS");
}
