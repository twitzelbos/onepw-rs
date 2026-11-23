//! base64url helpers. 1Password objects use unpadded base64url, but be lenient on input.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use crate::error::Result;

/// Decodes base64url (padded or not) or, as a fallback, standard base64.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    let trimmed = s.trim_end_matches('=');
    match URL_SAFE_NO_PAD.decode(trimmed) {
        Ok(v) => Ok(v),
        Err(_) => Ok(STANDARD.decode(s)?),
    }
}

/// Encodes as unpadded base64url.
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
