//! The 1Password Secret Key (called "Account Key" internally), e.g.
//! `A3-8MMQJN-MZ64CY-2SDB4-RPX3T-V52Q3-N2C84`.
//!
//! Layout (white paper §3.2, §8.1): format version `A3`, a 6-character non-secret account ID,
//! then 26 random characters from `2-9 A-H J-N P-T V-Z` (≈ 2^128). Hyphens are only for
//! readability.

use std::fmt;
use std::str::FromStr;

use zeroize::Zeroizing;

use crate::error::{Error, Result};

const ALPHABET: &str = "23456789ABCDEFGHJKLMNPQRSTVWXYZ";
const SECRET_LEN: usize = 26;
const ACCOUNT_ID_LEN: usize = 6;

/// A parsed Secret Key. The secret part is zeroed on drop and never shown by `Debug`.
#[derive(Clone)]
pub struct SecretKey {
    format: String,
    account_id: String,
    secret: Zeroizing<String>,
}

impl SecretKey {
    /// Parses a Secret Key, ignoring case, hyphens and whitespace.
    ///
    /// ```
    /// use onepw::SecretKey;
    ///
    /// // The example key from the 1Password white paper.
    /// let key = SecretKey::parse("a3-8mmqjn mz64cy-2sdb4-rpx3t-v52q3-n2c84")?;
    /// assert_eq!(key.format(), "A3");
    /// assert_eq!(key.account_id(), "8MMQJN");
    /// assert!(!format!("{key:?}").contains("MZ64CY")); // the secret part is never printed
    ///
    /// // 0, 1, I, O and U never appear in Secret Keys.
    /// assert!(SecretKey::parse("A3-8MMQJN-MZ64CY-2SDB4-RPX3T-V52Q3-N2C8O").is_err());
    /// # Ok::<(), onepw::Error>(())
    /// ```
    pub fn parse(input: &str) -> Result<Self> {
        let clean: Zeroizing<String> = Zeroizing::new(
            input
                .chars()
                .filter(|c| *c != '-' && !c.is_whitespace())
                .collect::<String>()
                .to_ascii_uppercase(),
        );
        if !clean.starts_with("A3") {
            return Err(Error::Unsupported(
                "Secret Key format (only A3 keys are supported; the key should start with \"A3-\")"
                    .into(),
            ));
        }
        if clean.len() != 2 + ACCOUNT_ID_LEN + SECRET_LEN {
            return Err(Error::InvalidInput(format!(
                "Secret Key has {} characters after removing hyphens, expected {}",
                clean.len(),
                2 + ACCOUNT_ID_LEN + SECRET_LEN
            )));
        }
        let body = &clean[2..];
        if let Some(bad) = body.chars().find(|c| !ALPHABET.contains(*c)) {
            return Err(Error::InvalidInput(format!(
                "Secret Key contains {bad:?}, which is never used in Secret Keys (check 0/O, 1/I, U/V)"
            )));
        }
        Ok(SecretKey {
            format: clean[..2].to_string(),
            account_id: body[..ACCOUNT_ID_LEN].to_string(),
            secret: Zeroizing::new(body[ACCOUNT_ID_LEN..].to_string()),
        })
    }

    /// Format version, e.g. `"A3"`. Also used as HKDF `info` in key derivation.
    pub fn format(&self) -> &str {
        &self.format
    }

    /// The non-secret account ID (6 characters). The server calls it `skid` / `accountKeyUuid`.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// The 26 secret characters (uppercase, no hyphens).
    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl FromStr for SecretKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        SecretKey::parse(s)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecretKey({}-{}-<redacted>)",
            self.format, self.account_id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Example key from the 1Password white paper, Figure 8.3.
    const EXAMPLE: &str = "A3-8MMQJN-MZ64CY-2SDB4-RPX3T-V52Q3-N2C84";

    #[test]
    fn parses_white_paper_example() {
        let k = SecretKey::parse(EXAMPLE).unwrap();
        assert_eq!(k.format(), "A3");
        assert_eq!(k.account_id(), "8MMQJN");
        assert_eq!(k.secret(), "MZ64CY2SDB4RPX3TV52Q3N2C84");
    }

    #[test]
    fn ignores_case_spaces_and_hyphens() {
        let k = SecretKey::parse(" a3 8mmqjn mz64cy-2sdb4 rpx3t v52q3 n2c84 ").unwrap();
        assert_eq!(k.secret(), "MZ64CY2SDB4RPX3TV52Q3N2C84");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(SecretKey::parse("A2-8MMQJN-MZ64CY-2SDB4-RPX3T-V52Q3-N2C84").is_err());
        assert!(SecretKey::parse("A3-8MMQJN-MZ64CY").is_err());
        assert!(SecretKey::parse("A3-8MMQJN-MZ64CY-2SDB4-RPX3T-V52Q3-N2C8O").is_err()); // letter O
    }

    #[test]
    fn debug_hides_secret() {
        let k = SecretKey::parse(EXAMPLE).unwrap();
        let dbg = format!("{k:?}");
        assert!(!dbg.contains("MZ64CY"));
        assert!(dbg.contains("8MMQJN"));
    }
}
