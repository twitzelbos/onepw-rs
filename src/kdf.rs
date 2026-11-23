//! Two-Secret Key Derivation (2SKD), white paper §8.2, Figure 8.1:
//!
//! ```text
//! p   ← NFKD(trim(password))
//! s   ← HKDF-SHA256(ikm = salt, salt = lowercase(email), info = label,   len = 32)
//! k_m ← PBKDF2-HMAC-SHA256(p, s, iterations, 32)
//! k_A ← HKDF-SHA256(ikm = secret,  salt = account ID,     info = format, len = 32)
//! out ← k_m ⊕ k_A
//! ```
//!
//! The same function yields the **Account Unlock Key** (`label` = the key's `alg`, e.g.
//! `"PBES2g-HS256"`, with the `p2s`/`p2c` of the encrypted symmetric key) and the **SRP secret
//! x** (`label` = the SRP method, e.g. `"SRPg-4096"`, with the salt and iterations from the auth
//! response).

use hkdf::Hkdf;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::SymmetricKey;
use crate::secret_key::SecretKey;

/// The only derivation algorithm 1Password uses today.
pub const ALG_PBES2G_HS256: &str = "PBES2g-HS256";

/// Account password preprocessing: trim surrounding whitespace, then Unicode NFKD.
pub fn normalize_password(password: &str) -> Zeroizing<String> {
    Zeroizing::new(password.trim().nfkd().collect::<String>())
}

/// SRP method of the 4096-bit group.
pub const SRP_METHOD_4096: &str = "SRPg-4096";

/// Runs 2SKD and returns the 32-byte result. `label` is the HKDF info for the salt stretch:
/// the `alg` for the Account Unlock Key, the SRP `method` for SRP-x.
pub fn two_secret_kdf(
    password: &str,
    secret_key: &SecretKey,
    email: &str,
    label: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let alg = label;
    if iterations == 0 {
        return Err(Error::Malformed("iteration count is 0".into()));
    }
    let email = email.trim().to_lowercase();

    let mut stretched_salt = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(email.as_bytes()), salt)
        .expand(alg.as_bytes(), stretched_salt.as_mut())
        .expect("32 bytes is a valid HKDF length");

    let password = normalize_password(password);
    let mut out = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), stretched_salt.as_ref(), iterations, out.as_mut());

    let mut k_a = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(secret_key.account_id().as_bytes()), secret_key.secret().as_bytes())
        .expand(secret_key.format().as_bytes(), k_a.as_mut())
        .expect("32 bytes is a valid HKDF length");

    for (o, k) in out.iter_mut().zip(k_a.iter()) {
        *o ^= k;
    }
    Ok(out)
}

/// Derives the Account Unlock Key (`kid = "mp"`) from the parameters stored next to the
/// encrypted symmetric key (`alg`, `p2s`, `p2c`).
pub fn account_unlock_key(
    password: &str,
    secret_key: &SecretKey,
    email: &str,
    alg: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<SymmetricKey> {
    if alg != ALG_PBES2G_HS256 {
        return Err(Error::Unsupported(format!("key derivation algorithm {alg:?}")));
    }
    let k = two_secret_kdf(password, secret_key, email, alg, salt, iterations)?;
    Ok(SymmetricKey::new("mp", *k))
}

/// Derives the SRP secret `x` for the given SRP method (e.g. `"SRPg-4096"`) and the salt and
/// iterations from the auth response.
pub fn srp_x(
    password: &str,
    secret_key: &SecretKey,
    email: &str,
    method: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    if method != SRP_METHOD_4096 {
        return Err(Error::Unsupported(format!("SRP method {method:?}")));
    }
    two_secret_kdf(password, secret_key, email, method, salt, iterations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_normalization_matches_white_paper() {
        // §8.2.2: "Å" in any encoding becomes U+0041 U+030A; surrounding whitespace is removed,
        // inner whitespace kept.
        for p in ["\u{212B}", "\u{00C5}", "A\u{030A}"] {
            assert_eq!(normalize_password(&format!("  {p} x\t")).as_str(), "A\u{030A} x");
        }
    }

    #[test]
    fn derivation_is_deterministic_and_uses_both_secrets() {
        let sk = SecretKey::parse("A3-8MMQJN-MZ64CY-2SDB4-RPX3T-V52Q3-N2C84").unwrap();
        let sk2 = SecretKey::parse("A3-8MMQJN-MZ64CY-2SDB4-RPX3T-V52Q3-N2C85").unwrap();
        let salt = [9u8; 16];
        let a = two_secret_kdf("pw", &sk, "Patty@Dogs.Example", ALG_PBES2G_HS256, &salt, 100).unwrap();
        let b = two_secret_kdf("pw", &sk, "patty@dogs.example", ALG_PBES2G_HS256, &salt, 100).unwrap();
        assert_eq!(*a, *b, "email is case-insensitive");
        let c = two_secret_kdf("pw2", &sk, "patty@dogs.example", ALG_PBES2G_HS256, &salt, 100).unwrap();
        let d = two_secret_kdf("pw", &sk2, "patty@dogs.example", ALG_PBES2G_HS256, &salt, 100).unwrap();
        assert_ne!(*a, *c);
        assert_ne!(*a, *d);
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let sk = SecretKey::parse("A3-8MMQJN-MZ64CY-2SDB4-RPX3T-V52Q3-N2C84").unwrap();
        assert!(account_unlock_key("pw", &sk, "e@x", "PBES2-HS512", &[0; 16], 1).is_err());
        assert!(srp_x("pw", &sk, "e@x", "SRPg-2048", &[0; 16], 1).is_err());
    }

    #[test]
    fn auk_and_srp_x_differ_by_label() {
        let sk = SecretKey::parse("A3-8MMQJN-MZ64CY-2SDB4-RPX3T-V52Q3-N2C84").unwrap();
        let auk = account_unlock_key("pw", &sk, "e@x", ALG_PBES2G_HS256, &[1; 16], 10).unwrap();
        let x = srp_x("pw", &sk, "e@x", SRP_METHOD_4096, &[1; 16], 10).unwrap();
        assert_ne!(auk.as_bytes(), &*x);
    }
}
