//! **macOS only.** Touch ID unlock (feature `touchid`). This module doesn't exist on other
//! platforms; enabling the feature there is a no-op.
//!
//! After one sign-in with the password, the [`UnlockKeys`] (SRP `x` and the Account Unlock Key, not
//! the password) are stored in the macOS Keychain behind Touch ID. Later sign-ins use
//! [`load`] + [`Account::sign_in_with_keys`](crate::Account::sign_in_with_keys), which brings up
//! the Touch ID prompt instead of asking for the password.
//!
//! [`save_with_secret_key`] and [`load_with_secret_key`] keep the **Secret Key** in the same item,
//! so a sign-in reads one keychain item behind one Touch ID prompt. Items saved by [`save`] (or by
//! onepw 0.3.0 and earlier) have no Secret Key; [`load_with_secret_key`] then returns `None` for
//! it, and you can re-save with the Secret Key to upgrade the item.
//!
//! Two protection levels, picked automatically:
//!
//! * [`Protection::Biometry`]: the item lives in the *data protection* keychain with a
//!   `biometryCurrentSet` access control. The **Secure Enclave** refuses to release it without a
//!   Touch ID match of a currently enrolled finger (adding a fingerprint invalidates it). This
//!   needs the binary to be signed with a Developer ID and a keychain-access-groups entitlement.
//! * [`Protection::TouchIdGate`]: fallback for unsigned builds. onepw asks for Touch ID through
//!   LocalAuthentication and then reads a normal keychain item, whose ACL trusts only the
//!   binary that created it (other programs make macOS ask you first). The Touch ID check here is
//!   enforced by onepw, not by the hardware, and it doesn't stop malware running as you: it can
//!   launch the trusted onepw binary with an injected library (unsigned builds have no hardened
//!   runtime) and read the item without a prompt. Use a signed build for real protection.

use std::sync::mpsc;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{self, AccessControlOptions, PasswordOptions};
use zeroize::Zeroizing;

use crate::client::UnlockKeys;
use crate::error::{Error, Result};
use crate::secret_key::SecretKey;

const SERVICE: &str = "onepw-unlock";
/// `errSecMissingEntitlement`: the binary isn't signed with a keychain-access-groups entitlement.
const ERR_MISSING_ENTITLEMENT: i32 = -34018;
/// `errSecItemNotFound`.
const ERR_NOT_FOUND: i32 = -25300;
/// `errSecUserCanceled` / `errSecAuthFailed`.
const ERR_CANCELED: i32 = -128;
const ERR_AUTH_FAILED: i32 = -25293;

/// How the stored keys are protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    /// Secure Enclave enforced Touch ID (data protection keychain, `biometryCurrentSet`).
    Biometry,
    /// Touch ID checked by onepw, then an app-restricted (legacy) keychain item.
    TouchIdGate,
}

/// What [`load_with_secret_key`] found.
#[derive(Debug)]
pub struct Stored {
    /// The keys that replace the password.
    pub keys: UnlockKeys,
    /// The Secret Key, if the item was saved with [`save_with_secret_key`].
    pub secret_key: Option<SecretKey>,
    /// How the item is protected.
    pub protection: Protection,
}

/// Version byte of the item format that includes the Secret Key. The old format is exactly the
/// 64 bytes of [`UnlockKeys::to_bytes`], with no version byte.
const FORMAT_WITH_SECRET_KEY: u8 = 2;

/// `keys` (and `secret_key`) as stored in the keychain item.
fn encode(keys: &UnlockKeys, secret_key: Option<&SecretKey>) -> Zeroizing<Vec<u8>> {
    let k = keys.to_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(1 + 64 + 40));
    match secret_key {
        None => out.extend_from_slice(k.as_ref()),
        Some(sk) => {
            out.push(FORMAT_WITH_SECRET_KEY);
            out.extend_from_slice(k.as_ref());
            for part in [sk.format(), sk.account_id(), sk.secret()] {
                out.extend_from_slice(part.as_bytes());
            }
        }
    }
    out
}

fn decode(bytes: &[u8]) -> Result<(UnlockKeys, Option<SecretKey>)> {
    if bytes.len() == 64 {
        return Ok((UnlockKeys::from_bytes(bytes)?, None));
    }
    match bytes.split_first() {
        Some((&FORMAT_WITH_SECRET_KEY, rest)) if rest.len() > 64 => {
            let keys = UnlockKeys::from_bytes(&rest[..64])?;
            let text = Zeroizing::new(
                std::str::from_utf8(&rest[64..])
                    .map_err(|_| Error::Malformed("stored Secret Key is not text".into()))?
                    .to_owned(),
            );
            Ok((keys, Some(SecretKey::parse(&text)?)))
        }
        _ => Err(Error::Malformed(format!(
            "stored Touch ID item has an unknown format ({} bytes)",
            bytes.len()
        ))),
    }
}

/// Whether Touch ID is available and has enrolled fingers.
pub fn is_available() -> bool {
    // SAFETY: plain Objective-C calls on a freshly created LAContext.
    unsafe {
        LAContext::new().canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
    }
    .is_ok()
}

/// Shows the Touch ID prompt with `reason` (shown as "onepw wants to `reason`") and waits for the result.
pub fn authenticate(reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        // LocalAuthentication raises an Objective-C exception for an empty reason.
        return Err(Error::InvalidInput(
            "Touch ID: the reason must not be empty".into(),
        ));
    }
    // SAFETY: LAContext is created and used on this thread; the reply block only sends on a channel.
    unsafe {
        let ctx = LAContext::new();
        let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;
        if let Err(e) = ctx.canEvaluatePolicy_error(policy) {
            return Err(Error::Unsupported(format!(
                "Touch ID unavailable: {}",
                e.localizedDescription()
            )));
        }
        let (tx, rx) = mpsc::channel::<std::result::Result<(), String>>();
        let reply = RcBlock::new(move |ok: Bool, err: *mut NSError| {
            let res = if ok.as_bool() {
                Ok(())
            } else {
                Err(err
                    .as_ref()
                    .map(|e| e.localizedDescription().to_string())
                    .unwrap_or_else(|| "cancelled".into()))
            };
            let _ = tx.send(res);
        });
        ctx.setLocalizedFallbackTitle(Some(&NSString::from_str(""))); // hide "Enter Password"
        ctx.evaluatePolicy_localizedReason_reply(policy, &NSString::from_str(reason), &reply);
        match rx.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(msg)) => Err(Error::InvalidInput(format!("Touch ID: {msg}"))),
            Err(_) => Err(Error::Protocol(
                "Touch ID: no answer from LocalAuthentication".into(),
            )),
        }
    }
}

fn biometry_options(account: &str) -> PasswordOptions {
    let mut o = PasswordOptions::new_generic_password(SERVICE, account);
    o.use_protected_keychain();
    o
}

/// Saves `keys` for `account` (any stable label, e.g. `"you@example.com@my.1password.com"`).
/// Tries [`Protection::Biometry`] first and falls back to [`Protection::TouchIdGate`] when the
/// binary isn't entitled. Returns the protection that was used.
pub fn save(account: &str, keys: &UnlockKeys) -> Result<Protection> {
    store(account, &encode(keys, None))
}

/// Like [`save`], and also stores the Secret Key in the same item, so [`load_with_secret_key`]
/// needs only this one item.
pub fn save_with_secret_key(
    account: &str,
    keys: &UnlockKeys,
    secret_key: &SecretKey,
) -> Result<Protection> {
    store(account, &encode(keys, Some(secret_key)))
}

fn store(account: &str, bytes: &[u8]) -> Result<Protection> {
    let _ = delete(account);

    let mut o = biometry_options(account);
    // ThisDeviceOnly: the item never leaves this Mac (not in backups, not migrated to a new
    // machine), and it's deleted if the device passcode is removed.
    let access = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        AccessControlOptions::BIOMETRY_CURRENT_SET.bits(),
    )
    .map_err(|e| Error::Protocol(format!("keychain access control: {e}")))?;
    o.set_access_control(access);
    match passwords::set_generic_password_options(bytes, o) {
        Ok(()) => return Ok(Protection::Biometry),
        Err(e) if e.code() == ERR_MISSING_ENTITLEMENT => {}
        Err(e) => return Err(Error::Protocol(format!("keychain: {e}"))),
    }
    passwords::set_generic_password(SERVICE, account, bytes)
        .map_err(|e| Error::Protocol(format!("keychain: {e}")))?;
    Ok(Protection::TouchIdGate)
}

/// Loads the keys for `account`, showing the Touch ID prompt with `reason`. A stored Secret Key is
/// ignored (see [`load_with_secret_key`]).
pub fn load(account: &str, reason: &str) -> Result<(UnlockKeys, Protection)> {
    let s = load_with_secret_key(account, reason)?;
    Ok((s.keys, s.protection))
}

/// Loads the keys and, if it was saved with them, the Secret Key for `account`, showing the
/// Touch ID prompt with `reason`.
pub fn load_with_secret_key(account: &str, reason: &str) -> Result<Stored> {
    // Secure Enclave item: the system shows the Touch ID prompt itself.
    match passwords::generic_password(biometry_options(account)) {
        Ok(b) => {
            let b = Zeroizing::new(b);
            let (keys, secret_key) = decode(&b)?;
            return Ok(Stored {
                keys,
                secret_key,
                protection: Protection::Biometry,
            });
        }
        Err(e) if e.code() == ERR_CANCELED || e.code() == ERR_AUTH_FAILED => {
            return Err(Error::InvalidInput(
                "Touch ID: cancelled or not recognised".into(),
            ));
        }
        Err(e) if e.code() == ERR_NOT_FOUND || e.code() == ERR_MISSING_ENTITLEMENT => {}
        Err(e) => return Err(Error::Protocol(format!("keychain: {e}"))),
    }
    // Fallback item: check Touch ID ourselves, *before* reading the item's data. Look up its
    // attributes first (no data, no keychain prompt) so there's no pointless Touch ID prompt when
    // nothing is stored.
    if !fallback_item_exists(account) {
        return Err(Error::InvalidInput(
            "Touch ID unlock is not set up for this account".into(),
        ));
    }
    authenticate(reason)?;
    match passwords::get_generic_password(SERVICE, account) {
        Ok(b) => {
            let b = Zeroizing::new(b);
            let (keys, secret_key) = decode(&b)?;
            Ok(Stored {
                keys,
                secret_key,
                protection: Protection::TouchIdGate,
            })
        }
        Err(e) if e.code() == ERR_NOT_FOUND => Err(Error::InvalidInput(
            "Touch ID unlock is not set up for this account".into(),
        )),
        Err(e) => Err(Error::Protocol(format!("keychain: {e}"))),
    }
}

/// Whether the fallback (legacy keychain) item exists, without reading its data.
fn fallback_item_exists(account: &str) -> bool {
    use security_framework::item::{ItemClass, ItemSearchOptions};
    ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .service(SERVICE)
        .account(account)
        .load_attributes(true)
        .search()
        .is_ok_and(|r| !r.is_empty())
}

/// Removes stored keys for `account` (both protection levels).
pub fn delete(account: &str) -> Result<()> {
    let a = passwords::delete_generic_password_options(biometry_options(account));
    let b = passwords::delete_generic_password(SERVICE, account);
    if a.is_ok() || b.is_ok() {
        Ok(())
    } else {
        Err(Error::InvalidInput("nothing stored".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SK: &str = "A3-8MMQJN-MZ64CY-2SDB4-RPX3T-V52Q3-N2C84";

    fn keys() -> UnlockKeys {
        let b: Vec<u8> = (0..64).collect();
        UnlockKeys::from_bytes(&b).unwrap()
    }

    #[test]
    fn item_format_round_trips_with_and_without_secret_key() {
        let old = encode(&keys(), None);
        assert_eq!(old.len(), 64, "the 0.3.0 format is unchanged");
        let (k, sk) = decode(&old).unwrap();
        assert_eq!(*k.to_bytes(), *keys().to_bytes());
        assert!(sk.is_none());

        let sk = SecretKey::parse(SK).unwrap();
        let new = encode(&keys(), Some(&sk));
        assert_eq!(new[0], FORMAT_WITH_SECRET_KEY);
        let (k, back) = decode(&new).unwrap();
        assert_eq!(*k.to_bytes(), *keys().to_bytes());
        let back = back.unwrap();
        assert_eq!(
            (back.format(), back.account_id(), back.secret()),
            (sk.format(), sk.account_id(), sk.secret())
        );
    }

    #[test]
    fn unknown_item_formats_are_refused() {
        assert!(decode(&[]).is_err());
        assert!(decode(&[0u8; 63]).is_err());
        assert!(
            decode(&[FORMAT_WITH_SECRET_KEY; 65]).is_err(),
            "too short for keys + key"
        );
        let mut bad = encode(&keys(), Some(&SecretKey::parse(SK).unwrap()));
        bad[0] = 3;
        assert!(decode(&bad).is_err(), "unknown version");
    }
}
