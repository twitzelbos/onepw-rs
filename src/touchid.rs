//! **macOS only.** Touch ID unlock (feature `touchid`). This module doesn't exist on other
//! platforms; enabling the feature there is a no-op.
//!
//! After one sign-in with the password, the [`UnlockKeys`] (SRP `x` and the Account Unlock Key, not
//! the password) are stored in the macOS Keychain behind Touch ID. Later sign-ins use
//! [`load`] + [`Account::sign_in_with_keys`](crate::Account::sign_in_with_keys), which brings up
//! the Touch ID prompt instead of asking for the password.
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
//!   enforced by onepw, not by the hardware.

use std::sync::mpsc;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};
use security_framework::passwords::{self, AccessControlOptions, PasswordOptions};

use crate::client::UnlockKeys;
use crate::error::{Error, Result};

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
    let bytes = keys.to_bytes();
    let _ = delete(account);

    let mut o = biometry_options(account);
    o.set_access_control_options(AccessControlOptions::BIOMETRY_CURRENT_SET);
    match passwords::set_generic_password_options(bytes.as_ref(), o) {
        Ok(()) => return Ok(Protection::Biometry),
        Err(e) if e.code() == ERR_MISSING_ENTITLEMENT => {}
        Err(e) => return Err(Error::Protocol(format!("keychain: {e}"))),
    }
    passwords::set_generic_password(SERVICE, account, bytes.as_ref())
        .map_err(|e| Error::Protocol(format!("keychain: {e}")))?;
    Ok(Protection::TouchIdGate)
}

/// Loads the keys for `account`, showing the Touch ID prompt with `reason`.
pub fn load(account: &str, reason: &str) -> Result<(UnlockKeys, Protection)> {
    // Secure Enclave item: the system shows the Touch ID prompt itself.
    match passwords::generic_password(biometry_options(account)) {
        Ok(b) => return Ok((UnlockKeys::from_bytes(&b)?, Protection::Biometry)),
        Err(e) if e.code() == ERR_CANCELED || e.code() == ERR_AUTH_FAILED => {
            return Err(Error::InvalidInput(
                "Touch ID: cancelled or not recognised".into(),
            ));
        }
        Err(e) if e.code() == ERR_NOT_FOUND || e.code() == ERR_MISSING_ENTITLEMENT => {}
        Err(e) => return Err(Error::Protocol(format!("keychain: {e}"))),
    }
    // Fallback item: check Touch ID ourselves first.
    match passwords::get_generic_password(SERVICE, account) {
        Ok(b) => {
            authenticate(reason)?;
            Ok((UnlockKeys::from_bytes(&b)?, Protection::TouchIdGate))
        }
        Err(e) if e.code() == ERR_NOT_FOUND => Err(Error::InvalidInput(
            "Touch ID unlock is not set up for this account".into(),
        )),
        Err(e) => Err(Error::Protocol(format!("keychain: {e}"))),
    }
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
