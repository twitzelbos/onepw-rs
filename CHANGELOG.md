# Changelog

## 0.2.0 (2026-11-23)

### Added
- `onepw` command-line tool (feature `cli`): `account add|show|forget|touch-id`, `vault list`,
  `item list|get`, `read op://…`, `run -- cmd` (replaces `op://` references in the environment).
  The Secret Key is stored in the system keychain; the account password is never stored.
- Touch ID unlock (feature `touchid`, **macOS only**; a no-op elsewhere): `onepw::touchid` stores
  the derived `UnlockKeys` (not the password) in the Keychain behind Touch ID. Secure Enclave
  enforced for signed, entitled builds; LocalAuthentication-gated otherwise.
- `UnlockKeys` and `Account::sign_in_with_keys` / `Account::unlock_keys`.
- `SecretReference` (`op://vault/item/field`), `Item::fields()`, `Item::urls()`.
- docs.rs builds for macOS too, with platform badges on macOS-only items.

## 0.1.0 (2026-11-23)

- First release: pure-Rust sign-in (2SKD, SRP-6a, TOTP), keyset and vault key decryption,
  read-only access to vaults and items.
