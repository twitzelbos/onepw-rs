# Changelog

## 0.3.2 (2026-11-24)

### Changed
- `sha2` 0.11.1 (fixes how round constants are loaded on AArch64, including Apple Silicon).
- `num-bigint-dig` 0.9.1 (used only for public SRP values). Its 0.9 release moved to rand 0.9,
  but only behind optional features (`std`, `prime`) that onepw doesn't enable. So the upgrade
  adds no second copy of rand, and it drops the `spin` dependency.

## 0.3.1 (2026-11-24)

### Fixed
- **Linux: the CLI's Secret Key survives a reboot.** It's now stored in the Secret Service (GNOME
  Keyring, KWallet, KeePassXC) instead of the kernel keyring, which is emptied on reboot. A key
  still in the kernel keyring is moved over on first use. Building the CLI on Linux now needs the
  D-Bus headers (`libdbus-1-dev`). Without a running Secret Service (headless servers), set
  `ONEPW_SECRET_KEY`.

### Changed
- **Touch ID: one keychain item, one prompt.** The Secret Key is stored with the unlock keys in the
  Touch ID item, so a sign-in reads one item instead of two (one macOS keychain prompt after a
  rebuild instead of two, and at the Secure Enclave level the Secret Key is behind Touch ID too).
  Items saved by 0.3.0 are upgraded on the next Touch ID sign-in.

### Added
- `touchid::save_with_secret_key`, `touchid::load_with_secret_key` and `touchid::Stored`. `save`
  and `load` are unchanged.

## 0.3.0 (2026-11-24)

A security release. Upgrading is strongly recommended: 0.2.0 and earlier accept unencrypted
server responses after sign-in (see "Security").

### Security
- **After sign-in, only responses encrypted with the session key are accepted.** 0.2.0 accepted
  plaintext responses, which let an interceptor with a trusted TLS certificate (for example a
  TLS-inspecting proxy) inject or hide vaults and items. A plaintext object with an `errorCode` is
  now only ever treated as an error, and an empty body is refused wherever data is expected.
- Sign-in is refused if the server asks for fewer than 100 000 PBKDF2 iterations, for either the
  SRP secret or the Account Unlock Key (`SignInOptions::min_kdf_iterations`).
- Only 1Password's own domains are contacted (`*.1password.com/.ca/.eu`, HTTPS); override with
  `SignInOptions::allow_any_host`. HTTP redirects are no longer followed. Connect (15 s) and
  request (120 s, `SignInOptions::timeout`) timeouts, a 64 MiB response limit, and a cap on item
  pages.
- Constant-time SRP: secret-dependent maths uses `crypto-bigint` with fixed 1024-bit exponents.
- `rsa` 0.10 (fixes the Marvin timing attack, RUSTSEC-2023-0071), with blinded decryption.
- Keys (session key, Account Unlock Key, SRP `x`, keyset and vault keys) live in their own
  `mlock`ed memory pages, excluded from core dumps on Linux and zeroed before being freed.
- Item details are decrypted only on demand; field values are wiped on drop; `Debug` on `Item`,
  `Field` and `Details` no longer prints secret values.
- `op://` references and `onepw item get [--vault]` refuse ambiguous names (two vaults with the
  same name, two items with the same title); `Private` always means the personal vault and never
  a shared vault named "Private".
- CLI: `onepw run` no longer passes `ONEPW_PASSWORD` / `ONEPW_SECRET_KEY` (any `ONEPW_*`) to the
  command, and no longer panics (printing the value) on a non-UTF-8 environment variable.
  `item get` hides every field whose kind isn't known to be plain text (e.g. SSH keys) unless
  `--reveal`, and builds its output in a buffer that is wiped, including when it grows. Core
  dumps are disabled.
- Touch ID: the fallback level asks for Touch ID *before* reading the keychain item; the Secure
  Enclave item is `ThisDeviceOnly`; keychain buffers are wiped; an empty prompt reason is refused.

### Changed (breaking)
- Item details are no longer decrypted by `Account::items`. They stay encrypted in the `Item` and
  are decrypted on demand by `Item::details()`, `Item::fields()` and `Item::field()`, which now
  return `Result`. The public `Item::details` field is replaced by the `details()` method.
- `Item::field` returns `Result<Option<Zeroizing<String>>>`; `Field::value` is a `Zeroizing<String>`.
- `SignInOptions` has new public fields: `min_kdf_iterations`, `allow_any_host`, `timeout`.
- `SecretReference::find_vault` no longer falls back to a vault *named* "Private" when the
  personal vault isn't readable.
- The RustCrypto dependencies moved to their current generation (`rsa` 0.10, `sha2` 0.11, `hmac`
  0.13, `aes-gcm` 0.11, `rand` 0.10, …). Minimum Rust version is now **1.88**.

### Added
- `Details`: decrypted item JSON (derefs to `serde_json::Value`) whose strings are zeroed on drop.
- `client::find_vault`, `client::MIN_KDF_ITERATIONS`, `client::ONEPASSWORD_DOMAINS`.
- `SECURITY.md` (threat model, private vulnerability reporting); fuzz targets in `fuzz/` (weekly
  in CI); `cargo-deny` and an MSRV check in CI; CI actions pinned by commit SHA with read-only
  permissions; Dependabot.

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
