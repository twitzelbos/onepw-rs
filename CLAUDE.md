# CLAUDE.md: onepw

Context for working on this repository. Read it fully before changing protocol or crypto code.

## What this is

`onepw` is an **unofficial, pure-Rust client for 1Password accounts**. It signs in with account password + Secret Key over SRP, unlocks the user's keysets, and reads vaults, items and `op://` secret references, talking to 1Password's servers directly. It needs neither the `op` CLI nor the desktop app. It is read-only.

- Crate: `onepw` on crates.io. **v0.2.0 is published** (library + CLI + Touch ID, 2026-11-23, tag `v0.2.0`; v0.1.0 was library only).
- Repo: github.com/twitzelbos/onepw-rs (public). Crate name `onepw`, repo name `onepw-rs`.
- License: MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`; `LICENSE` is GitHub's Apache copy, kept). `NOTICE` credits 1Password's Apache-2.0 SRP test vectors.
- Not affiliated with AgileBits/1Password. The README says so up front; keep it that way. Never brand anything as official.

## Status

| Area | State |
|---|---|
| Crypto core (SRP, 2SKD, Secret Key, AES-GCM/RSA-OAEP, keysets) | Done. Matches 1Password's published test vectors |
| Request MAC + session encryption | Done. Matches 1Password's published vectors |
| Sign-in against the **real** service | **Verified 2026-11-23** on the maintainer's individual account (my.1password.com): personal + shared vault, every item decrypted, counts matched the server |
| CLI (`--features cli`) | Done, in CI, published in 0.2.0 (`cargo install onepw --features cli`) |
| Touch ID (`--features touchid`, macOS) | Library and CLI done. Interactive flow (add → touch-id on → Touch ID prompt → vault list/read/run, cancel → password fallback, off) **verified by the maintainer on 2026-11-23** at the TouchIdGate level. Secure Enclave level needs signing (see "Open work") |
| 2FA | TOTP only. WebAuthn/Duo/SSO unsupported |
| Writing items | Not implemented |

Released in v0.2.0: the CLI, `SecretReference`, `Item::fields()/urls()`, `UnlockKeys` + `Account::sign_in_with_keys`, the `touchid` module, the macOS-only markings. See CHANGELOG.md.

## Layout

```
src/lib.rs           crate docs = README.md (include_str!), module list, re-exports.
                     #![deny(unsafe_code)]; the only exception is touchid (#[allow(unsafe_code)])
src/error.rs         Error enum (InvalidInput, Unsupported, Protocol, Decrypt, Malformed, Server{status,body}, Http)
src/b64.rs           base64url helpers (lenient decode: padded/unpadded/standard)
src/secret_key.rs    SecretKey parse (A3 + 6-char account id + 26 secret chars, alphabet 2-9 A-H J-N P-T V-Z)
src/kdf.rs           2SKD: two_secret_kdf, account_unlock_key (label = alg), srp_x (label = SRP method)
src/srp/mod.rs       SRP-6a client; Variant::Standard (current flow) and Variant::Legacy; identity(); server_hex
src/srp/u_vectors.rs generated from 1Password/srp Go tests (cfg(test) only)
src/keys.rs          EncryptedObject envelope, SymmetricKey, PrivateKey (RSA JWK), Jwk, EncryptedKeyset, decrypt_keysets
src/mac.rs           X-AgileBits-MAC request signing
src/client.rs        Account (sign_in / sign_in_with_keys / vaults / items / read / sign_out), Rest (HTTP plumbing),
                     ClientIdentity, Credentials, SignInOptions, UnlockKeys, Vault, Item, Field, SecretReference
src/touchid.rs       macOS only: LocalAuthentication + Keychain storage of UnlockKeys
src/bin/onepw.rs     CLI (required-features = ["cli"])
tests/mock_server.rs end-to-end tests against a simulated 1Password server (wiremock)
examples/try_account.rs   real-account smoke test (prints no secrets)
examples/touchid_probe.rs Touch ID availability + which protection level this build gets
.github/workflows/ci.yml  ubuntu + macos: test (--features cli), doc tests, clippy -D warnings, rustdoc -D warnings
```

## The protocol (what the code implements)

### Key derivation (2SKD), `kdf.rs`
```
p   = NFKD(trim(password))
s   = HKDF-SHA256(ikm = 16-byte salt, salt = lowercase(trim(email)), info = LABEL, len 32)
k_m = PBKDF2-HMAC-SHA256(p, s, iterations, 32)        # iterations from the server (650 000 now; older accounts fewer)
k_A = HKDF-SHA256(ikm = 26 secret chars, salt = account id (6 chars), info = format "A3", len 32)
out = k_m XOR k_A
```
- **AUK** (Account Unlock Key, kid `"mp"`): LABEL = the encSymKey's `alg` (`"PBES2g-HS256"`), salt/iterations = `p2s`/`p2c` of the primary keyset's `encSymKey`.
- **SRP x**: LABEL = the SRP method (`"SRPg-4096"`), salt/iterations from `userAuth` in the auth/start response.

### SRP, `srp/mod.rs`
- Group: RFC 5054 / RFC 3526 4096-bit, g = 5. SHA-256 everywhere.
- **Standard variant (current login flow, used by `Account`)**: `k = SHA256(N ‖ PAD(g))`, `u = SHA256(PAD(A) ‖ PAD(B))` (padded to len(N)), `K = SHA256(lowercase-hex(S) without leading zeros)`. That's the hash of the *hex string*, not of bytes.
- **Client proves first**: `M1 = SHA256((H(N) ⊕ H(g)) ‖ H(I) ‖ salt ‖ A ‖ B ‖ K)` with unpadded big-endian A, B. The server answers `SHA256(A ‖ M1 ‖ K)`.
- **Identity**: `I = base64url_nopad(SHA256( SHA256(account_id) ‖ SHA256(lowercase(NFKD(trim(email)))) ))`, and `H(I)` = SHA256 of that *string*. ⚠️ The outer SHA256 is essential. Missing it caused the first real-account failure (401 at confirm-key).
- Legacy variant (Go library default / older flow): caller-supplied k (or `SHA256(N ‖ g)`), u over hex strings, server proves first. Kept with the official test vectors, but unused by `Account`.
- Wire encoding of A/B: lowercase hex, leading zeros stripped (`server_hex` / `from_server_hex`).

### Login flow, `client.rs`
Base URL `https://{sign_in_address}/api/`. Headers on every request: `X-AgileBits-Client: {clientName}/{clientVersion}`, the same as `User-Agent`, and `OP-User-Agent: 1|M|{version}|{deviceUuid}|||reqwest|0.13|{platform}`. Defaults mimic the desktop app because the server's WAF rejects unfamiliar clients. The **device name is `onepw`**, so users can recognise and revoke it.

1. `POST v3/auth/start` `{email, skFormat, skid, deviceUuid, userUuid:""}` → `{status, sessionID, accountKeyFormat, accountKeyUuid, userAuth{method, alg, iterations, salt}}`. Status `device-not-registered` → `POST v1/device` (with `X-AgileBits-Session-ID`) and retry. `device-deleted` → `PUT v1/device/{uuid}/reauthorize`.
2. `POST v2/auth` `{userA}` → `{userB}`.
3. `POST v2/auth/confirm-key` `{clientVerifyHash: b64(M1)}` → `{serverVerifyHash}`. **A bare 401 here = wrong password/Secret Key** (or stale UnlockKeys).
4. From here on, bodies are encrypted with K (envelope `{kid: sessionID, enc:"A256GCM", cty:"b5+jwk+json", iv, data}`) and every request carries `X-AgileBits-MAC`. `POST v2/auth/complete` `{client, device}`. The response may include `mfa` → `POST v1/auth/mfa` `{sessionID, client, totp:{code}}`. **A wrong TOTP code kills the session.**
5. `GET v1/account/keysets` → primary keyset = `encryptedBy == "mp"` with the highest `sn`. Derive the AUK, then `decrypt_keysets`.
6. `GET v1/account?attrs=me,vaults` → vaults with `access[]` (`acl & 32` = readable, `encVaultKey` RSA-wrapped for a keyset) and `encAttrs` (name).
7. `GET v1/vault/{uuid}/{batch}/items`, starting at batch 0, then `contentVersion` until `batchComplete`. `encOverview`/`encDetails` are AES-GCM under the vault key.
8. `PUT v1/session/signout`.

Encrypted error responses can come back as HTTP 200 with `{errorCode, errorMessage}`. `Rest::send` turns those into `Error::Server`.

### MAC, `mac.rs`
`mac_key = HMAC-SHA256(K, "He never wears a Mac, in the pouring rain. Very strange.")`. Message: `"{sessionID}|{METHOD}|{host-lowercase-no-port}/{path-without-leading-/}?{query}|v1|{requestId}"` (the `?` is always present). Header: `v1|{requestId}|` + b64url(first 12 bytes). Request IDs increase by 1 per request within a session, starting at a random value.

### Keys, `keys.rs`
- `EncryptedObject`: AES-GCM objects have a 12-byte `iv`, and `data` = ciphertext‖tag, no AAD. **RSA objects have no `iv`** (it's `#[serde(default)]`). Missing that broke every vault on the first real run.
- RSA-OAEP hash is chosen by the **object's `enc`**: `RSA-OAEP` = SHA-1, `RSA-OAEP-256` = SHA-256.
- **Non-primary keysets (group/older) have `encSymKey` RSA-OAEP-wrapped by another keyset's private key**, not AES. `decrypt_keysets` follows `encryptedBy` links. A failing non-primary keyset is skipped; a failing primary keyset is an error. That was the second real-account bug.
- `Debug` impls redact all key material. Secrets live in `Zeroizing`.

### Touch ID, `touchid.rs` (macOS only, feature `touchid`)
- Stores `UnlockKeys` (SRP x ‖ AUK, 64 bytes; **never the password**) in the Keychain, service `onepw-unlock`, account label `"{email}@{address}"`.
- `save` first tries `Protection::Biometry`: data-protection keychain + `BIOMETRY_CURRENT_SET`, Secure Enclave enforced. On `errSecMissingEntitlement` (-34018) it falls back to `Protection::TouchIdGate`: a legacy keychain item, read only after our own `LAContext` biometrics check. Unsigned/`cargo install` builds always get the fallback.
- `load` tries the Biometry item (the OS shows the prompt), then the fallback (our prompt). The policy is biometrics only, with no Mac-password fallback inside the prompt. The caller falls back to the 1Password password instead.
- On non-macOS the module doesn't exist and the feature pulls in no dependencies. That is documented in the README feature table, the docs.rs `doc(cfg)` badge, `Cargo.toml` and the hidden CLI subcommand. **Keep it that way.** Any code used only by Touch ID must not trip `dead_code` on Linux (CI runs clippy `-D warnings` on ubuntu).

## CLI (`src/bin/onepw.rs`)
- Commands: `account add | show | forget | touch-id on|off`, `vault list`, `item list [--vault] [--trashed]`, `item get <item> [--vault] [--reveal] [--json]`, `read <op://…> [-n]`, `run [--env-file F]… -- cmd`.
- Config: `~/.config/onepw/config.json` `{address, email, device_uuid, touch_id}`. The Secret Key goes in the OS keychain via `keyring` (service `onepw`, label `email@address`), or `ONEPW_SECRET_KEY`.
- **The account password is never stored.** It is prompted every time (hidden, `rpassword`), read from `ONEPW_PASSWORD`, or replaced by Touch ID when enabled. With Touch ID on, a successful password sign-in refreshes the stored keys.
- `run` resolves every `op://` value from the environment plus env files with one sign-in (the `Cache` struct) and passes the child's exit code through.
- Prompts and status go to stderr. Only data goes to stdout.

## Sources and licensing rules (important)
- 1Password *Security Design* white paper: 2SKD, key hierarchy, envelope format.
- github.com/1Password/srp (Apache-2.0): SRP variants and test vectors (credited in `NOTICE`).
- github.com/1Password/burp-1password-session-analyzer (BSD-3): MAC and session-payload test vectors.
- detunized/password-manager-access (C#, MIT): may be ported with credit.
- **Bitwarden `sdk-internal` 1Password importer is GPLv3: consult for protocol FACTS only, never copy code.** This crate is MIT/Apache.

## Testing
```sh
cargo test --features cli            # unit (incl. official vectors) + mock e2e + doc tests
cargo clippy --all-targets --features cli -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --features cli
RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --no-deps --all-features   # docs.rs view with platform badges
cargo run --example touchid_probe --features touchid                      # no prompt
```
- **Mock server rule:** `tests/mock_server.rs` must compute server-side values (identity, M1, B, u, MAC, request-ID tracking per session) **independently of the client functions**. Reusing client code there masked the identity bug once. The mock rebuilds the URL from the `Host` header before checking MACs (wiremock reports `localhost`).
- **Real-account testing:** the maintainer runs `cargo run --example try_account` (or the CLI) **in their own terminal** and pastes the output. Never ask for, accept or handle passwords, Secret Keys, 2FA codes or API tokens in the conversation, and never use `!`-commands for interactive credential prompts. The example keeps its device UUID in `~/.config/onepw/device-uuid` (same device as the CLI). Avoid repeated failed sign-ins: 1Password rate-limits and IP-blocks.
- The local cross-check `cargo check --target x86_64-unknown-linux-musl` fails in `aws-lc-sys` (C toolchain). That's unrelated; rely on Linux CI instead.

## Releasing
1. `cargo fmt`; tests, clippy and docs as above (CI must be green on both OSes).
2. Bump `version` in `Cargo.toml`, update the README status table, `cargo publish --dry-run`.
3. **Get the maintainer's explicit OK** (publishing is permanent; versions can only be yanked).
4. `cargo publish`, tag `vX.Y.Z` on the published commit, push the tag.
5. crates.io auth: the maintainer runs `cargo login` themselves. The token needs `publish-new` + `publish-update`, scoped to crate **`onepw`** (not `onepw-rs`; that mismatch caused a 403 once).

## Open work / next steps
1. ~~Maintainer Touch ID test~~ done 2026-11-23, all steps passed.
2. ~~Release 0.2.0~~ done 2026-11-23. Then add `onepw` to the maintainer's terminal cheat sheet (Obsidian vault note).
3. **Secure Enclave level (Protection::Biometry)**: needs a Developer ID-signed build with a provisioning profile granting `keychain-access-groups`. A bare CLI can't embed a profile, so the plan is an app-bundle wrapper (`onepw.app/Contents/{Info.plist, MacOS/onepw, embedded.provisionprofile}`), codesigned with entitlements (`com.apple.application-identifier`, `com.apple.developer.team-identifier`, `keychain-access-groups`), with `onepw` on PATH as a symlink into the bundle, and possibly notarized. Maintainer prerequisites: install the "Developer ID Application" certificate (Xcode → Settings → Accounts → Manage Certificates), register an App ID, and create a Developer ID provisioning profile. Then they supply the Team ID and bundle ID. No signing identity was installed as of 2026-11-23 (`security find-identity -v -p codesigning` showed 0). Verify with `touchid_probe` that the signed build reports `Biometry`.
4. Possible convenience API: `onepw::read_secret("op://…")` using the CLI's saved profile + Keychain (+ Touch ID).
5. Later: item create/edit (`v4/vault/{v}/item/itemsbatch` per community research), WebAuthn/Duo 2FA, session reuse/caching, a "remember me" dsecret.

## Conventions
- Keep secrets in `Zeroizing`, redact `Debug`, and never log or print secret values (examples print counts/names only).
- New protocol behaviour: add a mock-server case that would have caught the bug, written independently of the client.
- Error messages should tell the user what to do (e.g. "wrong account password or Secret Key", "stored unlock keys are out of date…").
- `cargo fmt` before committing. Commit messages describe the why. Co-author trailer as configured.
