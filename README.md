# onepw

[![crates.io](https://img.shields.io/crates/v/onepw.svg)](https://crates.io/crates/onepw) [![docs.rs](https://docs.rs/onepw/badge.svg)](https://docs.rs/onepw) [![CI](https://github.com/twitzelbos/onepw-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/twitzelbos/onepw-rs/actions/workflows/ci.yml)

An **unofficial**, pure-Rust client for 1Password accounts. It signs in with your account password and Secret Key, unlocks your keys, and reads vaults, items and `op://` secret references, talking to 1Password's servers directly. It needs neither the `op` CLI nor the desktop app.

> **⚠️ Not affiliated with, endorsed by, or supported by AgileBits Inc. / 1Password.**
> 1Password's server API is not publicly documented. This crate combines the documented cryptography with a reverse-engineered transport, and **it can stop working whenever 1Password changes its servers.** Using an unofficial client may be against 1Password's terms of service; that's for you to judge. For anything important, use the official [`op` CLI](https://developer.1password.com/docs/cli/) or the [official SDKs](https://developer.1password.com/docs/sdks/).

## Status

| Part | State |
|---|---|
| SRP-6a (1Password variants), 2SKD key derivation, Secret Key parsing | ✅ matches 1Password's published test vectors |
| Request MAC (`X-AgileBits-MAC`), session encryption | ✅ matches 1Password's published test vectors |
| Keysets → vault keys → items (AES-256-GCM, RSA-OAEP / OAEP-256) | ✅ tested end-to-end against a simulated server |
| Sign-in against the **real** 1Password service | ✅ verified 2026-11-23 on an individual account (my.1password.com): sign-in, personal and shared vaults, all items decrypted |
| 2FA | authenticator app (TOTP) only. Security keys, Duo and SSO accounts are not supported |
| Writing (create/edit items) | ❌ read-only |

Version 0.1 is experimental, and the API will change.

## Install

```toml
[dependencies]
onepw = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Quick start

```rust,no_run
use onepw::{Account, Credentials, SecretKey, SignInOptions};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> onepw::Result<()> {
    let creds = Credentials {
        sign_in_address: "my.1password.com".into(), // or my.1password.eu, yourteam.1password.com …
        email: "you@example.com".into(),
        secret_key: SecretKey::parse("A3-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX")?,
        password: Zeroizing::new(std::env::var("OP_ACCOUNT_PASSWORD").unwrap_or_default()),
    };

    let mut opts = SignInOptions::new();
    opts.device_uuid = "store-and-reuse-this-26chr".into(); // see "Device UUID" below

    let account = Account::sign_in(&creds, opts).await?;

    // One secret, by reference (same format as `op read`):
    let key = account.read("op://Private/Anthropic API/credential").await?;
    println!("got a key of {} characters", key.len());

    // Or walk everything:
    for vault in account.vaults().await? {
        for item in account.items(&vault).await? {
            if !item.trashed {
                println!("{} / {}", vault.name(), item.title());
            }
        }
    }

    account.sign_out().await
}
```

### Try it on your account

```sh
cargo run --example try_account
```

It prompts for the sign-in address, email, Secret Key and password (the last two hidden) and, if needed, a 2FA code. It then lists your vaults with item counts. It never prints secrets. The device UUID is saved in `~/.config/onepw/device-uuid`.

## Manual

### Credentials

| Field | Where to find it |
|---|---|
| `sign_in_address` | The host you sign in at: `my.1password.com`, `my.1password.eu`, `my.1password.ca`, or `<team>.1password.com` |
| `email` | Your account email. Case and surrounding spaces don't matter |
| `secret_key` | `A3-…` from 1Password → Settings → Accounts, or your Emergency Kit. `SecretKey::parse` ignores case, spaces and hyphens and rejects impossible characters (0, 1, I, O, U) |
| `password` | Your account password. It is wrapped in `Zeroizing` and wiped from memory on drop |

Never hard-code these. Read them from a prompt (`rpassword`), from the environment, or from your OS keychain.

### Sign-in options

```rust,ignore
let mut opts = SignInOptions::new();
opts.device_uuid = saved_uuid;                       // reuse between runs
opts.totp = Some(Box::new(|| Ok(read_code_from_user()))); // only if 2FA is on
opts.identity.device_name = "my-backup-tool".into(); // shown in your account's device list
```

- **Device UUID.** Every sign-in identifies a *device*. A new UUID registers a new device in your account (and 1Password may email you about it). Generate one once with `onepw::client::new_device_uuid()`, store it, and reuse it.
- **2FA.** If the account has authenticator-app 2FA, `totp` is called for the 6-digit code. **A wrong code ends the session**, so sign in again rather than retrying.
- **Client identity.** 1Password's servers sit behind a firewall that turns away unfamiliar clients, so the request headers follow the format of 1Password's own desktop app (`ClientIdentity::default()`). The **device name** defaults to `onepw`, so you can always spot and revoke these sessions under *Settings → Devices* on 1Password.com.

### Reading data

| Call | Returns |
|---|---|
| `account.vaults()` | Vaults you can read, with their keys unlocked. `vault.name()`, `vault.vault_type` (`P` personal, `E` everyone, `U` user-made), `vault.attrs` |
| `account.items(&vault)` | Every item, decrypted, **including trashed ones** (check `item.trashed`) |
| `item.title()` | Item title |
| `item.field("username" \| "password" \| "credential" \| <label>)` | A field by designation, name or section label |
| `item.overview` / `item.details` | The raw decrypted JSON (`URLs`, `tags`, `sections`, `notesPlain`, …) |
| `account.read("op://vault/item/field")` | One value. Vault and item can be names or UUIDs. `Private` also matches your personal vault |
| `account.sign_out()` | Ends the server session |

### Errors

Everything returns `onepw::Result<T>`. The `Error` variants:

- `InvalidInput`: a bad Secret Key, a wrong password or Secret Key ("wrong account password or Secret Key"), a reference that doesn't exist.
- `Unsupported`: an unsupported 2FA method, Secret Key format or key derivation.
- `Protocol`: the server misbehaved, for example a failed SRP proof (possible tampering) or a missing field.
- `Decrypt`: wrong key or tampered data. AES-GCM authentication failed.
- `Server { status, body }`: an HTTP or API error from 1Password. The body never contains secrets you sent.
- `Http`: a network error.

Don't retry failed sign-ins in a loop. 1Password rate-limits and blocks by IP.

### Lower-level building blocks

The modules are public, if you want to reuse the cryptography:

| Module | What |
|---|---|
| `onepw::kdf` | 2SKD: `account_unlock_key`, `srp_x`, `normalize_password` |
| `onepw::srp` | SRP-6a client, `Variant::Standard` (current flow) and `Variant::Legacy`, `identity`, hex helpers |
| `onepw::secret_key` | `SecretKey` parsing |
| `onepw::keys` | `EncryptedObject` (the `{kid, enc, cty, iv, data}` envelope), `SymmetricKey`, `PrivateKey`, keyset decryption |
| `onepw::mac` | `X-AgileBits-MAC` request signing |

## How it works

```text
account password ─┐
Secret Key ───────┼─ 2SKD (HKDF + PBKDF2-SHA256 650k + XOR) ─┬─► SRP x ─► SRP-6a 4096-bit ─► session key K
email, salts ─────┘                                          └─► Account Unlock Key (kid "mp")
                                                                   │
            every request after login: body AES-256-GCM under K, header HMAC-SHA256 MAC
                                                                   ▼
         keyset: symmetric key (AES-GCM) + RSA-2048 private key ◄── decrypted with the AUK
                                                                   │ RSA-OAEP
                                                                   ▼
                                                              vault keys ──AES-GCM──► items
```

1. `POST v3/auth/start` returns the session ID and SRP parameters. An unknown device is registered with `POST v1/device` first.
2. `POST v2/auth` exchanges A and B. Then `POST v2/auth/confirm-key`: the client proves knowledge of K, and the server proves knowledge of the verifier, so neither side ever sends the password.
3. `POST v2/auth/complete` (encrypted and MAC'd) finishes sign-in and may ask for 2FA.
4. `GET v1/account/keysets`, `GET v1/account?attrs=me,vaults` and `GET v1/vault/{id}/{batch}/items` fetch the data.

Your password and Secret Key never leave the process. The server only sees SRP values that are useless without them.

## Security notes

- Secrets (password, Secret Key, derived keys, the session key, decrypted key material) are held in `Zeroizing` buffers and redacted from `Debug` output. **Decrypted item JSON (`item.details`) is a `serde_json::Value` and can't be zeroed**, so drop items as soon as you're done with them.
- The crate contains no `unsafe` (`#![forbid(unsafe_code)]`).
- The crypto uses the RustCrypto crates (`aes-gcm`, `rsa`, `hkdf`, `pbkdf2`, `hmac`, `sha2`). Nothing is home-made except 1Password's composition of them.
- This code has **not** had a security review. Treat it accordingly.

## Development

```sh
cargo test                            # unit tests incl. 1Password's SRP/MAC/envelope vectors + mock-server e2e
cargo run --example try_account       # against your real account
```

`tests/mock_server.rs` simulates the server side: SRP verifier math, proof checking, MAC verification on every request, and encrypted keysets, vaults and items.

## Acknowledgements and sources

- *1Password Security Design* white paper: 2SKD, key hierarchy, encrypted-object format.
- [1Password/srp](https://github.com/1Password/srp) (Apache-2.0): the SRP variant and test vectors (see `NOTICE`).
- [1Password/burp-1password-session-analyzer](https://github.com/1Password/burp-1password-session-analyzer) (BSD-3-Clause): request MAC and session payload test vectors.
- Protocol details were cross-checked against the public, independently developed clients by detunized (MIT) and in Bitwarden's importer. No code was copied from GPL sources.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. "1Password" is a trademark of AgileBits Inc.
