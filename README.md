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

Version 0.2 is experimental, and the API will change.

## Install

```toml
[dependencies]
onepw = "0.3"
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

## Cargo features

| Feature | Platforms | What it adds |
|---|---|---|
| *(none)* | all | The library: sign-in, vaults, items, `op://` references |
| `cli` | all | The `onepw` binary. Its `account touch-id` command is macOS only, and hidden elsewhere |
| `touchid` | **macOS only** | `onepw::touchid`: unlock with Touch ID instead of the password. On Linux and Windows it compiles to nothing and pulls in no dependencies, so it's safe to leave on in cross-platform builds. Docs: [macOS build on docs.rs](https://docs.rs/onepw/latest/aarch64-apple-darwin/onepw/touchid/) |

## Command-line tool

```sh
cargo install onepw --features cli
```

```sh
onepw account add                          # one-time: address, email, Secret Key (→ OS keychain); checks sign-in
onepw vault list
onepw item list [--vault Private]
onepw item get GitHub [--reveal] [--json]  # concealed values hidden unless --reveal
onepw read op://Private/GitHub/password    # like `op read`; -n for no trailing newline
onepw run --env-file .env.op -- cargo run  # like `op run`: op:// values in the env/env file are resolved
onepw account show | forget
onepw account touch-id on | off            # macOS only: Touch ID instead of the password
```

- **Secret Key:** stored in the macOS Keychain (or the Linux kernel keyring) under the service `onepw`. Settings (address, email, device ID) go in `~/.config/onepw/config.json`. You can also set `ONEPW_SECRET_KEY`.
- **Account password:** **never stored**. It's asked for (hidden) on every command, or read from `ONEPW_PASSWORD`. Keeping it next to the Secret Key would undo 1Password's two-secret design.
- **Touch ID (macOS only):** `onepw account touch-id on` asks for the password once, then stores the *derived* unlock keys (not the password) in the Keychain behind Touch ID. Builds signed with a Developer ID and the right entitlement get a Secure Enclave-enforced item. Others get an item that only onepw reads, after its own Touch ID check. A cancelled prompt or out-of-date keys fall back to the password.
- **`run`:** every environment variable, from your shell or from `--env-file` lines `KEY=op://vault/item/field`, whose value starts with `op://` is replaced before the command starts. The command's exit code is passed through. onepw's own `ONEPW_*` variables (password, Secret Key) are removed from the command's environment.
- **Cost:** each command is a full sign-in (≈1 s, mostly the 650 000-round key derivation). `run` resolves all references with one sign-in.

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
| `account.items(&vault)` | Every item, **including trashed ones** (check `item.trashed`). Only the overview (title, URLs, tags) is decrypted; fields and passwords stay encrypted until you ask for them |
| `item.title()` | Item title |
| `item.field("username" \| "password" \| "credential" \| <label>)?` | `Option<Zeroizing<String>>`: a field by designation, name or section label |
| `item.fields()?` | All non-empty fields (`label`, `section`, `value: Zeroizing<String>`, `concealed`) |
| `item.overview` / `item.details()?` | The raw decrypted JSON (`URLs`, `tags` / `sections`, `notesPlain`, …). `details()` returns a `Details` that wipes its strings on drop |
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

### What onepw protects

- **Keys in locked memory:** the session key, the Account Unlock Key, the SRP secret `x` (as stored in `UnlockKeys`) and every AES key (keyset and vault keys) each live in their own `mlock`ed memory page: not written to swap, excluded from core dumps on Linux, zeroed before being freed. If the OS refuses to lock (a low `RLIMIT_MEMLOCK` on Linux), they're still zeroed on drop.
- **Other credentials** (your password, Secret Key, decrypted key material in transit) are held in `Zeroizing` buffers (overwritten with zeros when dropped) and redacted from `Debug` output.
- **Item secrets are decrypted only on demand.** `account.items()` keeps each item's fields, passwords and notes encrypted. `field()`, `fields()` and `details()` decrypt one item for that call only, return values that are wiped on drop (`Zeroizing<String>`, `Details`), and wipe the intermediate JSON.
- **No accidental printing:** `Debug` on `Item`, `Field` and `Details` never shows values. `onepw item get` hides every field whose type isn't known to be plain text (so new kinds of secrets, such as SSH keys, are hidden by default) unless you pass `--reveal`.
- **Nothing is written to disk.** The CLI keeps no cache file and disables core dumps at startup.
- **Interception:** after sign-in, every server response must be an envelope encrypted with the SRP session key. Plaintext (which only someone between you and the server, such as a TLS-inspecting proxy, could inject) is refused, and a plaintext error object is only ever treated as an error, never as data. Redirects are never followed.
- **Look-alike sign-in addresses:** only `*.1password.com`, `*.1password.ca` and `*.1password.eu` over HTTPS are accepted (`SignInOptions::allow_any_host` overrides this), because the client sends its SRP proof before the server proves itself.
- **Weak key derivation:** a server asking for fewer than 100 000 PBKDF2 iterations (for sign-in or for the Account Unlock Key) is refused (`SignInOptions::min_kdf_iterations`).
- **Look-alike vault and item names:** an `op://` reference or `onepw item get [--vault]` whose vault or item name matches more than one is an error. `Private` always means your personal vault and never matches a shared vault named "Private". UUIDs always work.
- **Side channels in the crypto:** the SRP maths on your secrets runs in constant time (`crypto-bigint`, fixed 1024-bit exponents), and RSA decryption uses `rsa` 0.10 with blinding (fixing the Marvin timing attack, RUSTSEC-2023-0071).
- **A hostile or broken server** can't hang onepw (connect and request timeouts) or make it page through items forever, and its memory use is bounded (a response over 64 MiB, or more than 256 MiB of item data per vault, is refused).
- **`onepw run` never passes onepw's own credentials** (`ONEPW_PASSWORD`, `ONEPW_SECRET_KEY`, any `ONEPW_*`) to the command.

### ⚠️ What onepw does NOT protect

Read this before relying on onepw for anything sensitive. Memory wiping reduces how long secrets linger; it is not a guarantee.

| Gap | What it means | What you can do |
|---|---|---|
| **Your own copies** | `.to_string()`, `.clone()` into a plain `String`, `format!`, `serde_json::to_string(&*details)` and similar make copies that are **not** wiped | Keep values in `Zeroizing<String>`; use them by reference (`&*value`) |
| **Only keys are locked** | Item values, your password, the Secret Key, RSA private keys (held inside the `rsa` crate) and the SRP working copies of `x` and `a` are zeroed but **not** `mlock`ed, so they can reach swap | macOS encrypts swap by default; on Linux, use encrypted swap or none |
| **JSON parser scratch buffer** | When a decrypted string contains escape characters (`"`, `\`, control or some Unicode characters), `serde_json` copies it through an internal buffer that is freed without being wiped | None inside onepw today |
| **Freed heap memory in general** | Anything not listed as protected above (error messages, HTTP buffers inside `reqwest`/`rustls`, the Keychain's own copies, allocator leftovers) may stay in freed memory until reused | Keep the process short-lived (the CLI exits after each command) |
| **`ONEPW_PASSWORD`** | If you use it, the password sits in onepw's environment block for the life of the process (and in your shell's) | Prefer the prompt or Touch ID |
| **Terminal and stdout** | Whatever `onepw read` or `onepw item get --reveal` prints goes through stdout's buffer and into your terminal's scrollback (and tmux's history), outside onepw's control | Prefer `onepw run` or piping straight into the program that needs the value. Piping to `pbcopy` avoids scrollback but puts the secret on the clipboard, where clipboard-history tools (e.g. Raycast's) keep it. Clear scrollback afterwards |
| **`onepw run`** | The resolved secrets are handed to the child process as **environment variables** (as `op run` does). The child, and anything it starts, inherits them; programs may log their environment; on Linux, root and the same user can read `/proc/<pid>/environ` | Only `run` programs you trust, for as short as possible |
| **Shell history** | `op://` references are not secret, but a value you paste on the command line is | Never type secret values on the command line |
| **Malware running as your user** | It can attach a debugger, read process memory, read the Keychain items it is allowed to, or log keystrokes. No in-process protection stops that | Keep your machine clean; a signed build with the hardened runtime and the Secure Enclave level raises the bar |
| **A malicious or compromised 1Password server** | It can offer you vaults and items it made (encrypted to your public key, which isn't secret) or swap encrypted parts between items: 1Password's format doesn't tie an item's ciphertext to its ID. onepw doesn't yet remember keys it has seen | Use UUIDs in `op://` references for anything important |
| **Touch ID fallback level** | On unsigned builds (`Protection::TouchIdGate`), Touch ID is checked by onepw, not enforced by the hardware. Malware running as you can launch the (trusted) onepw binary with an injected library, since unsigned builds have no hardened runtime, and read the stored unlock keys without any prompt | Use a signed build for the Secure Enclave level (`Protection::Biometry`) |
| **Remaining timing leak in SRP** | `K = SHA256(hex(S))` strips leading zero digits of `S`, as 1Password's protocol requires, which can reveal how many leading zeros `S` has | None (protocol-defined) |
| **Several fields with the same label** | `item.field("x")` / `op://…/x` returns the first matching field (top-level, then sections) without an ambiguity check | Check the item in 1Password if a label is reused |
| **No professional audit** | onepw has had an automated, independent code review (findings fixed in 0.3.0) and fuzzing, but **no** professional security audit | Treat it accordingly |

### Other notes

- Threat model and how to report a vulnerability: [SECURITY.md](SECURITY.md).
- `unsafe` is denied crate-wide (`#![deny(unsafe_code)]`) and allowed in three places only: the locked-memory allocator (`mlock`/`madvise`), the macOS Touch ID module (Objective-C calls), and the CLI's one `setrlimit` call.
- The crypto uses the RustCrypto crates (`aes-gcm`, `rsa`, `hkdf`, `pbkdf2`, `hmac`, `sha2`, `crypto-bigint`). Nothing is home-made except 1Password's composition of them.
- Parsers of server data, secret references and Secret Keys are fuzzed (`fuzz/`, weekly in CI); dependencies are checked with `cargo-deny` (RustSec advisories, licenses, sources) on every push.

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
