# Security policy

onepw is an **unofficial** 1Password client. It is not affiliated with or endorsed by AgileBits /
1Password, and it has **not** had an independent security review.

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub:
**Security → Report a vulnerability** on <https://github.com/twitzelbos/onepw-rs/security>.
Don't open a public issue for anything that could put users' secrets at risk.

Include what you found, how to reproduce it, and the onepw version. You can expect an
acknowledgement within a week. Fixes are released as a new version on crates.io, with a
GitHub security advisory (and a RustSec advisory for serious issues). Reporters are credited
unless they'd rather not be.

A vulnerability in 1Password's own service or apps should go to 1Password's bug bounty, not here.

## Supported versions

Only the latest release gets security fixes. onepw is 0.x: upgrade to the newest version.

## Threat model

What onepw is designed to resist, and what it is not. The README's
"What onepw does NOT protect" section has the detailed list of memory-safety gaps.

### In scope

| Threat | Defence |
|---|---|
| **Network attacker** who can read or change traffic, including one with a trusted TLS certificate (a TLS-inspecting corporate proxy, a compromised CA) | TLS, plus 1Password's protocol: SRP-6a proves both sides know the verifier without sending the password; the server's SRP proof is checked (in constant time) before anything else is trusted; after sign-in every request carries a MAC and every response must be an envelope encrypted with the session key: plaintext is refused, and a plaintext error object is only ever an error, never data. Redirects aren't followed. Only 1Password's own domains are contacted (the client proves first in SRP, so a look-alike address must never get that proof). |
| **Forged sign-in parameters** (a fake or tampered server asking for a weak key derivation) | Only the `SRPg-4096` group is accepted, the SRP values `B` and `u` are validated, and fewer than 100 000 PBKDF2 iterations (for sign-in or the Account Unlock Key) is refused (`SignInOptions::min_kdf_iterations`). |
| **Hostile server resource use** | Connect and request timeouts, a 64 MiB limit per response, a 256 MiB limit on item data per vault, and a cap on item pages. |
| **Look-alike vaults and items** (someone shares a vault named "Private", or adds an item with the same title) | In `op://` references and `onepw item get [--vault]`, names must be unique: an ambiguous vault or item name is an error, and `Private` always means your personal vault (never a shared vault of that name). UUIDs always work. |
| **Secrets leaking from the process by accident** (logs, `Debug` output, crash dumps, swap, long-lived memory) | Keys in their own `mlock`ed pages; zeroizing buffers for other secrets and values; item details decrypted only on demand; redacted `Debug`; unknown field kinds hidden by default in `item get`; core dumps disabled in the CLI; `onepw run` strips `ONEPW_*` credentials from the child's environment. |
| **Other programs reading stored credentials** | The Secret Key and the Touch ID unlock keys live in the macOS Keychain. Signed builds store the unlock keys behind Secure Enclave–enforced Touch ID, in an item that never leaves the device (`ThisDeviceOnly`). |
| **Timing side channels** | SRP maths on secrets is constant time (`crypto-bigint`, fixed 1024-bit exponents); RSA decryption uses `rsa` 0.10 with blinding (Marvin attack fixed). One protocol-defined leak remains: the hex encoding of the SRP premaster secret drops leading zeros. |
| **Supply chain** | Few dependencies, RustCrypto for all crypto, `cargo-deny` (RustSec advisories, licenses, crates.io only) in CI, actions pinned by commit SHA, least-privilege CI tokens, Dependabot with a cooldown. |
| **Parser bugs** | Everything that parses server data (responses, keysets, keys, items, SRP values), secret references and Secret Keys is fuzzed (`fuzz/`, weekly in CI). Not fuzzed: the CLI's own `config.json` and `--env-file` parsing, which read your own files. |

### Out of scope (not defended)

- **A malicious or compromised 1Password server.** 1Password's design limits what a server can
  learn, but a malicious server can still offer you vaults and items it created (encrypted to
  your public key) or swap encrypted parts between items, because 1Password's format doesn't bind
  an item's ciphertext to its ID. onepw doesn't yet pin keys it has seen before.
- **Malware running as your user,** or anyone with root on your machine: it can read process
  memory, attach a debugger, or log keystrokes. On unsigned builds it can also run the trusted
  onepw binary with an injected library and read the Touch ID fallback item without a prompt.
  A signed build with the hardened runtime raises the bar but doesn't remove this.
- **Weak account passwords.** The Secret Key makes offline guessing infeasible without it; with
  it, the password is all that's left.
- **Physical and microarchitectural side channels** (power, EM, cache attacks by co-located
  code). The constant-time work above targets timing observable over the network.
