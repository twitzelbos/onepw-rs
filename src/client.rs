//! Signing in to a 1Password account and reading vaults and items.
//!
//! Login flow (current generation of 1Password's API):
//!
//! 1. `POST v3/auth/start` `{email, skFormat, skid, deviceUuid}` → session ID and SRP parameters.
//!    Unknown devices are registered with `POST v1/device` first.
//! 2. `POST v2/auth` `{userA}` → `{userB}` (SRP exchange, [`crate::srp::Variant::Standard`]).
//! 3. `POST v2/auth/confirm-key` `{clientVerifyHash}` → `{serverVerifyHash}` (mutual proof).
//! 4. From here on every body is encrypted with the SRP session key and every request carries an
//!    `X-AgileBits-MAC` header. `POST v2/auth/complete` finishes the login and may ask for 2FA.
//!
//! Then `GET v1/account/keysets` (personal keys, unlocked with the Account Unlock Key),
//! `GET v1/account?attrs=vaults` (vaults and their RSA-wrapped vault keys) and
//! `GET v1/vault/{uuid}/{batch}/items` (items, AES-GCM under the vault key).

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use rand::RngExt;
use reqwest::{Method, Url};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::keys::{EncryptedKeyset, EncryptedObject, Keyset, SymmetricKey, decrypt_keysets};
use crate::locked::Locked;
use crate::secret_key::SecretKey;
use crate::{b64, kdf, mac, srp};

const MAC_HEADER: &str = "X-AgileBits-MAC";
const SESSION_HEADER: &str = "X-AgileBits-Session-ID";
const CLIENT_HEADER: &str = "X-AgileBits-Client";
const OP_USER_AGENT_HEADER: &str = "OP-User-Agent";

/// How this client presents itself to the server.
///
/// 1Password's servers sit behind a web application firewall that rejects unfamiliar clients,
/// so the defaults follow the format of 1Password's own desktop app (`clientName/clientVersion`,
/// plus an `OP-User-Agent` line). The **device name** shown in your account's device list is
/// `onepw` by default, so you can always recognise and revoke sessions made with this crate.
#[derive(Clone, Debug)]
pub struct ClientIdentity {
    /// e.g. `"1Password for Mac"`.
    pub client_name: String,
    /// e.g. `"81210036"`.
    pub client_version: String,
    /// Device name shown under *Settings → Devices* in your 1Password account.
    pub device_name: String,
    /// OS name sent with the device registration, e.g. `"macOS"`.
    pub os_name: String,
    /// `OP-User-Agent` platform suffix, e.g. `"MacOSX|26.3.1|aarch64"`.
    pub platform: String,
    /// One-letter platform code used in `OP-User-Agent` (`"M"` = Mac).
    pub platform_code: String,
}

impl Default for ClientIdentity {
    fn default() -> Self {
        ClientIdentity {
            client_name: "1Password for Mac".into(),
            client_version: "81210036".into(),
            device_name: "onepw".into(),
            os_name: "macOS".into(),
            platform: "MacOSX|26.3.1|aarch64".into(),
            platform_code: "M".into(),
        }
    }
}

impl ClientIdentity {
    fn client_id(&self) -> String {
        format!("{}/{}", self.client_name, self.client_version)
    }
    fn op_user_agent(&self, device_uuid: &str) -> String {
        format!(
            "1|{}|{}|{}|||reqwest|0.13|{}",
            self.platform_code, self.client_version, device_uuid, self.platform
        )
    }
}

/// Everything needed to sign in.
pub struct Credentials {
    /// Account email address.
    pub email: String,
    /// Account password.
    pub password: Zeroizing<String>,
    /// Secret Key.
    pub secret_key: SecretKey,
    /// Sign-in address, e.g. `"my.1password.com"`, `"my.1password.eu"` or `"yourteam.1password.com"`.
    pub sign_in_address: String,
}

/// Options for [`Account::sign_in`].
pub struct SignInOptions {
    /// Device UUID (26 lowercase base32 characters). **Store and reuse it** so every run doesn't
    /// register a new device. [`new_device_uuid`] makes one.
    pub device_uuid: String,
    /// Client identity headers.
    pub identity: ClientIdentity,
    /// Called when the account has authenticator-app 2FA enabled; returns the 6-digit code.
    #[allow(clippy::type_complexity)]
    pub totp: Option<Box<dyn Fn() -> Result<String> + Send + Sync>>,
    /// Base URL override (for tests). Defaults to `https://{sign_in_address}/api/`. An explicit
    /// base URL is used as given: the 1Password-domain check below doesn't apply to it.
    pub base_url: Option<Url>,
    /// Allow sign-in addresses outside 1Password's own domains (default `false`). In 1Password's
    /// protocol the client sends its SRP proof first, so a mistyped or look-alike address would
    /// hand that proof to a stranger. Only `*.1password.com`, `*.1password.ca` and
    /// `*.1password.eu` are accepted unless this is set.
    pub allow_any_host: bool,
    /// Timeout for each HTTP request (default 120 s; connecting has its own 15 s limit).
    pub timeout: std::time::Duration,
    /// Refuse to sign in if the server asks for fewer PBKDF2 iterations than this (default
    /// [`MIN_KDF_ITERATIONS`]). The count comes from the server; a forged low count would make
    /// offline guessing of the password cheap.
    pub min_kdf_iterations: u32,
}

/// What a response must look like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reply {
    /// Before the session key exists (or for discarded replies): plain JSON.
    Plain,
    /// After sign-in: an envelope encrypted with the session key.
    Encrypted,
    /// After sign-in, for calls whose reply is discarded (2FA): anything but an error is fine.
    /// Accepting a forged "success" here is harmless: the real server still refuses the session
    /// if 2FA didn't actually pass, and no data from this reply is used.
    Discarded,
}

/// Interprets a successful (2xx) response body. In an encrypted session the body must be an
/// envelope under the session key (checked by key ID and GCM tag). A plaintext object carrying
/// `errorCode` is always turned into an error, never returned as data, and any other plaintext
/// (including an empty body where data is expected) is refused.
fn decode_response(
    path: &str,
    text: &str,
    reply: Reply,
    session_key: Option<&SymmetricKey>,
) -> Result<Value> {
    let value: Value = if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(text)?
    };
    let as_error = |v: &Value| -> Option<Error> {
        let code = v.get("errorCode")?;
        Some(Error::Server {
            status: code
                .as_i64()
                .map_or(0, |c| c.clamp(0, u16::MAX.into()) as u16),
            body: truncate(v.get("errorMessage").and_then(Value::as_str).unwrap_or("")),
        })
    };
    let refuse = || {
        // After SRP, the real server encrypts every response with the session key. Plaintext can
        // only come from someone between us and the server (e.g. a TLS-intercepting proxy), who
        // could otherwise inject or hide vaults and items.
        Error::Protocol(format!(
            "{path}: the server's response was not encrypted with the session key; refusing it \
             (the connection may be intercepted)"
        ))
    };
    let key = match (reply, session_key) {
        (Reply::Plain, _) | (_, None) => {
            return match as_error(&value) {
                Some(e) => Err(e),
                None => Ok(value),
            };
        }
        (_, Some(key)) => key,
    };
    if value.get("enc").is_some() && value.get("data").is_some() {
        let env: EncryptedObject = serde_json::from_value(value)?;
        let inner: Value = env.decrypt_json(key)?;
        return match as_error(&inner) {
            Some(e) => Err(e),
            None if reply == Reply::Discarded => Ok(Value::Null),
            None => Ok(inner),
        };
    }
    if let Some(code) = value.get("errorCode") {
        // A plaintext error in an encrypted session: still only an error, but say it was
        // unencrypted, so injected errors don't pass for ordinary server errors.
        return Err(Error::Protocol(format!(
            "{path}: unencrypted error response (errorCode {code}, message {:?}); the connection \
             may be intercepted",
            truncate(
                value
                    .get("errorMessage")
                    .and_then(Value::as_str)
                    .unwrap_or("")
            )
        )));
    }
    if reply == Reply::Discarded {
        return Ok(Value::Null);
    }
    Err(refuse())
}

/// 1Password's sign-in domains. A sign-in address must be one of these or a subdomain.
pub const ONEPASSWORD_DOMAINS: &[&str] = &["1password.com", "1password.ca", "1password.eu"];

/// Most pages of items onepw fetches for one vault (each page holds many items).
const MAX_ITEM_PAGES: u32 = 10_000;

/// Most encrypted item data onepw keeps in memory for one vault (256 MiB).
const MAX_VAULT_BYTES: usize = 256 << 20;

/// Largest server response onepw accepts (64 MiB); bigger ones are refused, not buffered.
const MAX_RESPONSE_BYTES: usize = 64 << 20;

/// Checks that `url` is HTTPS on one of [`ONEPASSWORD_DOMAINS`].
fn check_onepassword_host(url: &Url) -> Result<()> {
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    let ok = url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && ONEPASSWORD_DOMAINS
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")));
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!(
            "sign-in address {host:?} is not a 1Password domain ({}); refusing to send it your \
             sign-in proof (set SignInOptions::allow_any_host to override)",
            ONEPASSWORD_DOMAINS.join(", ")
        )))
    }
}

/// Default minimum PBKDF2 iteration count. Current accounts use 650 000; very old ones 100 000.
pub const MIN_KDF_ITERATIONS: u32 = 100_000;

impl SignInOptions {
    /// Options with a fresh device UUID and default identity.
    pub fn new() -> Self {
        SignInOptions {
            device_uuid: new_device_uuid(),
            identity: ClientIdentity::default(),
            totp: None,
            base_url: None,
            allow_any_host: false,
            timeout: std::time::Duration::from_secs(120),
            min_kdf_iterations: MIN_KDF_ITERATIONS,
        }
    }
}

impl Default for SignInOptions {
    fn default() -> Self {
        Self::new()
    }
}

fn check_iterations(n: u32, min: u32) -> Result<u32> {
    if n < min {
        return Err(Error::Protocol(format!(
            "the server asked for only {n} key-derivation iterations (minimum {min}); \
             refusing to sign in (possible tampering)"
        )));
    }
    Ok(n)
}

/// A random device UUID in 1Password's format (26 characters of `a-z2-7`).
pub fn new_device_uuid() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut rng = rand::rng();
    (0..26)
        .map(|_| ALPHABET[rng.random_range(0..32)] as char)
        .collect()
}

/// A signed-in, unlocked account.
pub struct Account {
    rest: Rest,
    keysets: Vec<Keyset>,
    user_uuid: Option<String>,
    unlock_keys: UnlockKeys,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("base", &self.rest.base.as_str())
            .field("keysets", &self.keysets.len())
            .finish()
    }
}

/// The two keys derived from the account password and Secret Key: the SRP secret `x` and the
/// Account Unlock Key. Together they can sign in to **this** account and unlock its keys without
/// the password, so treat them like the password itself. They're useless for any other account
/// and become invalid when the password or Secret Key changes.
///
/// This is what a Touch ID unlock stores (see the `touchid` feature), the same way 1Password's own
/// apps avoid keeping your password.
#[derive(Clone)]
pub struct UnlockKeys {
    srp_x: Locked<32>,
    auk: Locked<32>,
}

impl UnlockKeys {
    /// Serializes to 64 bytes (`x ‖ AUK`) for storage.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        out[..32].copy_from_slice(self.srp_x.as_ref());
        out[32..].copy_from_slice(self.auk.as_ref());
        out
    }

    /// Restores keys stored with [`UnlockKeys::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error::Malformed(format!(
                "unlock keys are {} bytes, expected 64",
                bytes.len()
            )));
        }
        let mut srp_x = Locked::zeroed();
        let mut auk = Locked::zeroed();
        srp_x.copy_from_slice(&bytes[..32]);
        auk.copy_from_slice(&bytes[32..]);
        Ok(UnlockKeys { srp_x, auk })
    }
}

impl std::fmt::Debug for UnlockKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnlockKeys(<redacted>)")
    }
}

/// How to prove knowledge of the account password.
enum Secret<'a> {
    Password(&'a str),
    Keys(&'a UnlockKeys),
}

/// A vault you can read.
#[derive(Clone, Debug)]
pub struct Vault {
    /// Vault UUID.
    pub uuid: String,
    /// Vault type: `"P"` personal, `"E"` everyone, `"U"` user-created, `"S"` system.
    pub vault_type: String,
    /// Decrypted vault attributes (`name`, `desc`, …).
    pub attrs: Value,
    /// Number of active items, as reported by the server.
    pub active_item_count: Option<u64>,
    key: Arc<SymmetricKey>,
}

impl Vault {
    /// The vault's name (personal vaults may have none).
    pub fn name(&self) -> &str {
        self.attrs.get("name").and_then(Value::as_str).unwrap_or("")
    }
}

/// A downloaded item. The overview (title, URLs, tags) is decrypted; the details (fields,
/// passwords, notes) stay **encrypted** until you ask for them with [`Item::details`],
/// [`Item::fields`] or [`Item::field`], so listing a vault doesn't put every secret in memory.
/// `Debug` shows only the UUID and title.
///
/// **Not protected:** copies you make of decrypted values (`.to_string()`, `.clone()` into a
/// plain `String`, `format!`). See the README's *What onepw does NOT protect*.
#[derive(Clone)]
pub struct Item {
    /// Item UUID.
    pub uuid: String,
    /// Template UUID: `"001"` login, `"005"` password, `"003"` secure note, …
    pub template_uuid: String,
    /// Whether the item is in the trash.
    pub trashed: bool,
    /// Decrypted overview: `title`, `url`, `URLs`, `tags`, …
    pub overview: Value,
    enc_details: Option<EncryptedObject>,
    key: Arc<SymmetricKey>,
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("uuid", &self.uuid)
            .field("title", &self.title())
            .field("template_uuid", &self.template_uuid)
            .field("trashed", &self.trashed)
            .field("details", &"<encrypted>")
            .finish()
    }
}

/// Decrypted item details (`fields`, `sections`, `notesPlain`, `password`, …) as JSON.
///
/// Derefs to [`serde_json::Value`]. On drop, every string in it is overwritten with zeros;
/// `Debug` prints `Details(<redacted>)`.
///
/// # Not protected
///
/// * Copies you make (`.to_string()`, `.clone()`, `serde_json::to_string(&*details)`, values
///   taken out with `as_str().to_owned()`) are ordinary heap memory and are **not** wiped.
/// * Object keys (field names such as `"password"`) and numbers are not wiped; only string values.
/// * While decrypting, `serde_json` copies strings that contain escape characters through an
///   internal buffer that is freed without being wiped.
pub struct Details(Value);

impl Details {
    /// Wraps any JSON value so its strings are wiped on drop.
    pub fn new(value: Value) -> Self {
        Details(value)
    }
}

impl std::ops::Deref for Details {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}

impl Drop for Details {
    fn drop(&mut self) {
        wipe_json(&mut self.0);
    }
}

impl std::fmt::Debug for Details {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Details(<redacted>)")
    }
}

/// Overwrites every string value (not object keys, which are field names) with zeros.
fn wipe_json(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe_json),
        Value::Object(m) => m.values_mut().for_each(wipe_json),
        _ => {}
    }
}

/// Top-level field types (`fields[].type`) whose values aren't secret: text, email, URL, checkbox,
/// phone, number. Anything else (including `P` passwords and types onepw doesn't know) counts
/// as concealed, so a new kind of secret is hidden by default rather than printed.
const PLAIN_TOP_LEVEL_TYPES: &[&str] = &["T", "E", "U", "C", "N", "TEL"];

/// Section field kinds (`sections[].fields[].k`) whose values aren't secret. Anything else
/// (`concealed`, `sshKey`, unknown kinds) counts as concealed.
const PLAIN_SECTION_KINDS: &[&str] = &[
    "string",
    "email",
    "URL",
    "date",
    "monthYear",
    "phone",
    "address",
    "menu",
    "cctype",
    "gender",
    "reference",
];

/// One field of an item, flattened from the top-level `fields` and the `sections`.
/// The value is wiped on drop; `Debug` shows it as `<redacted>`. Cloning the `Field` gives
/// another wiped copy; `field.value.to_string()` gives an unprotected one.
#[derive(Clone)]
pub struct Field {
    /// Section title, if the field is in a section.
    pub section: Option<String>,
    /// Field label (`"username"`, `"password"`, `"credential"`, a custom label, …).
    pub label: String,
    /// The value.
    pub value: Zeroizing<String>,
    /// Whether 1Password treats it as secret (password / concealed fields).
    pub concealed: bool,
}

impl std::fmt::Debug for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Field")
            .field("section", &self.section)
            .field("label", &self.label)
            .field("value", &"<redacted>")
            .field("concealed", &self.concealed)
            .finish()
    }
}

impl Item {
    /// Decrypts the details. Each call decrypts again; the result is wiped when dropped.
    pub fn details(&self) -> Result<Details> {
        Ok(Details(match &self.enc_details {
            Some(d) => d.decrypt_json(&self.key)?,
            None => Value::Null,
        }))
    }

    /// All fields with a non-empty value, top-level fields first, then section fields.
    pub fn fields(&self) -> Result<Vec<Field>> {
        let d = self.details()?;
        let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let secret = |v: Option<&Value>| -> Zeroizing<String> {
            Zeroizing::new(match v {
                Some(Value::String(x)) => x.clone(),
                Some(Value::Null) | None => String::new(),
                Some(other) => other.to_string(),
            })
        };
        let mut out = Vec::new();
        for f in d
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let label = Some(s(f, "designation"))
                .filter(|x| !x.is_empty())
                .unwrap_or_else(|| s(f, "name"));
            out.push(Field {
                section: None,
                concealed: label == "password"
                    || (label != "username"
                        && !PLAIN_TOP_LEVEL_TYPES.contains(&s(f, "type").as_str())),
                label,
                value: secret(f.get("value")),
            });
        }
        if let Some(p) = d.get("password").filter(|p| p.is_string())
            && !out.iter().any(|f| f.label == "password")
        {
            out.push(Field {
                section: None,
                label: "password".into(),
                value: secret(Some(p)),
                concealed: true,
            });
        }
        for sec in d
            .get("sections")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let title = Some(s(sec, "title")).filter(|x| !x.is_empty());
            for f in sec
                .get("fields")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let label = Some(s(f, "t"))
                    .filter(|x| !x.is_empty())
                    .unwrap_or_else(|| s(f, "n"));
                out.push(Field {
                    section: title.clone(),
                    concealed: !PLAIN_SECTION_KINDS.contains(&s(f, "k").as_str()),
                    label,
                    value: secret(f.get("v")),
                });
            }
        }
        out.retain(|f| !f.value.is_empty());
        Ok(out)
    }

    /// The item's URLs (from the overview).
    pub fn urls(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self
            .overview
            .get("URLs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|u| u.get("u").and_then(Value::as_str))
            .collect();
        if v.is_empty()
            && let Some(u) = self.overview.get("url").and_then(Value::as_str)
        {
            v.push(u);
        }
        v
    }

    /// The item's title.
    pub fn title(&self) -> &str {
        self.overview
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    /// Finds a field value by its name, label or designation (`"username"`, `"password"`,
    /// `"credential"`, a section field label, …). Looks at top-level fields, the legacy
    /// `password` key, and section fields. Decrypts the details for this call only.
    ///
    /// ```no_run
    /// # async fn run(account: &onepw::Account) -> onepw::Result<()> {
    /// for vault in account.vaults().await? {
    ///     for item in account.items(&vault).await? {
    ///         if item.trashed {
    ///             continue;
    ///         }
    ///         if let Some(user) = item.field("username")? {
    ///             println!("{}: {}", item.title(), *user);
    ///         }
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    pub fn field(&self, name: &str) -> Result<Option<Zeroizing<String>>> {
        let d = self.details()?;
        let own = |v: Option<&Value>| {
            v.and_then(Value::as_str)
                .map(|s| Zeroizing::new(s.to_owned()))
        };
        if let Some(fields) = d.get("fields").and_then(Value::as_array) {
            for f in fields {
                let hit = ["designation", "name"]
                    .iter()
                    .any(|k| f.get(*k).and_then(Value::as_str) == Some(name));
                if hit {
                    return Ok(own(f.get("value")));
                }
            }
        }
        if name == "password"
            && let Some(p) = own(d.get("password"))
        {
            return Ok(Some(p));
        }
        for s in d
            .get("sections")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for f in s
                .get("fields")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let hit = ["t", "n"]
                    .iter()
                    .any(|k| f.get(*k).and_then(Value::as_str) == Some(name));
                if hit {
                    return Ok(own(f.get("v")));
                }
            }
        }
        Ok(None)
    }
}

impl Account {
    /// Signs in with account password + Secret Key and unlocks the account's keys.
    ///
    /// ```no_run
    /// use onepw::{Account, Credentials, SecretKey, SignInOptions};
    /// use zeroize::Zeroizing;
    ///
    /// # async fn run() -> onepw::Result<()> {
    /// let creds = Credentials {
    ///     sign_in_address: "my.1password.com".into(),
    ///     email: "you@example.com".into(),
    ///     secret_key: SecretKey::parse(&std::env::var("OP_SECRET_KEY").unwrap_or_default())?,
    ///     password: Zeroizing::new(std::env::var("OP_PASSWORD").unwrap_or_default()),
    /// };
    /// let mut opts = SignInOptions::new();
    /// opts.device_uuid = std::fs::read_to_string("device-uuid").unwrap_or(opts.device_uuid);
    /// opts.totp = Some(Box::new(|| Ok(rpassword::prompt_password("2FA code: ").unwrap_or_default())));
    ///
    /// let account = Account::sign_in(&creds, opts).await?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] for a wrong password or Secret Key (or a Secret Key of another
    /// account), [`Error::Unsupported`] for 2FA methods other than an authenticator app,
    /// [`Error::Protocol`] if the server fails its half of the SRP proof.
    pub async fn sign_in(creds: &Credentials, opts: SignInOptions) -> Result<Account> {
        Self::sign_in_impl(
            &creds.email,
            &creds.sign_in_address,
            &creds.secret_key,
            Secret::Password(&creds.password),
            opts,
        )
        .await
    }

    /// Signs in with previously saved [`UnlockKeys`] instead of the password (see
    /// [`Account::unlock_keys`]). The Secret Key is still needed to identify the account.
    ///
    /// Fails with [`Error::InvalidInput`] "stored unlock keys are out of date" after a password or
    /// Secret Key change; sign in with the password again and save the new keys.
    pub async fn sign_in_with_keys(
        email: &str,
        sign_in_address: &str,
        secret_key: &SecretKey,
        keys: &UnlockKeys,
        opts: SignInOptions,
    ) -> Result<Account> {
        Self::sign_in_impl(email, sign_in_address, secret_key, Secret::Keys(keys), opts).await
    }

    /// The keys derived during this sign-in, for saving behind Touch ID (or another protected
    /// store) and passing to [`Account::sign_in_with_keys`] later.
    pub fn unlock_keys(&self) -> &UnlockKeys {
        &self.unlock_keys
    }

    async fn sign_in_impl(
        email: &str,
        sign_in_address: &str,
        sk: &SecretKey,
        secret: Secret<'_>,
        opts: SignInOptions,
    ) -> Result<Account> {
        let stale = || {
            Error::InvalidInput("stored unlock keys are out of date (password or Secret Key changed?): sign in with the password again".into())
        };
        let creds = (email, sign_in_address);
        let base = match &opts.base_url {
            Some(u) => u.clone(),
            None => Url::parse(&format!("https://{}/api/", creds.1.trim_end_matches('/')))
                .map_err(|e| Error::InvalidInput(format!("sign-in address: {e}")))?,
        };
        if opts.base_url.is_none() && !opts.allow_any_host {
            check_onepassword_host(&base)?;
        }
        let http = reqwest::Client::builder()
            // 1Password's API never redirects; following one could send the session's requests
            // (session ID, MAC, encrypted bodies) to another host.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(15))
            .timeout(opts.timeout)
            .https_only(opts.base_url.is_none())
            .build()?;
        let mut rest = Rest::new(http, base, &opts.identity, &opts.device_uuid);

        // 1. Start the session (registering the device if needed).
        let start = start_session(&mut rest, creds.0, sk, &opts).await?;
        if start.account_key_format.as_deref() != Some(sk.format())
            || start.account_key_uuid.as_deref() != Some(sk.account_id())
        {
            return Err(Error::InvalidInput(
                "Secret Key doesn't belong to this account".into(),
            ));
        }
        rest.session_id = Some(start.session_id.clone());
        let auth = start.user_auth;
        check_iterations(auth.iterations, opts.min_kdf_iterations)?;

        // 2. SRP: A → B.
        let salt = b64::decode(&auth.salt)?;
        let x = match secret {
            Secret::Password(pw) => {
                let mut x = kdf::srp_x(pw, sk, creds.0, &auth.method, &salt, auth.iterations)?;
                Locked::take(&mut x)
            }
            Secret::Keys(k) => k.srp_x.clone(),
        };
        let client = srp::Client::new_standard(srp::Group::for_method(&auth.method)?, x.as_ref());
        let resp: Value = rest
            .post_plain("v2/auth", &json!({"userA": client.public_a_hex()}))
            .await?;
        let big_b = srp::from_server_hex(
            resp["userB"]
                .as_str()
                .ok_or_else(|| Error::Protocol("no userB".into()))?,
        )?;
        let key = client.session_key(&big_b)?;

        // 3. Mutual proof.
        let identity = srp::identity(creds.0, sk.account_id());
        let m1 = client.client_proof(&big_b, &key, &identity, &salt);
        let resp: Value = match rest
            .post_plain(
                "v2/auth/confirm-key",
                &json!({"clientVerifyHash": b64::encode(&m1)}),
            )
            .await
        {
            Err(Error::Server { status: 401, .. }) => {
                return Err(match secret {
                    Secret::Keys(_) => stale(),
                    Secret::Password(_) => {
                        Error::InvalidInput("wrong account password or Secret Key".into())
                    }
                });
            }
            other => other?,
        };
        let server_hash = b64::decode(
            resp["serverVerifyHash"]
                .as_str()
                .ok_or_else(|| Error::Protocol("no serverVerifyHash".into()))?,
        )?;
        client.verify_server_confirmation(&m1, &key, &server_hash)?;

        // 4. Encrypted + MAC'd from here on.
        rest.session_key = Some(SymmetricKey::new(start.session_id.clone(), *key.as_bytes()));
        rest.request_id = AtomicU32::new(rand::rng().random_range(1..u32::MAX / 2));
        let complete: Value = rest
            .post(
                "v2/auth/complete",
                &json!({"client": opts.identity.client_id(), "device": device_body(&opts)}),
            )
            .await?;
        let user_uuid = complete
            .get("userUuid")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(mfa) = complete.get("mfa").filter(|m| !m.is_null()) {
            second_factor(&rest, mfa, &opts, &start.session_id).await?;
        }

        // Keysets → Account Unlock Key → personal keys.
        let ks: KeysetsResponse = rest.get("v1/account/keysets").await?;
        let primary = ks
            .keysets
            .iter()
            .filter(|k| k.encrypted_by == "mp")
            .max_by_key(|k| k.sn.unwrap_or(0))
            .ok_or_else(|| Error::Protocol("no keyset encrypted by the account password".into()))?;
        let esk = &primary.enc_sym_key;
        let auk = match secret {
            Secret::Password(pw) => kdf::account_unlock_key(
                pw,
                sk,
                creds.0,
                esk.alg.as_deref().unwrap_or(kdf::ALG_PBES2G_HS256),
                &b64::decode(
                    esk.p2s
                        .as_deref()
                        .ok_or_else(|| Error::Malformed("encSymKey without p2s".into()))?,
                )?,
                check_iterations(
                    esk.p2c
                        .ok_or_else(|| Error::Malformed("encSymKey without p2c".into()))?,
                    opts.min_kdf_iterations,
                )?,
            )?,
            Secret::Keys(k) => SymmetricKey::new("mp", *k.auk),
        };
        let keysets = match decrypt_keysets(&ks.keysets, &auk) {
            Err(Error::Decrypt(_)) if matches!(secret, Secret::Keys(_)) => return Err(stale()),
            other => other?,
        };
        let unlock_keys = UnlockKeys {
            srp_x: x,
            auk: auk.as_bytes_locked(),
        };
        Ok(Account {
            rest,
            keysets,
            user_uuid,
            unlock_keys,
        })
    }

    /// The signed-in user's UUID, if the server reported it.
    pub fn user_uuid(&self) -> Option<&str> {
        self.user_uuid.as_deref()
    }

    /// Lists the vaults this account can read, with their keys unlocked.
    pub async fn vaults(&self) -> Result<Vec<Vault>> {
        let account: Value = self.rest.get("v1/account?attrs=me,vaults").await?;
        let mut out = Vec::new();
        for v in account
            .get("vaults")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let raw: RawVault = serde_json::from_value(v.clone())?;
            let Some(key) = self.vault_key(&raw.access) else {
                continue;
            };
            let attrs = match &raw.enc_attrs {
                Some(a) => a.decrypt_json(&key).unwrap_or(Value::Null),
                None => Value::Null,
            };
            out.push(Vault {
                uuid: raw.uuid,
                vault_type: raw.vault_type,
                attrs,
                active_item_count: raw.active_item_count,
                key: Arc::new(key),
            });
        }
        Ok(out)
    }

    fn vault_key(&self, access: &[RawAccess]) -> Option<SymmetricKey> {
        for a in access {
            if a.acl.is_none_or(|acl| acl & 32 == 0) {
                continue; // no read access through this grant
            }
            let Some(ks) = self.keysets.iter().find(|k| k.uuid == a.enc_vault_key.kid) else {
                continue;
            };
            if let Ok(jwk) = ks.private.decrypt_object_jwk(&a.enc_vault_key)
                && let Ok(k) = SymmetricKey::from_jwk(&jwk)
            {
                return Some(k);
            }
        }
        None
    }

    /// Downloads and decrypts every item in a vault (including trashed ones; check
    /// [`Item::trashed`]).
    pub async fn items(&self, vault: &Vault) -> Result<Vec<Item>> {
        let mut out = Vec::new();
        let mut batch: u64 = 0;
        let mut pages = 0u32;
        let mut total = 0usize; // encrypted bytes kept in memory for this vault
        loop {
            let resp: ItemsBatch = self
                .rest
                .get(&format!("v1/vault/{}/{batch}/items", vault.uuid))
                .await?;
            for it in resp.items {
                total += it.enc_overview.data.len()
                    + it.enc_details.as_ref().map_or(0, |d| d.data.len());
                if total > MAX_VAULT_BYTES {
                    return Err(Error::Protocol(format!(
                        "vault {}: more than {} MiB of item data; giving up",
                        vault.uuid,
                        MAX_VAULT_BYTES >> 20
                    )));
                }
                out.push(Item {
                    overview: it.enc_overview.decrypt_json(&vault.key)?,
                    enc_details: match it.enc_details {
                        // Decrypted on demand; check the key now so errors show up here.
                        Some(d) if d.kid != vault.key.kid() => {
                            return Err(Error::Decrypt(format!(
                                "item details encrypted with key {:?}, not {:?}",
                                d.kid,
                                vault.key.kid()
                            )));
                        }
                        d => d,
                    },
                    key: vault.key.clone(),
                    uuid: it.uuid,
                    template_uuid: it.template_uuid.unwrap_or_default(),
                    trashed: it.trashed.as_deref() == Some("Y"),
                });
            }
            if resp.batch_complete.unwrap_or(true) || resp.content_version.unwrap_or(0) <= batch {
                return Ok(out);
            }
            batch = resp.content_version.unwrap_or(0);
            pages += 1;
            // A server that never says "complete" must not keep us paging forever.
            if pages >= MAX_ITEM_PAGES {
                return Err(Error::Protocol(format!(
                    "vault {}: more than {MAX_ITEM_PAGES} pages of items; giving up",
                    vault.uuid
                )));
            }
        }
    }

    /// Resolves a secret reference `op://<vault>/<item>/<field>` (names or UUIDs, case-sensitive
    /// match on names) to its value. `Private` also matches your personal vault.
    ///
    /// ```no_run
    /// # async fn run(account: &onepw::Account) -> onepw::Result<()> {
    /// let key = account.read("op://Private/Anthropic API/credential").await?;
    /// // `key` is a Zeroizing<String>: wiped from memory when dropped.
    /// // Use it by reference (`&*key`); `key.to_string()` would make an unwiped copy.
    /// # Ok(()) }
    /// ```
    pub async fn read(&self, reference: &str) -> Result<Zeroizing<String>> {
        let r = SecretReference::parse(reference)?;
        let vaults = self.vaults().await?;
        let vault = r.find_vault(&vaults)?;
        let items = self.items(vault).await?;
        r.resolve_in(&items)
    }

    /// Ends the session on the server.
    pub async fn sign_out(self) -> Result<()> {
        let _: Value = self
            .rest
            .send(Method::PUT, "v1/session/signout", None, Reply::Plain) // response is discarded
            .await
            .or_else(|e| match e {
                Error::Malformed(_) => Ok(Value::Null), // empty body
                e => Err(e),
            })?;
        Ok(())
    }
}

async fn start_session(
    rest: &mut Rest,
    email: &str,
    sk: &SecretKey,
    opts: &SignInOptions,
) -> Result<StartResponse> {
    for _ in 0..3 {
        let start: StartResponse = rest
            .post_plain(
                "v3/auth/start",
                &json!({
                    "email": email.trim(),
                    "skFormat": sk.format(),
                    "skid": sk.account_id(),
                    "deviceUuid": opts.device_uuid,
                    "userUuid": "",
                }),
            )
            .await?;
        match start.status.as_str() {
            "ok" => return Ok(start),
            "device-not-registered" => {
                rest.session_id = Some(start.session_id.clone());
                let _: Value = rest.post_plain("v1/device", &device_body(opts)).await?;
            }
            "device-deleted" => {
                rest.session_id = Some(start.session_id.clone());
                let _: Value = rest
                    .request(
                        Method::PUT,
                        &format!("v1/device/{}/reauthorize", opts.device_uuid),
                        None,
                    )
                    .await?;
            }
            other => return Err(Error::Protocol(format!("auth/start status {other:?}"))),
        }
    }
    Err(Error::Protocol(
        "device registration did not take effect".into(),
    ))
}

async fn second_factor(
    rest: &Rest,
    mfa: &Value,
    opts: &SignInOptions,
    session_id: &str,
) -> Result<()> {
    let enabled = |k: &str| {
        mfa.get(k)
            .and_then(|v| v.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    if enabled("totp") {
        let ask = opts.totp.as_ref().ok_or_else(|| {
            Error::Unsupported("this account needs a 2FA code: set SignInOptions::totp".into())
        })?;
        let code = ask()?;
        return rest
            .post_discarding_reply(
                "v1/auth/mfa",
                &json!({"sessionID": session_id, "client": opts.identity.client_id(), "totp": {"code": code.trim()}}),
            )
            .await
            .map_err(|e| match e {
                Error::Server { status, body } => {
                    Error::InvalidInput(format!(
                        "2FA code not accepted; the session has ended, so sign in again (server: {status} {body})"
                    ))
                }
                other => other,
            });
    }
    let any = mfa.as_object().map(|m| {
        m.values()
            .any(|v| v.get("enabled").and_then(Value::as_bool) == Some(true))
    });
    if any == Some(true) {
        return Err(Error::Unsupported(
            "only authenticator-app (TOTP) 2FA is supported so far".into(),
        ));
    }
    Ok(())
}

fn device_body(opts: &SignInOptions) -> Value {
    json!({
        "uuid": opts.device_uuid,
        "clientName": opts.identity.client_name,
        "clientVersion": opts.identity.client_version,
        "name": opts.identity.device_name,
        "osName": opts.identity.os_name,
        "userAgent": opts.identity.client_id(),
    })
}

/// HTTP plumbing: identity headers, session header, MAC signing, payload encryption.
struct Rest {
    http: reqwest::Client,
    base: Url,
    headers: reqwest::header::HeaderMap,
    session_id: Option<String>,
    session_key: Option<SymmetricKey>,
    request_id: AtomicU32,
}

impl Rest {
    fn new(http: reqwest::Client, base: Url, identity: &ClientIdentity, device_uuid: &str) -> Rest {
        use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
        let mut headers = HeaderMap::new();
        let v = |s: String| {
            HeaderValue::from_str(&s).unwrap_or_else(|_| HeaderValue::from_static("onepw"))
        };
        headers.insert(CLIENT_HEADER, v(identity.client_id()));
        headers.insert(USER_AGENT, v(identity.client_id()));
        headers.insert(OP_USER_AGENT_HEADER, v(identity.op_user_agent(device_uuid)));
        Rest {
            http,
            base,
            headers,
            session_id: None,
            session_key: None,
            request_id: AtomicU32::new(1),
        }
    }

    /// Unencrypted JSON POST (before the session key is confirmed).
    async fn post_plain<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        self.send(Method::POST, path, Some(body.clone()), Reply::Plain)
            .await
    }

    /// Encrypted JSON POST.
    async fn post<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        self.post_expecting(path, body, Reply::Encrypted).await
    }

    /// Encrypted POST whose reply is discarded: an empty body is accepted too.
    async fn post_discarding_reply(&self, path: &str, body: &Value) -> Result<()> {
        let _: Value = self.post_expecting(path, body, Reply::Discarded).await?;
        Ok(())
    }

    async fn post_expecting<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &Value,
        reply: Reply,
    ) -> Result<T> {
        let key = self
            .session_key
            .as_ref()
            .ok_or_else(|| Error::Protocol("not signed in".into()))?;
        let env = EncryptedObject::encrypt(key, "b5+jwk+json", &serde_json::to_vec(body)?);
        self.send(Method::POST, path, Some(serde_json::to_value(env)?), reply)
            .await
    }

    /// Encrypted GET.
    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.send(Method::GET, path, None, Reply::Encrypted).await
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<T> {
        let reply = if self.session_key.is_some() {
            Reply::Encrypted
        } else {
            Reply::Plain
        };
        self.send(method, path, body, reply).await
    }

    async fn send<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        reply: Reply,
    ) -> Result<T> {
        let url = self
            .base
            .join(path)
            .map_err(|e| Error::InvalidInput(format!("url: {e}")))?;
        let mut req = self
            .http
            .request(method.clone(), url.clone())
            .headers(self.headers.clone());
        if let Some(sid) = &self.session_id {
            req = req.header(SESSION_HEADER, sid);
        }
        if let (Some(key), Some(sid)) = (&self.session_key, &self.session_id) {
            let id = self.request_id.fetch_add(1, Ordering::Relaxed);
            req = req.header(
                MAC_HEADER,
                mac::request_mac(key.as_bytes(), sid, id, method.as_str(), &url),
            );
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let mut resp = req.send().await?;
        let status = resp.status();
        if resp
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err(Error::Protocol(format!("{path}: response too large")));
        }
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(Error::Protocol(format!("{path}: response too large")));
            }
            body.extend_from_slice(&chunk);
        }
        let text = String::from_utf8_lossy(&body);
        if !status.is_success() {
            return Err(Error::Server {
                status: status.as_u16(),
                body: truncate(&text),
            });
        }
        let value = decode_response(path, &text, reply, self.session_key.as_ref())?;
        Ok(serde_json::from_value(value)?)
    }
}

fn truncate(s: &str) -> String {
    let mut t: String = s.chars().take(300).collect();
    if s.len() > t.len() {
        t.push('…');
    }
    t
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartResponse {
    status: String,
    #[serde(rename = "sessionID")]
    session_id: String,
    account_key_format: Option<String>,
    account_key_uuid: Option<String>,
    #[serde(default)]
    user_auth: UserAuth,
}

#[derive(Debug, Default, Deserialize)]
struct UserAuth {
    #[serde(default)]
    method: String,
    #[serde(default)]
    salt: String,
    #[serde(default)]
    iterations: u32,
}

#[derive(Deserialize)]
struct KeysetsResponse {
    keysets: Vec<EncryptedKeyset>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawVault {
    uuid: String,
    #[serde(rename = "type", default)]
    vault_type: String,
    enc_attrs: Option<EncryptedObject>,
    active_item_count: Option<u64>,
    #[serde(default)]
    access: Vec<RawAccess>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAccess {
    acl: Option<u64>,
    enc_vault_key: EncryptedObject,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ItemsBatch {
    content_version: Option<u64>,
    batch_complete: Option<bool>,
    #[serde(default)]
    items: Vec<RawItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawItem {
    uuid: String,
    template_uuid: Option<String>,
    trashed: Option<String>,
    enc_overview: EncryptedObject,
    enc_details: Option<EncryptedObject>,
}

/// Finds a vault by UUID or name. `"Private"` always means your personal vault (type `P`) and
/// never matches by name, so a vault someone shares with you named "Private" can't take its
/// place. Any other name must be unique: two readable vaults with the same name are an error.
pub fn find_vault<'a>(vaults: &'a [Vault], name_or_uuid: &str) -> Result<&'a Vault> {
    if let Some(v) = vaults.iter().find(|v| v.uuid == name_or_uuid) {
        return Ok(v);
    }
    if name_or_uuid == "Private" {
        return vaults.iter().find(|v| v.vault_type == "P").ok_or_else(|| {
            Error::InvalidInput(
                "your personal vault isn't readable (use the vault UUID for a vault named \
                 \"Private\")"
                    .into(),
            )
        });
    }
    let named: Vec<&Vault> = vaults.iter().filter(|v| v.name() == name_or_uuid).collect();
    match named.as_slice() {
        [v] => Ok(v),
        [] => Err(Error::InvalidInput(format!(
            "no readable vault {name_or_uuid:?}"
        ))),
        many => Err(Error::InvalidInput(format!(
            "{} vaults are named {:?} ({}); use the vault UUID",
            many.len(),
            name_or_uuid,
            many.iter()
                .map(|v| v.uuid.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// A parsed secret reference `op://<vault>/<item>/<field>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretReference {
    /// Vault name or UUID (`"Private"` also matches the personal vault).
    pub vault: String,
    /// Item title or UUID.
    pub item: String,
    /// Field label or designation.
    pub field: String,
}

impl SecretReference {
    /// Parses `op://vault/item/field`.
    ///
    /// ```
    /// let r = onepw::SecretReference::parse("op://Private/Anthropic API/credential")?;
    /// assert_eq!((r.vault.as_str(), r.item.as_str(), r.field.as_str()), ("Private", "Anthropic API", "credential"));
    /// # Ok::<(), onepw::Error>(())
    /// ```
    pub fn parse(reference: &str) -> Result<Self> {
        let rest = reference.trim().strip_prefix("op://").ok_or_else(|| {
            Error::InvalidInput(format!("{reference:?} doesn't start with op://"))
        })?;
        let parts: Vec<&str> = rest.split('/').collect();
        match parts[..] {
            [v, i, f] if !v.is_empty() && !i.is_empty() && !f.is_empty() => Ok(SecretReference {
                vault: v.into(),
                item: i.into(),
                field: f.into(),
            }),
            _ => Err(Error::InvalidInput(format!(
                "{reference:?}: expected op://<vault>/<item>/<field>"
            ))),
        }
    }

    /// Picks the vault this reference points to (see [`find_vault`]).
    pub fn find_vault<'a>(&self, vaults: &'a [Vault]) -> Result<&'a Vault> {
        find_vault(vaults, &self.vault)
    }

    /// Resolves the reference among a vault's items (trashed items are ignored). By UUID, or by
    /// title, which must be unique in the vault.
    pub fn resolve_in(&self, items: &[Item]) -> Result<Zeroizing<String>> {
        let live = || items.iter().filter(|i| !i.trashed);
        let item = match live().find(|i| i.uuid == self.item) {
            Some(i) => i,
            None => {
                let titled: Vec<&Item> = live().filter(|i| i.title() == self.item).collect();
                match titled.as_slice() {
                    [i] => *i,
                    [] => {
                        return Err(Error::InvalidInput(format!(
                            "no item {:?} in vault {:?}",
                            self.item, self.vault
                        )));
                    }
                    many => {
                        return Err(Error::InvalidInput(format!(
                            "{} items are titled {:?} in vault {:?} ({}); use the item UUID in \
                             the reference",
                            many.len(),
                            self.item,
                            self.vault,
                            many.iter()
                                .map(|i| i.uuid.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )));
                    }
                }
            }
        };
        item.field(&self.field)?.ok_or_else(|| {
            Error::InvalidInput(format!(
                "item {:?} has no field {:?}",
                self.item, self.field
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(uuid: &str, name: &str, vault_type: &str) -> Vault {
        Vault {
            uuid: uuid.into(),
            vault_type: vault_type.into(),
            attrs: json!({"name": name}),
            active_item_count: None,
            key: Arc::new(SymmetricKey::new(uuid, [7; 32])),
        }
    }

    fn item(uuid: &str, title: &str, key: &Arc<SymmetricKey>, password: &str) -> Item {
        let details = json!({"fields": [{"designation": "password", "value": password}]});
        Item {
            uuid: uuid.into(),
            template_uuid: "001".into(),
            trashed: false,
            overview: json!({"title": title}),
            enc_details: Some(EncryptedObject::encrypt(
                key,
                "b5+json",
                details.to_string().as_bytes(),
            )),
            key: key.clone(),
        }
    }

    #[test]
    fn ambiguous_vault_names_are_refused() {
        let vaults = [
            vault("p1", "Private", "P"),
            vault("u1", "Work", "U"),
            vault("u2", "Work", "U"),
            vault("u3", "Private", "U"),
        ];
        let r = |s: &str| SecretReference::parse(s).unwrap();
        // "Private" is the personal vault even when someone shares a vault named "Private".
        assert_eq!(
            r("op://Private/x/y").find_vault(&vaults).unwrap().uuid,
            "p1"
        );
        let err = r("op://Work/x/y")
            .find_vault(&vaults)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("2 vaults") && err.contains("u1") && err.contains("u2"),
            "{err}"
        );
        assert_eq!(r("op://u2/x/y").find_vault(&vaults).unwrap().uuid, "u2");
        // Without a readable personal vault, "Private" doesn't fall back to the shared one.
        let shared_only = [vault("u3", "Private", "U")];
        assert!(r("op://Private/x/y").find_vault(&shared_only).is_err());
        assert_eq!(
            r("op://u3/x/y").find_vault(&shared_only).unwrap().uuid,
            "u3"
        );
    }

    #[test]
    fn unknown_field_kinds_are_concealed() {
        let key = Arc::new(SymmetricKey::new("v", [7; 32]));
        let mut it = item("i1", "Server", &key, "pw");
        let details = json!({
            "fields": [
                {"designation": "username", "value": "root"},
                {"designation": "password", "type": "P", "value": "pw"},
                {"name": "pin", "type": "Z", "value": "1234"},
                {"name": "note", "type": "T", "value": "hello"}
            ],
            "sections": [{"title": "SSH", "fields": [
                {"t": "private key", "k": "sshKey", "v": "-----BEGIN OPENSSH PRIVATE KEY-----"},
                {"t": "host", "k": "string", "v": "example.org"},
                {"t": "token", "k": "concealed", "v": "t0k3n"},
                {"t": "mystery", "k": "somethingNew", "v": "?"}
            ]}]
        });
        it.enc_details = Some(EncryptedObject::encrypt(
            &key,
            "b5+json",
            details.to_string().as_bytes(),
        ));
        let hidden: Vec<(String, bool)> = it
            .fields()
            .unwrap()
            .into_iter()
            .map(|f| (f.label, f.concealed))
            .collect();
        let expect = [
            ("username", false),
            ("password", true),
            ("pin", true),
            ("note", false),
            ("private key", true),
            ("host", false),
            ("token", true),
            ("mystery", true),
        ];
        assert_eq!(hidden, expect.map(|(l, c)| (l.to_string(), c)).to_vec());
    }

    #[test]
    fn ambiguous_item_titles_are_refused() {
        let key = Arc::new(SymmetricKey::new("v", [7; 32]));
        let mut old = item("i3", "GitHub", &key, "old");
        old.trashed = true;
        let items = [
            item("i1", "GitHub", &key, "one"),
            item("i2", "GitHub", &key, "two"),
            old,
            item("i4", "AWS", &key, "aws"),
        ];
        let r = |s: &str| SecretReference::parse(s).unwrap();
        let err = r("op://V/GitHub/password")
            .resolve_in(&items)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("2 items") && err.contains("i1") && err.contains("i2"),
            "{err}"
        );
        assert_eq!(
            r("op://V/i2/password").resolve_in(&items).unwrap().as_str(),
            "two"
        );
        assert_eq!(
            r("op://V/AWS/password")
                .resolve_in(&items)
                .unwrap()
                .as_str(),
            "aws"
        );
    }

    #[test]
    fn plaintext_is_never_data_in_an_encrypted_session() {
        let key = SymmetricKey::new("SID", [9; 32]);
        let dec = |t: &str, r| decode_response("p", t, r, Some(&key));
        // Forged data, with and without error-looking markers (review finding: errorCode null).
        for t in [
            r#"{"vaults": []}"#,
            r#"{"errorCode": null, "vaults": []}"#,
            r#"{"errorCode": "x", "vaults": []}"#,
            r#"{"errorCode": 1.5, "vaults": []}"#,
            r#"{"errorCode": -1, "vaults": []}"#,
            r#"[]"#,
            r#""text""#,
            "",
        ] {
            assert!(
                dec(t, Reply::Encrypted).is_err(),
                "accepted plaintext {t:?}"
            );
        }
        // A plaintext error object is an error, never data, and is flagged as unencrypted.
        let e = dec(
            r#"{"errorCode": 102, "errorMessage": "nope"}"#,
            Reply::Encrypted,
        )
        .unwrap_err();
        assert!(
            matches!(e, Error::Protocol(_)) && e.to_string().contains("unencrypted"),
            "{e}"
        );
        // Discarded replies (2FA): anything but an error is fine, and no data comes back.
        assert_eq!(dec("", Reply::Discarded).unwrap(), Value::Null);
        assert_eq!(dec(r#"{"x": 1}"#, Reply::Discarded).unwrap(), Value::Null);
        assert!(dec(r#"{"errorCode": 102}"#, Reply::Discarded).is_err());
        assert!(dec(r#"{"errorCode": null}"#, Reply::Discarded).is_err());
        // Before sign-in, a plaintext error is an ordinary server error.
        let e = dec(r#"{"errorCode": 102}"#, Reply::Plain).unwrap_err();
        assert!(matches!(e, Error::Server { status: 102, .. }), "{e}");
        // A real envelope works, and an encrypted error is still an error.
        let ok = serde_json::to_string(&EncryptedObject::encrypt(
            &key,
            "b5+jwk+json",
            br#"{"a":1}"#,
        ))
        .unwrap();
        assert_eq!(dec(&ok, Reply::Encrypted).unwrap(), json!({"a": 1}));
        let err = serde_json::to_string(&EncryptedObject::encrypt(
            &key,
            "b5+jwk+json",
            br#"{"errorCode":null}"#,
        ))
        .unwrap();
        assert!(dec(&err, Reply::Encrypted).is_err());
        // An envelope under another key (another session) fails.
        let other = SymmetricKey::new("OTHER", [9; 32]);
        let wrong = serde_json::to_string(&EncryptedObject::encrypt(
            &other,
            "b5+jwk+json",
            br#"{"a":1}"#,
        ))
        .unwrap();
        assert!(dec(&wrong, Reply::Encrypted).is_err());
    }

    #[test]
    fn only_onepassword_domains_are_accepted() {
        let ok = |a: &str| check_onepassword_host(&Url::parse(a).unwrap()).is_ok();
        assert!(ok("https://my.1password.com/api/"));
        assert!(ok("https://MY.1Password.EU/api/"));
        assert!(ok("https://acme.ent.1password.com/api/"));
        assert!(ok("https://1password.ca/api/"));
        assert!(!ok("https://my.1passw0rd.com/api/"), "look-alike");
        assert!(
            !ok("https://my.1password.com.evil.example/api/"),
            "suffix trick"
        );
        assert!(
            !ok("https://evil1password.com/api/"),
            "no dot before the domain"
        );
        assert!(!ok("http://my.1password.com/api/"), "plain http");
        // "user@host": the URL parser sees evil.example as the host.
        assert!(!ok(&format!(
            "https://{}/api/",
            "my.1password.com@evil.example"
        )));
        assert!(
            !ok("https://user@my.1password.com/api/"),
            "credentials in the URL"
        );
    }

    #[test]
    fn low_iteration_counts_are_refused() {
        assert!(check_iterations(650_000, MIN_KDF_ITERATIONS).is_ok());
        assert!(check_iterations(100_000, MIN_KDF_ITERATIONS).is_ok());
        assert!(check_iterations(99_999, MIN_KDF_ITERATIONS).is_err());
        assert!(check_iterations(1, MIN_KDF_ITERATIONS).is_err());
    }

    #[test]
    fn wipe_json_zeroes_all_strings() {
        let mut v =
            json!({"password": "hunter2", "sections": [{"fields": [{"v": "s3cret", "n": 5}]}]});
        wipe_json(&mut v);
        assert_eq!(
            v,
            json!({"password": "", "sections": [{"fields": [{"v": "", "n": 5}]}]})
        );
    }

    #[test]
    fn details_debug_is_redacted() {
        let d = Details::new(json!({"password": "hunter2"}));
        assert_eq!(format!("{d:?}"), "Details(<redacted>)");
        assert_eq!(d["password"], "hunter2");
    }

    #[test]
    fn field_debug_is_redacted() {
        let f = Field {
            section: None,
            label: "password".into(),
            value: Zeroizing::new("hunter2".into()),
            concealed: true,
        };
        let s = format!("{f:?}");
        assert!(s.contains("password") && !s.contains("hunter2"), "{s}");
    }
}

/// Entry points for the fuzz targets in `fuzz/` (only built with `--cfg fuzzing`).
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    use super::*;

    /// Runs the response decoder on arbitrary bytes, with and without a session key.
    pub fn decode_response(text: &[u8]) {
        let text = String::from_utf8_lossy(text);
        let key = SymmetricKey::new("SESSIONID", [9; 32]);
        for reply in [Reply::Plain, Reply::Encrypted, Reply::Discarded] {
            let _ = super::decode_response("fuzz", &text, reply, Some(&key));
            let _ = super::decode_response("fuzz", &text, reply, None);
        }
    }

    /// Runs `Item::fields` / `Item::field` on arbitrary decrypted details.
    pub fn item_fields(details: &[u8], name: &str) {
        let key = Arc::new(SymmetricKey::new("vault", [7; 32]));
        let item = Item {
            uuid: "u".into(),
            template_uuid: "001".into(),
            trashed: false,
            overview: json!({"title": "t"}),
            enc_details: Some(EncryptedObject::encrypt(&key, "b5+json", details)),
            key,
        };
        let _ = item.fields();
        let _ = item.field(name);
        let _ = item.details().map(|d| format!("{d:?}"));
    }
}
