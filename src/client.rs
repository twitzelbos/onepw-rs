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

use std::sync::atomic::{AtomicU32, Ordering};

use rand::Rng;
use reqwest::{Method, Url};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::{EncryptedKeyset, EncryptedObject, Keyset, SymmetricKey, decrypt_keysets};
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
    /// Base URL override (for tests). Defaults to `https://{sign_in_address}/api/`.
    pub base_url: Option<Url>,
}

impl SignInOptions {
    /// Options with a fresh device UUID and default identity.
    pub fn new() -> Self {
        SignInOptions {
            device_uuid: new_device_uuid(),
            identity: ClientIdentity::default(),
            totp: None,
            base_url: None,
        }
    }
}

impl Default for SignInOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// A random device UUID in 1Password's format (26 characters of `a-z2-7`).
pub fn new_device_uuid() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut rng = rand::thread_rng();
    (0..26)
        .map(|_| ALPHABET[rng.gen_range(0..32)] as char)
        .collect()
}

/// A signed-in, unlocked account.
pub struct Account {
    rest: Rest,
    keysets: Vec<Keyset>,
    user_uuid: Option<String>,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("base", &self.rest.base.as_str())
            .field("keysets", &self.keysets.len())
            .finish()
    }
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
    key: SymmetricKey,
}

impl Vault {
    /// The vault's name (personal vaults may have none).
    pub fn name(&self) -> &str {
        self.attrs.get("name").and_then(Value::as_str).unwrap_or("")
    }
}

/// A decrypted item.
#[derive(Clone, Debug)]
pub struct Item {
    /// Item UUID.
    pub uuid: String,
    /// Template UUID: `"001"` login, `"005"` password, `"003"` secure note, …
    pub template_uuid: String,
    /// Whether the item is in the trash.
    pub trashed: bool,
    /// Decrypted overview: `title`, `url`, `URLs`, `tags`, …
    pub overview: Value,
    /// Decrypted details: `fields`, `sections`, `notesPlain`, `password`, …
    /// Zeroing a `serde_json::Value` isn't possible; drop items as soon as you're done.
    pub details: Value,
}

impl Item {
    /// The item's title.
    pub fn title(&self) -> &str {
        self.overview
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    /// Finds a field value by its name, label or designation (`"username"`, `"password"`,
    /// `"credential"`, a section field label, …). Looks at top-level fields, the legacy
    /// `password` key, and section fields.
    pub fn field(&self, name: &str) -> Option<&str> {
        let d = &self.details;
        if let Some(fields) = d.get("fields").and_then(Value::as_array) {
            for f in fields {
                let hit = ["designation", "name"]
                    .iter()
                    .any(|k| f.get(*k).and_then(Value::as_str) == Some(name));
                if hit {
                    return f.get("value").and_then(Value::as_str);
                }
            }
        }
        if name == "password" {
            if let Some(p) = d.get("password").and_then(Value::as_str) {
                return Some(p);
            }
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
                    return f.get("v").and_then(Value::as_str);
                }
            }
        }
        None
    }
}

impl Account {
    /// Signs in with account password + Secret Key and unlocks the account's keys.
    pub async fn sign_in(creds: &Credentials, opts: SignInOptions) -> Result<Account> {
        let base = match &opts.base_url {
            Some(u) => u.clone(),
            None => Url::parse(&format!(
                "https://{}/api/",
                creds.sign_in_address.trim_end_matches('/')
            ))
            .map_err(|e| Error::InvalidInput(format!("sign-in address: {e}")))?,
        };
        let http = reqwest::Client::builder().build()?;
        let mut rest = Rest::new(http, base, &opts.identity, &opts.device_uuid);
        let sk = &creds.secret_key;

        // 1. Start the session (registering the device if needed).
        let start = start_session(&mut rest, creds, &opts).await?;
        if start.account_key_format.as_deref() != Some(sk.format())
            || start.account_key_uuid.as_deref() != Some(sk.account_id())
        {
            return Err(Error::InvalidInput(
                "Secret Key doesn't belong to this account".into(),
            ));
        }
        rest.session_id = Some(start.session_id.clone());
        let auth = start.user_auth;

        // 2. SRP: A → B.
        let salt = b64::decode(&auth.salt)?;
        let x = kdf::srp_x(
            &creds.password,
            sk,
            &creds.email,
            &auth.method,
            &salt,
            auth.iterations,
        )?;
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
        let identity = srp::identity(&creds.email, sk.account_id());
        let m1 = client.client_proof(&big_b, &key, &identity, &salt);
        let resp: Value = match rest
            .post_plain(
                "v2/auth/confirm-key",
                &json!({"clientVerifyHash": b64::encode(&m1)}),
            )
            .await
        {
            Err(Error::Server { status: 401, .. }) => {
                return Err(Error::InvalidInput(
                    "wrong account password or Secret Key".into(),
                ));
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
        rest.request_id = AtomicU32::new(rand::thread_rng().gen_range(1..u32::MAX / 2));
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
        let auk = kdf::account_unlock_key(
            &creds.password,
            sk,
            &creds.email,
            esk.alg.as_deref().unwrap_or(kdf::ALG_PBES2G_HS256),
            &b64::decode(
                esk.p2s
                    .as_deref()
                    .ok_or_else(|| Error::Malformed("encSymKey without p2s".into()))?,
            )?,
            esk.p2c
                .ok_or_else(|| Error::Malformed("encSymKey without p2c".into()))?,
        )?;
        let keysets = decrypt_keysets(&ks.keysets, &auk)?;
        Ok(Account {
            rest,
            keysets,
            user_uuid,
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
                key,
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
            if let Ok(jwk) = ks.private.decrypt_object_jwk(&a.enc_vault_key) {
                if let Ok(k) = SymmetricKey::from_jwk(&jwk) {
                    return Some(k);
                }
            }
        }
        None
    }

    /// Downloads and decrypts every item in a vault (including trashed ones; check
    /// [`Item::trashed`]).
    pub async fn items(&self, vault: &Vault) -> Result<Vec<Item>> {
        let mut out = Vec::new();
        let mut batch: u64 = 0;
        loop {
            let resp: ItemsBatch = self
                .rest
                .get(&format!("v1/vault/{}/{batch}/items", vault.uuid))
                .await?;
            for it in resp.items {
                out.push(Item {
                    overview: it.enc_overview.decrypt_json(&vault.key)?,
                    details: match &it.enc_details {
                        Some(d) => d.decrypt_json(&vault.key)?,
                        None => Value::Null,
                    },
                    uuid: it.uuid,
                    template_uuid: it.template_uuid.unwrap_or_default(),
                    trashed: it.trashed.as_deref() == Some("Y"),
                });
            }
            if resp.batch_complete.unwrap_or(true) || resp.content_version.unwrap_or(0) <= batch {
                return Ok(out);
            }
            batch = resp.content_version.unwrap_or(0);
        }
    }

    /// Resolves a secret reference `op://<vault>/<item>/<field>` (names or UUIDs, case-sensitive
    /// match on names) to its value.
    pub async fn read(&self, reference: &str) -> Result<Zeroizing<String>> {
        let rest = reference
            .strip_prefix("op://")
            .ok_or_else(|| Error::InvalidInput("reference must start with op://".into()))?;
        let parts: Vec<&str> = rest.split('/').collect();
        let [vault_ref, item_ref, field] = parts[..] else {
            return Err(Error::InvalidInput(
                "expected op://<vault>/<item>/<field>".into(),
            ));
        };
        let vaults = self.vaults().await?;
        let vault = vaults
            .iter()
            .find(|v| {
                v.uuid == vault_ref
                    || v.name() == vault_ref
                    || (vault_ref == "Private" && v.vault_type == "P")
            })
            .ok_or_else(|| Error::InvalidInput(format!("no readable vault {vault_ref:?}")))?;
        let items = self.items(vault).await?;
        let item = items
            .iter()
            .filter(|i| !i.trashed)
            .find(|i| i.uuid == item_ref || i.title() == item_ref)
            .ok_or_else(|| {
                Error::InvalidInput(format!("no item {item_ref:?} in vault {vault_ref:?}"))
            })?;
        item.field(field)
            .map(|v| Zeroizing::new(v.to_string()))
            .ok_or_else(|| Error::InvalidInput(format!("item {item_ref:?} has no field {field:?}")))
    }

    /// Ends the session on the server.
    pub async fn sign_out(self) -> Result<()> {
        let _: Value = self
            .rest
            .request(Method::PUT, "v1/session/signout", None)
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
    creds: &Credentials,
    opts: &SignInOptions,
) -> Result<StartResponse> {
    let sk = &creds.secret_key;
    for _ in 0..3 {
        let start: StartResponse = rest
            .post_plain(
                "v3/auth/start",
                &json!({
                    "email": creds.email.trim(),
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
        let _: Value = rest
            .post(
                "v1/auth/mfa",
                &json!({"sessionID": session_id, "client": opts.identity.client_id(), "totp": {"code": code.trim()}}),
            )
            .await?;
        return Ok(());
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
        self.send(Method::POST, path, Some(body.clone()), false)
            .await
    }

    /// Encrypted JSON POST.
    async fn post<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        let key = self
            .session_key
            .as_ref()
            .ok_or_else(|| Error::Protocol("not signed in".into()))?;
        let env = EncryptedObject::encrypt(key, "b5+jwk+json", &serde_json::to_vec(body)?);
        self.send(Method::POST, path, Some(serde_json::to_value(env)?), true)
            .await
    }

    /// Encrypted GET.
    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.send(Method::GET, path, None, true).await
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<T> {
        let encrypted = self.session_key.is_some();
        self.send(method, path, body, encrypted).await
    }

    async fn send<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        encrypted: bool,
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
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(Error::Server {
                status: status.as_u16(),
                body: truncate(&text),
            });
        }
        let value: Value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text)?
        };
        let value = match (encrypted, &self.session_key) {
            (true, Some(key)) if value.get("enc").is_some() && value.get("data").is_some() => {
                let env: EncryptedObject = serde_json::from_value(value)?;
                env.decrypt_json(key)?
            }
            _ => value,
        };
        if let Some(code) = value.get("errorCode").and_then(Value::as_i64) {
            let msg = value
                .get("errorMessage")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            return Err(Error::Server {
                status: code as u16,
                body: msg,
            });
        }
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
