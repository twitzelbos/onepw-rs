//! `onepw`: a small command-line client for 1Password, built on the `onepw` crate.
//!
//! ```text
//! onepw account add                 one-time setup (Secret Key goes into the OS keychain)
//! onepw vault list
//! onepw item list [--vault V]
//! onepw item get <item> [--vault V] [--reveal] [--json]
//! onepw read op://vault/item/field  [-n]
//! onepw run [--env-file F] -- cmd   run cmd with op:// references in its environment resolved
//! ```
//!
//! The account password is asked for on every run (hidden), or read from `ONEPW_PASSWORD`.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use onepw::client::new_device_uuid;
use onepw::{Account, Credentials, Item, SecretKey, SecretReference, SignInOptions, Vault};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const KEYCHAIN_SERVICE: &str = "onepw";

#[derive(Parser)]
#[command(
    name = "onepw",
    version,
    about = "Unofficial 1Password command-line client (not affiliated with 1Password)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Set up, show or remove the account.
    #[command(subcommand)]
    Account(AccountCmd),
    /// Vaults.
    #[command(subcommand)]
    Vault(VaultCmd),
    /// Items.
    #[command(subcommand)]
    Item(ItemCmd),
    /// Print one secret: `onepw read op://Private/GitHub/password`.
    ///
    /// The value ends up wherever stdout goes (terminal scrollback, tmux history, a file).
    /// Prefer `onepw run`, or piping it straight into the program that needs it (the clipboard
    /// is no safer: clipboard-history tools keep copies).
    Read {
        /// Secret reference op://<vault>/<item>/<field>.
        reference: String,
        /// Don't print a trailing newline.
        #[arg(short = 'n', long)]
        no_newline: bool,
    },
    /// Run a command with every `op://…` environment value replaced by the secret.
    ///
    /// Secrets are passed as environment variables: the command and everything it starts
    /// inherits them, and some programs log their environment. Only run programs you trust.
    Run {
        /// Extra KEY=VALUE lines to load (values may be op:// references). Repeatable.
        #[arg(long = "env-file")]
        env_files: Vec<PathBuf>,
        /// The command and its arguments (after `--`).
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum AccountCmd {
    /// Sign in once, then remember address, email and device; the Secret Key goes into the keychain.
    Add {
        /// Sign-in address, e.g. my.1password.com.
        #[arg(long)]
        address: Option<String>,
        /// Account email.
        #[arg(long)]
        email: Option<String>,
        /// Where to keep the Secret Key (`systemd-creds`: Linux, sealed to this machine's TPM2).
        #[arg(long, value_enum, default_value_t = Store::Keychain)]
        store: Store,
    },
    /// Move the Secret Key to another store: `keychain` or `systemd-creds` (Linux, TPM2).
    Store {
        #[arg(value_enum)]
        to: Store,
    },
    /// Show the configured account.
    Show,
    /// Forget the account (config file and keychain entries).
    Forget,
    /// (macOS only) Unlock with Touch ID instead of the password: `on` or `off`.
    #[cfg_attr(not(target_os = "macos"), command(hide = true))]
    TouchId {
        /// `on` or `off`.
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
}

#[derive(Subcommand)]
enum VaultCmd {
    /// List readable vaults.
    List,
}

#[derive(Subcommand)]
enum ItemCmd {
    /// List items (titles).
    List {
        /// Only this vault (name or UUID).
        #[arg(long)]
        vault: Option<String>,
        /// Include trashed items.
        #[arg(long)]
        trashed: bool,
    },
    /// Show an item's fields. Concealed values are hidden unless --reveal.
    Get {
        /// Item title or UUID.
        item: String,
        /// Only look in this vault (name or UUID).
        #[arg(long)]
        vault: Option<String>,
        /// Show concealed values (passwords, credentials). They stay in your terminal's
        /// scrollback (and tmux history) afterwards.
        #[arg(long)]
        reveal: bool,
        /// Print the item as JSON (concealed values still need --reveal).
        #[arg(long)]
        json: bool,
    },
}

#[derive(Serialize, Deserialize)]
struct Config {
    address: String,
    email: String,
    device_uuid: String,
    /// Unlock with Touch ID (macOS) instead of the password.
    #[serde(default)]
    touch_id: bool,
    /// Where the Secret Key is kept.
    #[serde(default, skip_serializing_if = "Store::is_keychain")]
    secret_key_store: Store,
}

/// Where the CLI keeps the Secret Key.
#[derive(Serialize, Deserialize, ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Store {
    /// The OS keychain: macOS Keychain, or the Secret Service on Linux.
    #[default]
    Keychain,
    /// Linux: a file sealed to this machine's TPM2 and your user with `systemd-creds --user`
    /// (systemd 256 or later). For machines without a desktop keychain.
    SystemdCreds,
}

impl Store {
    fn is_keychain(&self) -> bool {
        *self == Store::Keychain
    }
}

/// Keychain account label shared by the Secret Key entry and the Touch ID entry.
fn account_label(email: &str, address: &str) -> String {
    format!("{email}@{address}")
}

impl Config {
    #[cfg_attr(not(all(feature = "touchid", target_os = "macos")), allow(dead_code))]
    fn label(&self) -> String {
        account_label(&self.email, &self.address)
    }
    fn save(&self) -> Result<(), String> {
        let p = config_path();
        std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(&p, serde_json::to_string_pretty(self).unwrap()).map_err(|e| e.to_string())
    }
}

fn config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join(".config/onepw/config.json")
}

fn load_config() -> Result<Config, String> {
    let p = config_path();
    let s = std::fs::read_to_string(&p)
        .map_err(|_| "no account configured: run `onepw account add` first".to_string())?;
    serde_json::from_str(&s).map_err(|e| format!("{}: {e}", p.display()))
}

/// The Secret Key's keychain entry: the macOS Keychain, or on Linux the Secret Service (GNOME
/// Keyring, KWallet, KeePassXC …).
fn keychain(cfg_email: &str, address: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYCHAIN_SERVICE, &account_label(cfg_email, address))
        .map_err(|e| format!("keychain: {e}"))
}

/// Where onepw 0.3.0 and earlier kept the Secret Key on Linux: the kernel keyring, which is
/// emptied on reboot. Only read to move a key to the Secret Service, and cleared by `forget`.
#[cfg(target_os = "linux")]
fn old_kernel_keyring(cfg_email: &str, address: &str) -> Result<keyring::Entry, String> {
    let c = keyring::keyutils::KeyutilsCredential::new_with_target(
        None,
        KEYCHAIN_SERVICE,
        &account_label(cfg_email, address),
    )
    .map_err(|e| format!("kernel keyring: {e}"))?;
    Ok(keyring::Entry::new_with_credential(Box::new(c)))
}

/// The Secret Key: `ONEPW_SECRET_KEY`, else the keychain.
fn secret_key_text(cfg: &Config) -> Result<Zeroizing<String>, String> {
    if let Ok(s) = std::env::var("ONEPW_SECRET_KEY") {
        return Ok(Zeroizing::new(s));
    }
    stored_secret_key(cfg, cfg.secret_key_store)
}

/// The Secret Key from `store` (ignoring `ONEPW_SECRET_KEY`).
fn stored_secret_key(cfg: &Config, store: Store) -> Result<Zeroizing<String>, String> {
    if store == Store::SystemdCreds {
        return systemd_creds::load();
    }
    let entry = keychain(&cfg.email, &cfg.address)?;
    match entry.get_password() {
        Ok(s) => Ok(Zeroizing::new(s)),
        #[cfg(target_os = "linux")]
        Err(keyring::Error::NoEntry) => {
            let old = old_kernel_keyring(&cfg.email, &cfg.address)?;
            let s = Zeroizing::new(old.get_password().map_err(|_| no_secret_key(None))?);
            entry
                .set_password(&s)
                .map_err(|e| format!("Secret Service: {e}"))?;
            let _ = old.delete_credential();
            eprintln!("onepw: moved the Secret Key from the kernel keyring to the Secret Service");
            Ok(s)
        }
        #[cfg(not(target_os = "linux"))]
        Err(keyring::Error::NoEntry) => Err(no_secret_key(None)),
        Err(e) => Err(no_secret_key(Some(&e))),
    }
}

fn no_secret_key(e: Option<&keyring::Error>) -> String {
    match e {
        None => "Secret Key not in the keychain: run `onepw account add`".into(),
        Some(e) => format!(
            "cannot read the Secret Key from the keychain ({e}). On Linux this needs a running \
             Secret Service (GNOME Keyring, KWallet, KeePassXC); without one, set ONEPW_SECRET_KEY"
        ),
    }
}

/// Saves the Secret Key text in `store`.
fn save_secret_key(email: &str, address: &str, store: Store, text: &str) -> Result<(), String> {
    match store {
        Store::Keychain => keychain(email, address)?
            .set_password(text)
            .map_err(|e| format!("keychain: {e}")),
        Store::SystemdCreds => systemd_creds::save(text),
    }
}

/// Removes the Secret Key from `store` (ignores "nothing there").
fn delete_secret_key(email: &str, address: &str, store: Store) {
    match store {
        Store::Keychain => {
            if let Ok(e) = keychain(email, address) {
                let _ = e.delete_credential();
            }
            #[cfg(target_os = "linux")]
            if let Ok(old) = old_kernel_keyring(email, address) {
                let _ = old.delete_credential();
            }
        }
        Store::SystemdCreds => {
            let _ = std::fs::remove_file(systemd_creds::path());
        }
    }
}

fn store_name(store: Store) -> &'static str {
    match store {
        Store::Keychain => "the keychain",
        Store::SystemdCreds => "a TPM-sealed file (systemd-creds)",
    }
}

/// The Secret Key sealed with `systemd-creds --user`: encrypted with a key bound to this
/// machine's TPM2 (and the host key on disk), your UID, user name and machine ID. The file is
/// useless on another machine or to another user, but any program running as you can ask
/// systemd to decrypt it, just as it could ask the Secret Service.
#[cfg(target_os = "linux")]
mod systemd_creds {
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use zeroize::Zeroizing;

    /// Embedded in the credential and checked on decryption, so another credential can't be
    /// swapped in for this file.
    const NAME: &str = "onepw-secret-key";

    pub fn path() -> PathBuf {
        super::config_path().with_file_name("secret-key.cred")
    }

    /// Whether systemd reports a fully usable TPM2 (`has-tpm2` exits 0 only then; "partial"
    /// is not enough). `systemd-analyze has-tpm2` replaced `systemd-creds has-tpm2` (still
    /// redirected as of systemd 259), so try the new one first.
    fn has_tpm2() -> bool {
        ["systemd-analyze", "systemd-creds"].iter().any(|tool| {
            Command::new(tool)
                .arg("has-tpm2")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        })
    }

    /// Runs `systemd-creds --user --name=… <args>`, feeding `input` on stdin (never argv) and
    /// returning stdout in a buffer that is wiped on drop.
    fn run(args: &[&str], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut child = Command::new("systemd-creds")
            .arg("--user")
            .arg(format!("--name={NAME}"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                format!("cannot run systemd-creds ({e}); it needs systemd 256 or later")
            })?;
        child
            .stdin
            .take()
            .expect("piped")
            .write_all(input)
            .map_err(|e| format!("systemd-creds: {e}"))?;
        // Room for any Secret Key or credential, so the buffer never reallocates (leaving copies).
        let mut out = Zeroizing::new(Vec::with_capacity(16 * 1024));
        child
            .stdout
            .take()
            .expect("piped")
            .read_to_end(&mut out)
            .map_err(|e| format!("systemd-creds: {e}"))?;
        let mut err = String::new();
        let _ = child.stderr.take().expect("piped").read_to_string(&mut err);
        let status = child.wait().map_err(|e| format!("systemd-creds: {e}"))?;
        if !status.success() {
            return Err(format!(
                "systemd-creds failed ({status}): {} (`--user` needs systemd 256 or later)",
                err.trim()
            ));
        }
        Ok(out)
    }

    /// Encrypts `secret` with `key` (`host+tpm2` in real use). Returns the credential (ciphertext).
    pub(super) fn seal(secret: &str, key: &str) -> Result<Vec<u8>, String> {
        let out = run(
            &[&format!("--with-key={key}"), "encrypt", "-", "-"],
            secret.as_bytes(),
        )?;
        Ok(out.to_vec())
    }

    pub(super) fn unseal(file: &Path) -> Result<Zeroizing<String>, String> {
        let blob = std::fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
        let out = run(&["--newline=no", "decrypt", "-", "-"], &blob)?;
        let text = std::str::from_utf8(&out).map_err(|_| "sealed Secret Key is not text")?;
        Ok(Zeroizing::new(text.to_owned()))
    }

    /// Writes `blob` to `file`, readable by you only, replacing it atomically.
    pub(super) fn write_private(file: &Path, blob: &[u8]) -> Result<(), String> {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = file.parent().expect("config dir");
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let tmp = file.with_extension("cred.tmp");
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(blob)
            .and_then(|()| f.sync_all())
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, file).map_err(|e| format!("{}: {e}", file.display()))
    }

    pub fn save(secret: &str) -> Result<(), String> {
        if !has_tpm2() {
            return Err(
                "no usable TPM2 (`systemd-creds has-tpm2`): use the keychain, or set \
                        ONEPW_SECRET_KEY"
                    .into(),
            );
        }
        let blob = seal(secret, "host+tpm2")?;
        let file = path();
        write_private(&file, &blob)?;
        // Check it opens before relying on it.
        match unseal(&file) {
            Ok(back) if back.as_str() == secret => Ok(()),
            Ok(_) => Err("systemd-creds returned a different value".into()),
            Err(e) => Err(e),
        }
    }

    pub fn load() -> Result<Zeroizing<String>, String> {
        let file = path();
        if !file.exists() {
            return Err(format!(
                "Secret Key not found at {}: run `onepw account add --store systemd-creds`",
                file.display()
            ));
        }
        unseal(&file)
    }
}

/// `systemd-creds` is Linux only.
#[cfg(not(target_os = "linux"))]
mod systemd_creds {
    use std::path::PathBuf;

    use zeroize::Zeroizing;

    const LINUX_ONLY: &str = "the systemd-creds store is Linux only";

    pub fn path() -> PathBuf {
        super::config_path().with_file_name("secret-key.cred")
    }
    pub fn save(_: &str) -> Result<(), String> {
        Err(LINUX_ONLY.into())
    }
    pub fn load() -> Result<Zeroizing<String>, String> {
        Err(LINUX_ONLY.into())
    }
}

fn prompt(label: &str, default: Option<&str>) -> io::Result<String> {
    match default {
        Some(d) => eprint!("{label} [{d}]: "),
        None => eprint!("{label}: "),
    }
    io::stderr().flush()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    let s = s.trim();
    Ok(if s.is_empty() {
        default.unwrap_or("").to_string()
    } else {
        s.to_string()
    })
}

fn hidden(label: &str) -> io::Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(format!(
        "{label}: "
    ))?))
}

fn password() -> Result<Zeroizing<String>, String> {
    if let Ok(p) = std::env::var("ONEPW_PASSWORD") {
        return Ok(Zeroizing::new(p));
    }
    hidden("1Password account password").map_err(|e| format!("cannot read password: {e}"))
}

fn options(device_uuid: String) -> SignInOptions {
    let mut opts = SignInOptions::new();
    opts.device_uuid = device_uuid;
    opts.totp = Some(Box::new(|| {
        rpassword::prompt_password("2FA code: ")
            .map_err(|e| onepw::Error::InvalidInput(e.to_string()))
    }));
    opts
}

async fn sign_in() -> Result<Account, String> {
    let cfg = load_config()?;
    sign_in_with(&cfg, false).await
}

/// Signs in with Touch ID when enabled (unless `force_password`), else with the password. After a
/// password sign-in with Touch ID enabled, the stored keys are refreshed (e.g. after a password
/// change).
async fn sign_in_with(cfg: &Config, force_password: bool) -> Result<Account, String> {
    Ok(sign_in_full(cfg, force_password).await?.0)
}

/// [`sign_in_with`], also returning the Secret Key that was used.
async fn sign_in_full(cfg: &Config, force_password: bool) -> Result<(Account, SecretKey), String> {
    #[cfg(all(feature = "touchid", target_os = "macos"))]
    if cfg.touch_id && !force_password && std::env::var("ONEPW_PASSWORD").is_err() {
        // One item behind one Touch ID prompt holds the unlock keys and the Secret Key.
        match onepw::touchid::load_with_secret_key(&cfg.label(), "unlock your 1Password account") {
            Ok(stored) => {
                let from_env = std::env::var_os("ONEPW_SECRET_KEY").is_some();
                // Items saved by 0.3.0 and earlier have no Secret Key: read it from the keychain
                // this once, then upgrade the item.
                let upgrade = stored.secret_key.is_none() && !from_env;
                let secret_key = match stored.secret_key {
                    Some(sk) if !from_env => Ok(sk),
                    _ => secret_key_text(cfg)
                        .and_then(|t| SecretKey::parse(&t).map_err(|e| e.to_string())),
                };
                match secret_key {
                    Ok(secret_key) => match Account::sign_in_with_keys(
                        &cfg.email,
                        &cfg.address,
                        &secret_key,
                        &stored.keys,
                        options(cfg.device_uuid.clone()),
                    )
                    .await
                    {
                        Ok(a) => {
                            if upgrade {
                                let _ = onepw::touchid::save_with_secret_key(
                                    &cfg.label(),
                                    &stored.keys,
                                    &secret_key,
                                );
                            }
                            return Ok((a, secret_key));
                        }
                        Err(e) => eprintln!("onepw: {e}"),
                    },
                    Err(e) => return Err(e),
                }
            }
            Err(e) => eprintln!("onepw: {e}; using the password instead"),
        }
    }
    let _ = force_password;

    let sk = secret_key_text(cfg)?;
    let creds = Credentials {
        email: cfg.email.clone(),
        password: password()?,
        secret_key: SecretKey::parse(&sk).map_err(|e| e.to_string())?,
        sign_in_address: cfg.address.clone(),
    };
    let account = Account::sign_in(&creds, options(cfg.device_uuid.clone()))
        .await
        .map_err(|e| format!("sign-in failed: {e}"))?;
    #[cfg(all(feature = "touchid", target_os = "macos"))]
    if cfg.touch_id {
        let _ = onepw::touchid::save_with_secret_key(
            &cfg.label(),
            account.unlock_keys(),
            &creds.secret_key,
        );
    }
    Ok((account, creds.secret_key))
}

/// Caches vaults and per-vault items so several references cost one download each.
struct Cache<'a> {
    account: &'a Account,
    vaults: Option<Vec<Vault>>,
    items: HashMap<String, Vec<Item>>,
}

impl<'a> Cache<'a> {
    fn new(account: &'a Account) -> Self {
        Cache {
            account,
            vaults: None,
            items: HashMap::new(),
        }
    }

    async fn vaults(&mut self) -> Result<&[Vault], String> {
        if self.vaults.is_none() {
            self.vaults = Some(self.account.vaults().await.map_err(|e| e.to_string())?);
        }
        Ok(self.vaults.as_deref().unwrap())
    }

    async fn items(&mut self, vault: &Vault) -> Result<&[Item], String> {
        if !self.items.contains_key(&vault.uuid) {
            let items = self.account.items(vault).await.map_err(|e| e.to_string())?;
            self.items.insert(vault.uuid.clone(), items);
        }
        Ok(&self.items[&vault.uuid])
    }

    async fn resolve(&mut self, reference: &str) -> Result<Zeroizing<String>, String> {
        let r = SecretReference::parse(reference).map_err(|e| e.to_string())?;
        let vault = r
            .find_vault(self.vaults().await?)
            .map_err(|e| e.to_string())?
            .clone();
        let items = self.items(&vault).await?;
        r.resolve_in(items).map_err(|e| e.to_string())
    }

    /// Vaults matching an optional name/UUID filter.
    async fn select(&mut self, filter: Option<&str>) -> Result<Vec<Vault>, String> {
        let vaults = self.vaults().await?.to_vec();
        match filter {
            None => Ok(vaults),
            // Same rules as op:// references: UUID, "Private" = personal vault, unique name.
            Some(f) => onepw::client::find_vault(&vaults, f)
                .map(|v| vec![v.clone()])
                .map_err(|e| e.to_string()),
        }
    }
}

fn vault_label(v: &Vault) -> String {
    if v.name().is_empty() && v.vault_type == "P" {
        "Private".into()
    } else {
        v.name().to_string()
    }
}

async fn run(cli: Cli) -> Result<i32, String> {
    match cli.cmd {
        Cmd::Account(AccountCmd::Add {
            address,
            email,
            store,
        }) => {
            #[cfg(not(target_os = "linux"))]
            if store == Store::SystemdCreds {
                return Err("--store systemd-creds is Linux only".into());
            }
            let address = match address {
                Some(a) => a,
                None => prompt("Sign-in address", Some("my.1password.com"))
                    .map_err(|e| e.to_string())?,
            };
            let email = match email {
                Some(e) => e,
                None => prompt("Email", None).map_err(|e| e.to_string())?,
            };
            let sk_text = hidden("Secret Key (A3-…, hidden)").map_err(|e| e.to_string())?;
            let secret_key = SecretKey::parse(&sk_text).map_err(|e| e.to_string())?;
            let device_uuid = load_config()
                .map(|c| c.device_uuid)
                .unwrap_or_else(|_| new_device_uuid());
            let creds = Credentials {
                email: email.clone(),
                password: password()?,
                secret_key,
                sign_in_address: address.clone(),
            };
            eprintln!("Signing in to check the details…");
            let account = Account::sign_in(&creds, options(device_uuid.clone()))
                .await
                .map_err(|e| format!("sign-in failed: {e}"))?;
            let n = account.vaults().await.map_err(|e| e.to_string())?.len();
            let _ = account.sign_out().await;
            save_secret_key(&email, &address, store, &sk_text)?;
            let p = config_path();
            std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
            let cfg = Config {
                address,
                email,
                device_uuid,
                touch_id: false,
                secret_key_store: store,
            };
            cfg.save()?;
            eprintln!(
                "✓ {} ({} vaults). Secret Key saved in {}, settings in {}.",
                cfg.email,
                n,
                store_name(store),
                p.display()
            );
            eprintln!(
                "  The account password is never stored: you'll be asked for it each time (or set ONEPW_PASSWORD)."
            );
            #[cfg(all(feature = "touchid", target_os = "macos"))]
            eprintln!("  Tip: `onepw account touch-id on` to unlock with Touch ID instead.");
        }
        Cmd::Account(AccountCmd::Show) => {
            let c = load_config()?;
            let where_ = match c.secret_key_store {
                // Only checks the file is there; decrypting it isn't needed to show this.
                Store::SystemdCreds if systemd_creds::path().exists() => {
                    format!("TPM-sealed in {}", systemd_creds::path().display())
                }
                Store::SystemdCreds => "missing".into(),
                Store::Keychain if keychain(&c.email, &c.address)?.get_password().is_ok() => {
                    "in keychain".into()
                }
                Store::Keychain => "missing".into(),
            };
            println!(
                "address:     {}\nemail:       {}\ndevice:      {} (shown as \"onepw\")\nSecret Key:  {}\nTouch ID:    {}",
                c.address,
                c.email,
                c.device_uuid,
                where_,
                if c.touch_id { "on" } else { "off" }
            );
        }
        Cmd::Account(AccountCmd::Forget) => {
            let c = load_config()?;
            delete_secret_key(&c.email, &c.address, Store::Keychain);
            delete_secret_key(&c.email, &c.address, Store::SystemdCreds);
            #[cfg(all(feature = "touchid", target_os = "macos"))]
            let _ = onepw::touchid::delete(&c.label());
            let _ = std::fs::remove_file(config_path());
            eprintln!(
                "✓ forgotten. To also revoke the device: 1Password.com → Settings → Devices → \"onepw\"."
            );
        }
        Cmd::Account(AccountCmd::Store { to }) => {
            let mut cfg = load_config()?;
            let from = cfg.secret_key_store;
            if from == to {
                eprintln!("The Secret Key is already in {}.", store_name(to));
                return Ok(0);
            }
            let text = stored_secret_key(&cfg, from)?;
            SecretKey::parse(&text).map_err(|e| e.to_string())?;
            save_secret_key(&cfg.email, &cfg.address, to, &text)?;
            if stored_secret_key(&cfg, to)?.as_str() != text.as_str() {
                return Err(format!("{} returned a different value", store_name(to)));
            }
            cfg.secret_key_store = to;
            cfg.save()?;
            delete_secret_key(&cfg.email, &cfg.address, from);
            eprintln!(
                "✓ Secret Key moved from {} to {}.",
                store_name(from),
                store_name(to)
            );
        }
        Cmd::Account(AccountCmd::TouchId { state }) => {
            let mut cfg = load_config()?;
            #[cfg(all(feature = "touchid", target_os = "macos"))]
            {
                if state == "on" {
                    if !onepw::touchid::is_available() {
                        return Err("Touch ID isn't available on this Mac (no sensor, or no enrolled finger)".into());
                    }
                    eprintln!("Sign in once with your password to set up Touch ID…");
                    let (account, secret_key) = sign_in_full(&cfg, true).await?;
                    let protection = onepw::touchid::save_with_secret_key(
                        &cfg.label(),
                        account.unlock_keys(),
                        &secret_key,
                    )
                    .map_err(|e| e.to_string())?;
                    let _ = account.sign_out().await;
                    cfg.touch_id = true;
                    cfg.save()?;
                    eprintln!(
                        "✓ Touch ID on ({}).",
                        match protection {
                            onepw::touchid::Protection::Biometry => "Secure Enclave enforced",
                            onepw::touchid::Protection::TouchIdGate =>
                                "checked by onepw; sign the binary with a Developer ID for Secure Enclave enforcement",
                        }
                    );
                } else {
                    let _ = onepw::touchid::delete(&cfg.label());
                    cfg.touch_id = false;
                    cfg.save()?;
                    eprintln!(
                        "✓ Touch ID off; stored keys removed. The password will be asked for again."
                    );
                }
            }
            #[cfg(not(all(feature = "touchid", target_os = "macos")))]
            {
                let _ = (&mut cfg, state);
                return Err("Touch ID unlock is macOS only".into());
            }
        }
        Cmd::Vault(VaultCmd::List) => {
            let account = sign_in().await?;
            for v in account.vaults().await.map_err(|e| e.to_string())? {
                println!(
                    "{:<26}  {:<28} {:>5} items",
                    v.uuid,
                    vault_label(&v),
                    v.active_item_count.unwrap_or(0)
                );
            }
            let _ = account.sign_out().await;
        }
        Cmd::Item(ItemCmd::List { vault, trashed }) => {
            let account = sign_in().await?;
            let mut cache = Cache::new(&account);
            let mut rows = Vec::new();
            for v in cache.select(vault.as_deref()).await? {
                for i in cache.items(&v).await? {
                    if trashed || !i.trashed {
                        rows.push((vault_label(&v), i.title().to_string(), i.uuid.clone()));
                    }
                }
            }
            rows.sort_by_key(|r| r.1.to_lowercase());
            for (v, t, u) in rows {
                println!("{u:<26}  {v:<16} {t}");
            }
            let _ = account.sign_out().await;
        }
        Cmd::Item(ItemCmd::Get {
            item,
            vault,
            reveal,
            json,
        }) => {
            let account = sign_in().await?;
            let mut cache = Cache::new(&account);
            // A UUID wins; a title must be unique across the searched vaults.
            let mut by_uuid = None;
            let mut by_title = Vec::new();
            for v in cache.select(vault.as_deref()).await? {
                for i in cache.items(&v).await?.iter().filter(|i| !i.trashed) {
                    if i.uuid == item {
                        by_uuid = Some((vault_label(&v), i.clone()));
                    } else if i.title() == item {
                        by_title.push((vault_label(&v), i.clone()));
                    }
                }
            }
            let (vname, it) = match (by_uuid, by_title.len()) {
                (Some(hit), _) => hit,
                (None, 1) => by_title.pop().unwrap(),
                (None, 0) => return Err(format!("no item {item:?}")),
                (None, n) => {
                    let list: Vec<String> = by_title
                        .iter()
                        .map(|(v, i)| format!("  {}  ({v})", i.uuid))
                        .collect();
                    return Err(format!(
                        "{n} items are titled {item:?}; use the UUID (or --vault):\n{}",
                        list.join("\n")
                    ));
                }
            };
            let fields = it.fields().map_err(|e| e.to_string())?;
            let mask = |f: &onepw::Field| -> Zeroizing<String> {
                if f.concealed && !reveal {
                    Zeroizing::new("••••••••".to_string())
                } else {
                    f.value.clone()
                }
            };
            let mut out = io::stdout().lock();
            // Grows without leaving unwiped copies behind; wiped on drop.
            let mut text = WipingBuf::default();
            if json {
                use serde_json::{Map, Value};
                // Built by moving values in (json! would copy them), then wiped as a whole.
                let mut list = Vec::with_capacity(fields.len());
                for f in &fields {
                    let mut m = Map::new();
                    m.insert("section".into(), serde_json::json!(f.section));
                    m.insert("label".into(), Value::String(f.label.clone()));
                    m.insert("value".into(), Value::String(mask(f).to_string()));
                    m.insert("concealed".into(), Value::Bool(f.concealed));
                    list.push(Value::Object(m));
                }
                let mut m = Map::new();
                m.insert("uuid".into(), Value::String(it.uuid.clone()));
                m.insert("title".into(), Value::String(it.title().into()));
                m.insert("vault".into(), Value::String(vname.clone()));
                m.insert("urls".into(), serde_json::json!(it.urls()));
                m.insert("fields".into(), Value::Array(list));
                let doc = onepw::Details::new(Value::Object(m));
                serde_json::to_writer_pretty(&mut text, &*doc).map_err(|e| e.to_string())?;
                io::Write::write_all(&mut text, b"\n").map_err(|e| e.to_string())?;
            } else {
                let _ = writeln!(text, "{}  ({vname}, {})", it.title(), it.uuid);
                for u in it.urls() {
                    let _ = writeln!(text, "  url          {u}");
                }
                for f in &fields {
                    let label = match &f.section {
                        Some(s) => format!("{s} / {}", f.label),
                        None => f.label.clone(),
                    };
                    let _ = writeln!(text, "  {label:<12} {}", mask(f).as_str());
                }
                if !reveal && fields.iter().any(|f| f.concealed) {
                    eprintln!("(concealed values hidden; add --reveal to show them)");
                }
            }
            out.write_all(text.as_bytes())
                .and_then(|_| out.flush())
                .map_err(|e| e.to_string())?;
            drop(out);
            let _ = account.sign_out().await;
        }
        Cmd::Read {
            reference,
            no_newline,
        } => {
            SecretReference::parse(&reference).map_err(|e| e.to_string())?; // fail fast, before the password prompt
            let account = sign_in().await?;
            let value = Cache::new(&account).resolve(&reference).await;
            let _ = account.sign_out().await;
            let value = value?;
            let mut out = io::stdout();
            out.write_all(value.as_bytes()).map_err(|e| e.to_string())?;
            if !no_newline {
                out.write_all(b"\n").map_err(|e| e.to_string())?;
            }
        }
        Cmd::Run { env_files, command } => {
            let mut env: Vec<(String, String)> = Vec::new();
            for f in &env_files {
                let text =
                    std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?;
                for line in text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                {
                    let line = line.strip_prefix("export ").unwrap_or(line);
                    if let Some((k, v)) = line.split_once('=') {
                        env.push((
                            k.trim().to_string(),
                            v.trim().trim_matches('"').trim_matches('\'').to_string(),
                        ));
                    }
                }
            }
            // vars_os: a non-UTF-8 variable must not panic (the panic message would print it).
            let refs: Vec<(String, String)> = std::env::vars_os()
                .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
                .chain(env.iter().cloned())
                .filter(|(_, v)| v.starts_with("op://"))
                .collect();
            let mut resolved: Vec<(String, Zeroizing<String>)> = Vec::new();
            if !refs.is_empty() {
                let account = sign_in().await?;
                let mut cache = Cache::new(&account);
                for (k, r) in &refs {
                    let v = cache.resolve(r).await.map_err(|e| format!("{k}: {e}"))?;
                    resolved.push((k.clone(), v));
                }
                let _ = account.sign_out().await;
            }
            let mut child = tokio::process::Command::new(&command[0]);
            child.args(&command[1..]);
            // Never hand onepw's own credentials (ONEPW_PASSWORD, ONEPW_SECRET_KEY, …) to the
            // command, whether they come from the shell or an --env-file.
            for (k, _) in std::env::vars_os() {
                if k.to_string_lossy().starts_with("ONEPW_") {
                    child.env_remove(&k);
                }
            }
            env.retain(|(k, _)| !k.starts_with("ONEPW_"));
            resolved.retain(|(k, _)| !k.starts_with("ONEPW_"));
            for (k, v) in &env {
                child.env(k, v);
            }
            for (k, v) in &resolved {
                child.env(k, v.as_str());
            }
            let status = child
                .status()
                .await
                .map_err(|e| format!("{}: {e}", command[0]))?;
            return Ok(status.code().unwrap_or(1));
        }
    }
    Ok(0)
}

#[tokio::main]
async fn main() -> ExitCode {
    disable_core_dumps();
    match run(Cli::parse()).await {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("onepw: {e}");
            ExitCode::from(1)
        }
    }
}

/// A crash must not write decrypted secrets to a core file.
#[cfg(unix)]
fn disable_core_dumps() {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit only reads the struct we pass.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &none);
    }
}

#[cfg(not(unix))]
fn disable_core_dumps() {}

/// An output buffer that wipes itself: on drop, and whenever it grows (the old allocation is
/// zeroed before it's freed), so revealed values don't linger in freed memory.
#[derive(Default)]
struct WipingBuf(Zeroizing<Vec<u8>>);

impl WipingBuf {
    fn reserve(&mut self, extra: usize) {
        let need = self.0.len() + extra;
        if need > self.0.capacity() {
            let mut bigger = Zeroizing::new(Vec::with_capacity(
                need.max(2 * self.0.capacity()).max(1024),
            ));
            bigger.extend_from_slice(&self.0);
            self.0 = bigger; // the old buffer is wiped as it drops
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl io::Write for WipingBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.reserve(buf.len());
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Needs a running, unlocked Secret Service and the kernel keyring, so it's ignored by default;
/// CI runs it in the `linux-keychain` job (gnome-keyring in a private D-Bus session).
#[cfg(all(test, target_os = "linux"))]
mod linux_keychain_tests {
    use super::*;

    #[test]
    #[ignore]
    fn secret_key_moves_from_kernel_keyring_to_secret_service() {
        assert!(std::env::var_os("ONEPW_SECRET_KEY").is_none());
        let cfg = Config {
            address: "ci.1password.com".into(),
            email: "ci@example.com".into(),
            device_uuid: String::new(),
            touch_id: false,
            secret_key_store: Store::Keychain,
        };
        let sk = "A3-8MMQJN-MZ64CY-2SDB4-RPX3T-V52Q3-N2C84";
        let service = keychain(&cfg.email, &cfg.address).unwrap();
        let old = old_kernel_keyring(&cfg.email, &cfg.address).unwrap();
        let _ = service.delete_credential();
        old.set_password(sk).unwrap();

        // First read moves the key; the kernel copy is gone, the Secret Service has it.
        assert_eq!(secret_key_text(&cfg).unwrap().as_str(), sk);
        assert!(matches!(old.get_password(), Err(keyring::Error::NoEntry)));
        assert_eq!(service.get_password().unwrap(), sk);
        // Later reads come straight from the Secret Service.
        assert_eq!(secret_key_text(&cfg).unwrap().as_str(), sk);

        service.delete_credential().unwrap();
        assert!(
            secret_key_text(&cfg)
                .unwrap_err()
                .contains("onepw account add")
        );
    }
}

/// Needs systemd 256+ (for `systemd-creds --user`), so it's ignored by default; CI runs it in the
/// `linux-systemd-creds` job. CI machines have no TPM, so this uses the host key; real use
/// requires `host+tpm2`.
#[cfg(all(test, target_os = "linux"))]
mod systemd_creds_tests {
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};

    use super::systemd_creds::{seal, unseal, write_private};

    const SK: &str = "A3-8MMQJN-MZ64CY-2SDB4-RPX3T-V52Q3-N2C84";

    #[test]
    #[ignore]
    fn secret_key_is_sealed_and_bound_to_its_name() {
        let dir = std::env::temp_dir().join(format!("onepw-creds-{}", std::process::id()));
        let file = dir.join("secret-key.cred");

        let blob = seal(SK, "host").expect("seal");
        assert!(
            !blob.windows(SK.len()).any(|w| w == SK.as_bytes()),
            "the file holds ciphertext, not the key"
        );
        write_private(&file, &blob).unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "readable by the user only");
        assert_eq!(unseal(&file).expect("unseal").as_str(), SK);

        // A tampered file doesn't open.
        let mut bad = blob.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 1;
        write_private(&file, &bad).unwrap();
        assert!(unseal(&file).is_err(), "tampering is detected");

        // A credential made under another name isn't accepted as the Secret Key.
        let mut child = Command::new("systemd-creds")
            .args([
                "--user",
                "--name=something-else",
                "--with-key=host",
                "encrypt",
                "-",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), SK.as_bytes()).unwrap();
        let other = child.wait_with_output().unwrap();
        assert!(other.status.success());
        write_private(&file, &other.stdout).unwrap();
        assert!(unseal(&file).is_err(), "the embedded name is checked");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
