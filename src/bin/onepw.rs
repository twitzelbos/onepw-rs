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

use clap::{Parser, Subcommand};
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
    Read {
        /// Secret reference op://<vault>/<item>/<field>.
        reference: String,
        /// Don't print a trailing newline.
        #[arg(short = 'n', long)]
        no_newline: bool,
    },
    /// Run a command with every `op://…` environment value replaced by the secret.
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
        /// Show concealed values (passwords, credentials).
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

fn keychain(cfg_email: &str, address: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYCHAIN_SERVICE, &account_label(cfg_email, address))
        .map_err(|e| format!("keychain: {e}"))
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
    let sk =
        match std::env::var("ONEPW_SECRET_KEY") {
            Ok(s) => Zeroizing::new(s),
            Err(_) => Zeroizing::new(keychain(&cfg.email, &cfg.address)?.get_password().map_err(
                |e| format!("Secret Key not in keychain ({e}): run `onepw account add`"),
            )?),
        };
    let secret_key = SecretKey::parse(&sk).map_err(|e| e.to_string())?;

    #[cfg(all(feature = "touchid", target_os = "macos"))]
    if cfg.touch_id && !force_password && std::env::var("ONEPW_PASSWORD").is_err() {
        match onepw::touchid::load(&cfg.label(), "unlock your 1Password account") {
            Ok((keys, _)) => {
                match Account::sign_in_with_keys(
                    &cfg.email,
                    &cfg.address,
                    &secret_key,
                    &keys,
                    options(cfg.device_uuid.clone()),
                )
                .await
                {
                    Ok(a) => return Ok(a),
                    Err(e) => eprintln!("onepw: {e}"),
                }
            }
            Err(e) => eprintln!("onepw: {e}; using the password instead"),
        }
    }
    let _ = force_password;

    let creds = Credentials {
        email: cfg.email.clone(),
        password: password()?,
        secret_key,
        sign_in_address: cfg.address.clone(),
    };
    let account = Account::sign_in(&creds, options(cfg.device_uuid.clone()))
        .await
        .map_err(|e| format!("sign-in failed: {e}"))?;
    #[cfg(all(feature = "touchid", target_os = "macos"))]
    if cfg.touch_id {
        let _ = onepw::touchid::save(&cfg.label(), account.unlock_keys());
    }
    Ok(account)
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
            Some(f) => {
                let v: Vec<Vault> = vaults
                    .into_iter()
                    .filter(|v| {
                        v.uuid == f || v.name() == f || (f == "Private" && v.vault_type == "P")
                    })
                    .collect();
                if v.is_empty() {
                    Err(format!("no readable vault {f:?}"))
                } else {
                    Ok(v)
                }
            }
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
        Cmd::Account(AccountCmd::Add { address, email }) => {
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
            keychain(&email, &address)?
                .set_password(&sk_text)
                .map_err(|e| format!("keychain: {e}"))?;
            let p = config_path();
            std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
            let cfg = Config {
                address,
                email,
                device_uuid,
                touch_id: false,
            };
            cfg.save()?;
            eprintln!(
                "✓ {} ({} vaults). Secret Key saved in the keychain, settings in {}.",
                cfg.email,
                n,
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
            let in_keychain = keychain(&c.email, &c.address)?.get_password().is_ok();
            println!(
                "address:     {}\nemail:       {}\ndevice:      {} (shown as \"onepw\")\nSecret Key:  {}\nTouch ID:    {}",
                c.address,
                c.email,
                c.device_uuid,
                if in_keychain {
                    "in keychain"
                } else {
                    "missing"
                },
                if c.touch_id { "on" } else { "off" }
            );
        }
        Cmd::Account(AccountCmd::Forget) => {
            let c = load_config()?;
            let _ = keychain(&c.email, &c.address)?.delete_credential();
            #[cfg(all(feature = "touchid", target_os = "macos"))]
            let _ = onepw::touchid::delete(&c.label());
            let _ = std::fs::remove_file(config_path());
            eprintln!(
                "✓ forgotten. To also revoke the device: 1Password.com → Settings → Devices → \"onepw\"."
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
                    let account = sign_in_with(&cfg, true).await?;
                    let protection = onepw::touchid::save(&cfg.label(), account.unlock_keys())
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
            let mut found = None;
            for v in cache.select(vault.as_deref()).await? {
                if let Some(i) = cache
                    .items(&v)
                    .await?
                    .iter()
                    .find(|i| !i.trashed && (i.uuid == item || i.title() == item))
                {
                    found = Some((vault_label(&v), i.clone()));
                    break;
                }
            }
            let (vname, it) = found.ok_or_else(|| format!("no item {item:?}"))?;
            let mask = |f: &onepw::Field| {
                if f.concealed && !reveal {
                    "••••••••".to_string()
                } else {
                    f.value.clone()
                }
            };
            if json {
                let fields: Vec<_> = it.fields().iter().map(|f| serde_json::json!({
                    "section": f.section, "label": f.label, "value": mask(f), "concealed": f.concealed})).collect();
                let out = serde_json::json!({"uuid": it.uuid, "title": it.title(), "vault": vname, "urls": it.urls(), "fields": fields});
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            } else {
                println!("{}  ({vname}, {})", it.title(), it.uuid);
                for u in it.urls() {
                    println!("  url          {u}");
                }
                for f in it.fields() {
                    let label = match &f.section {
                        Some(s) => format!("{s} / {}", f.label),
                        None => f.label.clone(),
                    };
                    println!("  {label:<12} {}", mask(&f));
                }
                if !reveal && it.fields().iter().any(|f| f.concealed) {
                    eprintln!("(concealed values hidden; add --reveal to show them)");
                }
            }
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
            let refs: Vec<(String, String)> = std::env::vars()
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
    match run(Cli::parse()).await {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("onepw: {e}");
            ExitCode::from(1)
        }
    }
}
