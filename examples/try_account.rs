//! Sign in to a real 1Password account and list vaults and item counts. Prints no secrets.
//!
//! ```sh
//! cargo run --example try_account
//! ```
//!
//! Prompts for sign-in address, email, Secret Key and password (the last two hidden). Or set
//! ONEPW_ADDRESS / ONEPW_EMAIL / ONEPW_SECRET_KEY / ONEPW_PASSWORD. The device UUID is kept in
//! ~/.config/onepw/device-uuid so repeated runs don't register new devices.

use std::io::{self, Write};
use std::path::PathBuf;

use onepw::client::new_device_uuid;
use onepw::{Account, Credentials, SecretKey, SignInOptions};
use zeroize::Zeroizing;

fn ask(var: &str, prompt: &str, default: Option<&str>) -> io::Result<String> {
    if let Ok(v) = std::env::var(var) {
        return Ok(v);
    }
    match default {
        Some(d) => print!("{prompt} [{d}]: "),
        None => print!("{prompt}: "),
    }
    io::stdout().flush()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    let s = s.trim().to_string();
    Ok(if s.is_empty() { default.unwrap_or("").to_string() } else { s })
}

fn ask_hidden(var: &str, prompt: &str) -> io::Result<Zeroizing<String>> {
    if let Ok(v) = std::env::var(var) {
        return Ok(Zeroizing::new(v));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(format!("{prompt}: "))?))
}

fn device_uuid() -> String {
    let path = PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config/onepw/device-uuid");
    if let Ok(s) = std::fs::read_to_string(&path) {
        if s.trim().len() == 26 {
            return s.trim().to_string();
        }
    }
    let id = new_device_uuid();
    let _ = std::fs::create_dir_all(path.parent().unwrap());
    let _ = std::fs::write(&path, &id);
    id
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = ask("ONEPW_ADDRESS", "Sign-in address", Some("my.1password.com"))?;
    let email = ask("ONEPW_EMAIL", "Email", None)?;
    let secret_key = SecretKey::parse(&ask_hidden("ONEPW_SECRET_KEY", "Secret Key (hidden)")?)?;
    let password = ask_hidden("ONEPW_PASSWORD", "Account password (hidden)")?;

    let mut opts = SignInOptions::new();
    opts.device_uuid = device_uuid();
    opts.totp = Some(Box::new(|| {
        rpassword::prompt_password("2FA code from your authenticator app: ").map_err(|e| onepw::Error::InvalidInput(e.to_string()))
    }));

    println!("\nSigning in to {address} as {email} (device {}, shown as \"onepw\") …", opts.device_uuid);
    let creds = Credentials { email, password, secret_key, sign_in_address: address };
    let account = match Account::sign_in(&creds, opts).await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("✗ sign-in failed: {e}");
            std::process::exit(1);
        }
    };
    println!("✓ signed in, SRP verified both ways, personal keys unlocked");

    let vaults = account.vaults().await?;
    println!("✓ {} readable vault(s):", vaults.len());
    for v in &vaults {
        match account.items(v).await {
            Ok(items) => {
                let active = items.iter().filter(|i| !i.trashed).count();
                println!("    {:<28} type {}  {active} items decrypted (server says {:?})", v.name(), v.vault_type, v.active_item_count);
            }
            Err(e) => println!("    {:<28} type {}  ✗ items: {e}", v.name(), v.vault_type),
        }
    }
    account.sign_out().await?;
    println!("✓ signed out");
    Ok(())
}
