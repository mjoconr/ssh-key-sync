//! SSH Key Sync portable client.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    time::Duration,
};

use clap::{Parser, Subcommand};
use fs2::FileExt as _;
use serde::Deserialize;
use ssh_key_sync_core::{
    SignedEnvelope, load_verifying_key, new_nonce, parse_public_key, unix_now, verify_envelope,
};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Client configuration path.
    #[arg(long, default_value = "/etc/ssh-key-sync/client.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Fetch, verify, and install the configured public key set.
    Sync {
        /// Verify and print changes without writing `authorized_keys`.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print the effective `AuthorizedKeysFile` setting.
    InspectSshd,
    /// Configure the existing and managed authorization files.
    ConfigureSshd {
        /// Apply the validated configuration change.
        #[arg(long)]
        apply: bool,
        /// Do not reload the SSH service after applying.
        #[arg(long)]
        no_reload: bool,
        /// SSH configuration drop-in path.
        #[arg(long, default_value = "/etc/ssh/sshd_config.d/20-ssh-key-sync.conf")]
        drop_in: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    schema_version: u32,
    server_url: String,
    verifying_key_file: PathBuf,
    authorized_keys_file: PathBuf,
    #[serde(default)]
    token_file: Option<PathBuf>,
    #[serde(default)]
    allow_empty: bool,
}

impl ClientConfig {
    fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let config: Self = toml::from_str(&fs::read_to_string(path)?)?;
        if config.schema_version != 1 {
            return Err("unsupported client schema_version".into());
        }
        if !config.server_url.starts_with("https://")
            && !config.server_url.starts_with("http://127.0.0.1")
        {
            return Err(
                "server_url must use HTTPS (local development may use loopback HTTP)".into(),
            );
        }
        Ok(config)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Sync { dry_run } => sync(&cli.config, dry_run).await?,
        Command::InspectSshd => inspect_sshd()?,
        Command::ConfigureSshd {
            apply,
            no_reload,
            drop_in,
        } => configure_sshd(&cli.config, apply, no_reload, &drop_in)?,
    }
    Ok(())
}

async fn sync(config_path: &Path, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::load(config_path)?;
    let verifying_key = load_verifying_key(&config.verifying_key_file)?;
    let nonce = new_nonce();
    let endpoint = format!(
        "{}/v1/keys{}",
        config.server_url.trim_end_matches('/'),
        if config.token_file.is_some() {
            ""
        } else {
            "/public"
        }
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .connect_timeout(Duration::from_secs(10))
        .https_only(config.server_url.starts_with("https://"))
        .build()?;
    let mut request = client.get(endpoint).header("x-request-nonce", &nonce);
    if let Some(path) = config.token_file {
        let token = fs::read_to_string(path)?;
        request = request.bearer_auth(token.trim());
    }
    let envelope: SignedEnvelope = request.send().await?.error_for_status()?.json().await?;
    let payload = verify_envelope(&envelope, &verifying_key, &nonce, unix_now())?;
    if payload.keys.is_empty() && !config.allow_empty {
        return Err("server returned an empty key set; refusing to modify authorized_keys".into());
    }
    let mut content = payload
        .keys
        .iter()
        .map(|key| key.authorized_keys.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    println!(
        "verified group {} with {} keys",
        payload.group,
        payload.keys.len()
    );
    for key in &payload.keys {
        println!("  {}", key.fingerprint);
    }
    if dry_run {
        println!(
            "dry run: {} was not changed",
            config.authorized_keys_file.display()
        );
        return Ok(());
    }
    install_file(&config.authorized_keys_file, content.as_bytes())?;
    println!("installed {}", config.authorized_keys_file.display());
    Ok(())
}

fn install_file(path: &Path, content: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path.parent().ok_or("authorized_keys path has no parent")?;
    fs::create_dir_all(parent)?;
    let lock_path = path.with_extension("lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path)?;
    lock.lock_exclusive()?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err("refusing to replace a symbolic link".into());
        }
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temporary.write_all(content)?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(path)?;
    let installed = fs::read_to_string(path)?;
    for line in installed.lines() {
        parse_public_key(line)?;
    }
    Ok(())
}

fn inspect_sshd() -> Result<(), Box<dyn std::error::Error>> {
    let line = effective_authorized_keys_file()?;
    println!("AuthorizedKeysFile {line}");
    Ok(())
}

fn effective_authorized_keys_file() -> Result<String, Box<dyn std::error::Error>> {
    let output = ProcessCommand::new("sshd")
        .args(["-T", "-C", "user=root,host=localhost,addr=127.0.0.1"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "sshd -T failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let config = String::from_utf8(output.stdout)?;
    let line = config
        .lines()
        .find(|line| line.starts_with("authorizedkeysfile "))
        .ok_or("sshd did not report authorizedkeysfile")?;
    Ok(line.trim_start_matches("authorizedkeysfile ").to_owned())
}

fn configure_sshd(
    config_path: &Path,
    apply: bool,
    no_reload: bool,
    drop_in: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::load(config_path)?;
    let managed = config
        .authorized_keys_file
        .to_str()
        .ok_or("managed authorized_keys path is not UTF-8")?;
    let current = effective_authorized_keys_file()?;
    let mut files = current
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !files.iter().any(|file| file == managed) {
        files.push(managed.to_owned());
    }
    let desired = format!("AuthorizedKeysFile {}\n", files.join(" "));
    if current.split_whitespace().any(|file| file == managed) {
        println!("managed file is already effective: {managed}");
        return Ok(());
    }
    println!("current:   {current}");
    println!("proposed:  {}", files.join(" "));
    println!("drop-in:   {}", drop_in.display());
    if !apply {
        println!("dry run: use --apply to write and validate the configuration");
        return Ok(());
    }

    let parent = drop_in.parent().ok_or("drop-in path has no parent")?;
    fs::create_dir_all(parent)?;
    let backup = drop_in.with_extension("before-ssh-key-sync");
    let existing = fs::read(drop_in).ok();
    if let Some(ref content) = existing {
        fs::write(&backup, content)?;
    }
    atomic_write(drop_in, desired.as_bytes())?;

    let validation = ProcessCommand::new("sshd").arg("-t").status()?;
    if !validation.success() {
        restore_drop_in(drop_in, &backup, existing.as_deref())?;
        return Err("sshd rejected the new configuration; previous configuration restored".into());
    }
    let effective = effective_authorized_keys_file()?;
    if !effective.split_whitespace().any(|file| file == managed) {
        restore_drop_in(drop_in, &backup, existing.as_deref())?;
        return Err("drop-in was not effective; previous configuration restored".into());
    }
    if !no_reload {
        let reloaded = ProcessCommand::new("systemctl")
            .args(["reload", "ssh.service"])
            .status()
            .is_ok_and(|status| status.success())
            || ProcessCommand::new("systemctl")
                .args(["reload", "sshd.service"])
                .status()
                .is_ok_and(|status| status.success());
        if !reloaded {
            restore_drop_in(drop_in, &backup, existing.as_deref())?;
            return Err("SSH service reload failed; previous configuration restored".into());
        }
    }
    println!("configured: {effective}");
    Ok(())
}

fn restore_drop_in(
    drop_in: &Path,
    backup: &Path,
    existing: Option<&[u8]>,
) -> Result<(), Box<dyn std::error::Error>> {
    match existing {
        Some(content) => atomic_write(drop_in, content)?,
        None => {
            let _ = fs::remove_file(drop_in);
        }
    }
    if !backup.exists() {
        let _ = fs::remove_file(backup);
    }
    Ok(())
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path.parent().ok_or("path has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o644))?;
    temporary.write_all(content)?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(path)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn atomic_install_replaces_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authorized_keys");
        install_file(&path, b"").unwrap();
        assert_eq!(fs::read(path).unwrap(), b"");
    }
}
