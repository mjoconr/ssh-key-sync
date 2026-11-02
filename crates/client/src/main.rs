//! SSH Key Sync portable client.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    time::Duration,
};

use clap::{Parser, Subcommand};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use ssh_key_sync_core::{
    SignedEnvelope, load_verifying_key, new_nonce, new_token, parse_public_key, token_digest,
    unix_now, verify_envelope, verify_release_manifest,
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
    /// Request approval for a private-group machine token.
    Enroll {
        /// Human-readable machine name shown to the administrator.
        #[arg(long)]
        name: String,
    },
    /// Check or wait for enrollment approval.
    EnrollmentStatus {
        /// Poll until approved, denied, or expired.
        #[arg(long)]
        wait: bool,
    },
    /// Install or replace the root cron synchronization entry.
    InstallCron {
        /// Show the resulting crontab without installing it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Verify a signed release checksum manifest.
    ReleaseVerify {
        /// Checksum manifest to verify.
        #[arg(long)]
        manifest: PathBuf,
        /// Detached release signature.
        #[arg(long)]
        signature: PathBuf,
        /// Base64url-encoded release verification key.
        #[arg(long)]
        public_key: PathBuf,
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

#[derive(Debug, Serialize, Deserialize)]
struct PendingEnrollment {
    request_id: String,
    secret: String,
    token: String,
    token_file: PathBuf,
}

#[derive(Debug, Serialize)]
struct EnrollmentRequest<'a> {
    name: &'a str,
    hostname: &'a str,
    local_addresses: Vec<String>,
    secret_digest: String,
    token_digest: String,
}

#[derive(Debug, Deserialize)]
struct EnrollmentCreated {
    request_id: String,
    code: String,
    expires_at: u64,
}

#[derive(Debug, Deserialize)]
struct EnrollmentState {
    status: String,
    group: Option<String>,
    expires_at: u64,
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
        Command::Enroll { name } => enroll(&cli.config, &name).await?,
        Command::EnrollmentStatus { wait } => enrollment_status(&cli.config, wait).await?,
        Command::InstallCron { dry_run } => install_cron(&cli.config, dry_run)?,
        Command::ReleaseVerify {
            manifest,
            signature,
            public_key,
        } => {
            let manifest = fs::read(manifest)?;
            let signature = fs::read_to_string(signature)?;
            let key = ssh_key_sync_core::load_release_verifying_key(public_key)?;
            verify_release_manifest(&manifest, &signature, &key)?;
            println!("release signature is valid");
        }
    }
    Ok(())
}

fn install_cron(config_path: &Path, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    let existing = ProcessCommand::new("crontab")
        .arg("-l")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
    let minute = (unix_now() / 60) % 60;
    let command = format!(
        "{minute} */2 * * * /usr/local/bin/ssh-key-sync-client --config {} sync >/dev/null 2>&1",
        config_path.display()
    );
    let mut lines = existing
        .lines()
        .filter(|line| !line.contains("ssh-key-sync-client"))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    lines.push(command.clone());
    let rendered = format!("{}\n", lines.join("\n"));
    if dry_run {
        print!("{rendered}");
        return Ok(());
    }
    if !existing.is_empty() {
        atomic_write_mode(
            Path::new("/root/crontab.before-ssh-key-sync"),
            existing.as_bytes(),
            0o600,
        )?;
    }
    let mut child = ProcessCommand::new("crontab")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("cannot open crontab stdin")?
        .write_all(rendered.as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        return Err("crontab installation failed".into());
    }
    println!("Installed cron entry: {command}");
    Ok(())
}

async fn enroll(config_path: &Path, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::load(config_path)?;
    let token_file = config
        .token_file
        .clone()
        .ok_or("enrollment requires token_file in the client configuration")?;
    let secret = new_token();
    let token = new_token();
    let local_addresses = if_addrs::get_if_addrs()?
        .into_iter()
        .filter(|interface| !interface.is_loopback())
        .take(32)
        .map(|interface| format!("{}:{}", interface.name, interface.addr.ip()))
        .collect();
    let hostname = fs::read_to_string("/etc/hostname")
        .map(|value| value.trim().to_owned())
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".into());
    let body = EnrollmentRequest {
        name,
        hostname: &hostname,
        local_addresses,
        secret_digest: token_digest(&secret),
        token_digest: token_digest(&token),
    };
    let created: EnrollmentCreated = reqwest::Client::new()
        .post(format!(
            "{}/v1/enrollments",
            config.server_url.trim_end_matches('/')
        ))
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let pending = PendingEnrollment {
        request_id: created.request_id.clone(),
        secret,
        token,
        token_file,
    };
    atomic_write_mode(
        &config_path.with_file_name("pending-enrollment.json"),
        serde_json::to_string_pretty(&pending)?.as_bytes(),
        0o600,
    )?;
    println!("request: {}", created.request_id);
    println!("code:    {}", created.code);
    println!("expires: {}", created.expires_at);
    println!("Waiting for administrator approval.");
    Ok(())
}

async fn enrollment_status(
    config_path: &Path,
    wait: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::load(config_path)?;
    let pending_path = config_path.with_file_name("pending-enrollment.json");
    let pending: PendingEnrollment = serde_json::from_str(&fs::read_to_string(&pending_path)?)?;
    let client = reqwest::Client::new();
    loop {
        let state: EnrollmentState = client
            .get(format!(
                "{}/v1/enrollments/{}",
                config.server_url.trim_end_matches('/'),
                pending.request_id
            ))
            .bearer_auth(&pending.secret)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        match state.status.as_str() {
            "approved" => {
                atomic_write_mode(
                    &pending.token_file,
                    format!("{}\n", pending.token).as_bytes(),
                    0o600,
                )?;
                println!(
                    "approved for group {}; token installed at {}",
                    state.group.unwrap_or_default(),
                    pending.token_file.display()
                );
                return Ok(());
            }
            "denied" => return Err("enrollment was denied".into()),
            _ if unix_now() > state.expires_at => return Err("enrollment expired".into()),
            _ if wait => tokio::time::sleep(Duration::from_secs(5)).await,
            _ => {
                println!("status: pending");
                return Ok(());
            }
        }
    }
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
        println!("drop-in is not supported; updating /etc/ssh/sshd_config");
        configure_main_sshd(&desired, managed, no_reload)?;
        return Ok(());
    }
    if !no_reload {
        if let Err(error) = reload_sshd() {
            restore_drop_in(drop_in, &backup, existing.as_deref())?;
            return Err(error);
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

fn configure_main_sshd(
    directive: &str,
    managed: &str,
    no_reload: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new("/etc/ssh/sshd_config");
    let original = fs::read_to_string(path)?;
    let updated = update_sshd_config(&original, directive);
    let backup = path.with_extension("before-ssh-key-sync");
    fs::write(&backup, &original)?;
    atomic_write(path, updated.as_bytes())?;
    if !ProcessCommand::new("sshd").arg("-t").status()?.success() {
        atomic_write(path, original.as_bytes())?;
        return Err("sshd rejected the managed configuration; original restored".into());
    }
    let effective = effective_authorized_keys_file()?;
    if !effective.split_whitespace().any(|file| file == managed) {
        atomic_write(path, original.as_bytes())?;
        return Err("managed path was not effective; original restored".into());
    }
    if !no_reload {
        reload_sshd().inspect_err(|_error| {
            let _ = atomic_write(path, original.as_bytes());
        })?;
    }
    println!("configured via {}: {effective}", path.display());
    println!("backup: {}", backup.display());
    Ok(())
}

fn update_sshd_config(original: &str, directive: &str) -> String {
    const BEGIN: &str = "# BEGIN ssh-key-sync";
    const END: &str = "# END ssh-key-sync";
    let mut lines = Vec::new();
    let mut inside_block = false;
    for line in original.lines() {
        if line.trim() == BEGIN {
            inside_block = true;
            continue;
        }
        if line.trim() == END {
            inside_block = false;
            continue;
        }
        if !inside_block {
            lines.push(line.to_owned());
        }
    }
    let block = [
        BEGIN.to_owned(),
        directive.trim().to_owned(),
        END.to_owned(),
    ];
    let insert_at = lines
        .iter()
        .position(|line| line.trim_start().to_ascii_lowercase().starts_with("match "))
        .unwrap_or(lines.len());
    let existing_directive = lines[..insert_at].iter().position(|line| {
        let trimmed = line.trim_start().to_ascii_lowercase();
        !trimmed.starts_with('#') && trimmed.split_whitespace().next() == Some("authorizedkeysfile")
    });
    if let Some(index) = existing_directive {
        lines.splice(index..=index, block);
    } else {
        lines.splice(insert_at..insert_at, block);
    }
    let mut output = lines.join("\n");
    output.push('\n');
    output
}

fn reload_sshd() -> Result<(), Box<dyn std::error::Error>> {
    let attempts: &[(&str, &[&str])] = &[
        ("systemctl", &["reload", "ssh.service"]),
        ("systemctl", &["reload", "sshd.service"]),
        ("service", &["ssh", "reload"]),
        ("service", &["sshd", "reload"]),
        ("/etc/init.d/ssh", &["reload"]),
        ("/etc/init.d/sshd", &["reload"]),
        ("/etc/init.d/ssh", &["restart"]),
        ("/etc/init.d/sshd", &["restart"]),
    ];
    for (program, arguments) in attempts {
        if ProcessCommand::new(program)
            .args(*arguments)
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(());
        }
    }
    Err("SSH service reload failed; previous configuration restored".into())
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    atomic_write_mode(path, content, 0o644)
}

fn atomic_write_mode(
    path: &Path,
    content: &[u8],
    mode: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path.parent().ok_or("path has no parent")?;
    let temp_path = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or("path has no filename")?,
        std::process::id()
    ));
    let mut temporary = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)?;
    temporary.set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(content)?;
    temporary.sync_all()?;
    drop(temporary);
    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(error.into());
    }
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

    #[test]
    fn inserts_managed_line_before_match_blocks() {
        let original = "Port 22\nMatch User test\n  PasswordAuthentication no\n";
        let updated = update_sshd_config(
            original,
            "AuthorizedKeysFile .ssh/authorized_keys /managed/root",
        );
        assert!(updated.contains(
            "# BEGIN ssh-key-sync\nAuthorizedKeysFile .ssh/authorized_keys /managed/root"
        ));
        assert!(updated.find("ssh-key-sync").unwrap() < updated.find("Match User").unwrap());
    }

    #[test]
    fn replaces_tab_separated_authorized_keys_directive() {
        let original = "Port 22\nAuthorizedKeysFile\t.ssh/authorized_keys\n";
        let updated = update_sshd_config(
            original,
            "AuthorizedKeysFile .ssh/authorized_keys /managed/root",
        );
        assert!(updated.contains("AuthorizedKeysFile .ssh/authorized_keys /managed/root"));
        assert!(!updated.contains("AuthorizedKeysFile\t.ssh/authorized_keys"));
        assert_eq!(updated.matches("AuthorizedKeysFile").count(), 1);
    }

    #[test]
    fn atomic_write_replaces_existing_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        fs::write(&path, b"old").unwrap();
        atomic_write_mode(&path, b"new\n", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new\n");
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
