//! SSH Key Sync portable client.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    net::IpAddr,
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
use url::{Host, Url};

const CLIENT_USER_AGENT: &str = concat!("ssh-key-sync-client/", env!("CARGO_PKG_VERSION"));
const CLOCK_WARNING_SECONDS: u64 = 60;

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
    /// Quarantine legacy `.ssh/authorized_keys` files after migration.
    RetireLegacyAuthorizedKeys {
        /// Apply the validated file renames.
        #[arg(long)]
        apply: bool,
        /// SSH directory containing the legacy authorization files.
        #[arg(long, default_value = "/root/.ssh")]
        ssh_directory: PathBuf,
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
    #[serde(default = "default_true")]
    require_effective_sshd: bool,
    #[serde(default)]
    token_file: Option<PathBuf>,
    #[serde(default)]
    allow_empty: bool,
}

fn default_true() -> bool {
    true
}

fn is_enrollment_address(address: IpAddr) -> bool {
    !address.is_loopback() && !matches!(address, IpAddr::V4(address) if address.is_link_local())
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
    #[serde(default)]
    identity_conflict: bool,
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
        validate_server_url(&config.server_url)?;
        Ok(config)
    }
}

fn validate_server_url(value: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = Url::parse(value)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("server_url must not contain credentials, a query, or a fragment".into());
    }
    match (url.scheme(), url.host()) {
        ("https", Some(_)) => Ok(()),
        ("http", Some(Host::Ipv4(address))) if address.is_loopback() => Ok(()),
        ("http", Some(Host::Ipv6(address))) if address.is_loopback() => Ok(()),
        _ => Err("server_url must use HTTPS except for exact loopback HTTP".into()),
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
        Command::RetireLegacyAuthorizedKeys {
            apply,
            ssh_directory,
        } => {
            retire_legacy_authorized_keys(&cli.config, apply, &ssh_directory)?;
        }
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

fn enable_sync_schedule(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if Path::new("/run/systemd/system").is_dir()
        && ProcessCommand::new("systemctl")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    {
        let status = ProcessCommand::new("systemctl")
            .args(["enable", "--now", "ssh-key-sync-client.timer"])
            .status()?;
        if !status.success() {
            return Err("failed to enable ssh-key-sync-client.timer".into());
        }
        println!("enabled ssh-key-sync-client.timer");
    } else {
        install_cron(config_path, false)?;
    }
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
        .filter(|interface| is_enrollment_address(interface.addr.ip()))
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
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v1/enrollments",
            config.server_url.trim_end_matches('/')
        ))
        .header(reqwest::header::USER_AGENT, CLIENT_USER_AGENT)
        .json(&body)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "no response body".into());
        return Err(format!("enrollment request failed ({status}): {body}").into());
    }
    let created: EnrollmentCreated = response.json().await?;
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
    if created.identity_conflict {
        println!(
            "warning: this identity conflicts with an active enrollment; verify you are enrolled from the intended machine"
        );
    }
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
    let client = reqwest::Client::builder()
        .user_agent(CLIENT_USER_AGENT)
        .build()?;
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
                let group = state.group.unwrap_or_default();
                println!(
                    "approved for group {}; token installed at {}",
                    group,
                    pending.token_file.display()
                );
                sync(config_path, false).await?;
                enable_sync_schedule(config_path)?;
                fs::remove_file(&pending_path)?;
                println!("enrollment complete: synchronization verified and schedule enabled");
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
    if config.require_effective_sshd {
        let managed = config
            .authorized_keys_file
            .to_str()
            .ok_or("managed authorized_keys path is not UTF-8")?;
        let effective = effective_authorized_keys_file()?;
        if !authorized_keys_path_is_effective(managed, &effective) {
            return Err(format!(
                "managed authorized_keys path is not effective in sshd: {managed}; effective: {effective}; run: ssh-key-sync-client --config {} configure-sshd --apply",
                config_path.display()
            )
            .into());
        }
    }
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
        .user_agent(CLIENT_USER_AGENT)
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
    let verified_at = unix_now();
    let payload = verify_envelope(&envelope, &verifying_key, &nonce, verified_at)?;
    let clock_difference = payload.issued_at.abs_diff(verified_at);
    if clock_difference > CLOCK_WARNING_SECONDS {
        eprintln!(
            "warning: client clock differs from the server by {clock_difference} seconds; configure NTP or systemd-timesyncd"
        );
    }
    if let Some(warning) = time_synchronization_warning() {
        eprintln!("warning: {warning}");
    }
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
    let runtime_directory = Path::new("/run/sshd");
    if !runtime_directory.exists() {
        fs::create_dir(runtime_directory)?;
        fs::set_permissions(runtime_directory, fs::Permissions::from_mode(0o755))?;
    }
    let contextual = ProcessCommand::new("sshd")
        .args(["-T", "-C", "user=root,host=localhost,addr=127.0.0.1"])
        .output()?;
    let output = if contextual.status.success() {
        contextual
    } else {
        let fallback = ProcessCommand::new("sshd").arg("-T").output()?;
        if fallback.status.success() {
            fallback
        } else {
            return Err(format!(
                "sshd -T failed: {}; fallback sshd -T failed: {}",
                String::from_utf8_lossy(&contextual.stderr),
                String::from_utf8_lossy(&fallback.stderr)
            )
            .into());
        }
    };
    parse_authorized_keys_file(&String::from_utf8(output.stdout)?)
}

fn parse_authorized_keys_file(config: &str) -> Result<String, Box<dyn std::error::Error>> {
    let files = config
        .lines()
        .filter_map(|line| {
            let (directive, value) = line.split_once(char::is_whitespace)?;
            matches!(
                directive.to_ascii_lowercase().as_str(),
                "authorizedkeysfile" | "authorizedkeysfile2"
            )
            .then(|| value.trim())
        })
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if files.is_empty() {
        return Err("sshd did not report authorizedkeysfile".into());
    }
    Ok(files.join(" "))
}

fn authorized_keys_path_is_effective(managed: &str, effective: &str) -> bool {
    effective.split_whitespace().any(|path| path == managed)
}

fn time_synchronization_warning() -> Option<&'static str> {
    let output = ProcessCommand::new("timedatectl")
        .args(["show", "--property=NTPSynchronized", "--value"])
        .output()
        .ok()?;
    if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "no" {
        Some("system time is not synchronized; configure NTP or systemd-timesyncd")
    } else {
        None
    }
}

fn retire_legacy_authorized_keys(
    config_path: &Path,
    apply: bool,
    ssh_directory: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::load(config_path)?;
    let managed = config
        .authorized_keys_file
        .to_str()
        .ok_or("managed authorized_keys path is not UTF-8")?;
    let effective = effective_authorized_keys_file()?;
    if !authorized_keys_path_is_effective(managed, &effective) {
        return Err(format!(
            "managed authorized_keys path is not effective in sshd: {managed}; effective: {effective}"
        )
        .into());
    }
    let managed_keys = validate_managed_authorized_keys(&config.authorized_keys_file)?;
    println!("managed file is effective with {managed_keys} key(s): {managed}");
    quarantine_legacy_authorized_keys_files(&config.authorized_keys_file, ssh_directory, apply)?;
    if !apply {
        println!("dry run: use --apply to quarantine the listed files");
    }
    Ok(())
}

fn validate_managed_authorized_keys(path: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let mut count = 0;
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        parse_public_key(line)?;
        count += 1;
    }
    if count == 0 {
        return Err("managed authorized_keys file is empty".into());
    }
    Ok(count)
}

fn quarantine_legacy_authorized_keys_files(
    managed: &Path,
    ssh_directory: &Path,
    apply: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let candidates = ["authorized_keys", "authorized_keys2"]
        .into_iter()
        .map(|name| ssh_directory.join(name))
        .collect::<Vec<_>>();
    let mut existing = Vec::new();
    for path in candidates {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "refusing non-regular authorization file: {}",
                path.display()
            )
            .into());
        }
        if path == managed {
            return Err("refusing to quarantine the configured managed authorization file".into());
        }
        existing.push(path);
    }
    if existing.is_empty() {
        println!(
            "no legacy authorization files found in {}",
            ssh_directory.display()
        );
        return Ok(());
    }

    for path in existing {
        let backup = legacy_backup_path(&path)?;
        if apply {
            fs::rename(&path, &backup)?;
            println!("quarantined {} -> {}", path.display(), backup.display());
        } else {
            println!(
                "would quarantine {} -> {}",
                path.display(),
                backup.display()
            );
        }
    }
    Ok(())
}

fn legacy_backup_path(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("authorized_keys");
    let timestamp = unix_now();
    for suffix in 0..1_000 {
        let backup_name = if suffix == 0 {
            format!("{filename}.before-ssh-key-sync-{timestamp}")
        } else {
            format!("{filename}.before-ssh-key-sync-{timestamp}-{suffix}")
        };
        let candidate = path.with_file_name(backup_name);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err("cannot allocate a unique legacy authorized_keys backup name".into())
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
    if authorized_keys_path_is_effective(managed, &current) {
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
    if !authorized_keys_path_is_effective(managed, &effective) {
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
    if !authorized_keys_path_is_effective(managed, &effective) {
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

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti test";

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

    #[test]
    fn server_url_allows_only_exact_loopback_http() {
        assert!(validate_server_url("https://keys.example.net").is_ok());
        assert!(validate_server_url("http://127.0.0.1:18080").is_ok());
        assert!(validate_server_url("http://[::1]:18080").is_ok());
        assert!(validate_server_url("http://127.0.0.1.example").is_err());
        assert!(validate_server_url("http://127.0.0.1@example.com").is_err());
        assert!(validate_server_url("https://user@keys.example.net").is_err());
        assert!(validate_server_url("https://keys.example.net?token=secret").is_err());
    }

    #[test]
    fn enrollment_ignores_loopback_and_ipv4_link_local_addresses() {
        assert!(!is_enrollment_address("127.0.0.1".parse().unwrap()));
        assert!(!is_enrollment_address("::1".parse().unwrap()));
        assert!(!is_enrollment_address("169.254.7.113".parse().unwrap()));
        assert!(is_enrollment_address("172.29.56.1".parse().unwrap()));
        assert!(is_enrollment_address("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn detects_whether_the_managed_path_is_effective() {
        assert!(authorized_keys_path_is_effective(
            "/etc/ssh/authorized_keys.d/root",
            ".ssh/authorized_keys /etc/ssh/authorized_keys.d/root"
        ));
        assert!(!authorized_keys_path_is_effective(
            "/etc/ssh/authorized_keys.d/root",
            ".ssh/authorized_keys .ssh/authorized_keys2"
        ));
    }

    #[test]
    fn parses_legacy_primary_and_secondary_authorized_keys_files() {
        let config = "\
port 22
authorizedkeysfile .ssh/authorized_keys
authorizedkeysfile2 /etc/ssh/authorized_keys.d/root
";
        assert_eq!(
            parse_authorized_keys_file(config).unwrap(),
            ".ssh/authorized_keys /etc/ssh/authorized_keys.d/root"
        );
    }

    #[test]
    fn quarantines_legacy_authorized_key_files_after_validation() {
        let directory = tempfile::tempdir().unwrap();
        let managed = directory.path().join("managed");
        fs::write(&managed, format!("{KEY}\n")).unwrap();
        let ssh_directory = directory.path().join("dot-ssh");
        fs::create_dir(&ssh_directory).unwrap();
        let primary = ssh_directory.join("authorized_keys");
        let secondary = ssh_directory.join("authorized_keys2");
        fs::write(&primary, format!("{KEY}\n")).unwrap();
        fs::write(&secondary, format!("{KEY}\n")).unwrap();

        quarantine_legacy_authorized_keys_files(&managed, &ssh_directory, false).unwrap();
        assert!(primary.exists());
        assert!(secondary.exists());

        quarantine_legacy_authorized_keys_files(&managed, &ssh_directory, true).unwrap();
        assert!(!primary.exists());
        assert!(!secondary.exists());
        assert_eq!(
            fs::read_dir(&ssh_directory).unwrap().count(),
            2,
            "both files should remain as non-active backups"
        );
    }

    #[test]
    fn refuses_to_quarantine_the_managed_authorized_keys_file() {
        let directory = tempfile::tempdir().unwrap();
        let ssh_directory = directory.path().join("dot-ssh");
        fs::create_dir(&ssh_directory).unwrap();
        let managed = ssh_directory.join("authorized_keys");
        fs::write(&managed, format!("{KEY}\n")).unwrap();
        assert!(quarantine_legacy_authorized_keys_files(&managed, &ssh_directory, true).is_err());
        assert!(managed.exists());
    }

    #[test]
    fn legacy_backup_names_do_not_overwrite_existing_files() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("authorized_keys");
        let first = legacy_backup_path(&source).unwrap();
        fs::write(&first, b"existing backup").unwrap();
        let second = legacy_backup_path(&source).unwrap();
        assert_ne!(first, second);
        assert_eq!(fs::read(first).unwrap(), b"existing backup");
    }

    #[test]
    fn user_agent_identifies_the_client_version() {
        assert_eq!(
            CLIENT_USER_AGENT,
            format!("ssh-key-sync-client/{}", env!("CARGO_PKG_VERSION"))
        );
    }
}
