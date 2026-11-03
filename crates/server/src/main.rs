//! SSH Key Sync server and administrative command line.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    net::SocketAddr,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, chown},
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    sync::Arc,
};

use arc_swap::ArcSwap;
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path as AxumPath, Request, State as AxumState},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde::Serialize;
use ssh_key_sync_core::{
    Config, KeySetPayload, PROTOCOL_SCHEMA_VERSION, SignedEnvelope, encode_release_verifying_key,
    load_release_verifying_key, load_signing_key, load_signing_key_secure,
    release_verifying_key_fingerprint, sign_payload, sign_release_manifest, token_digest, unix_now,
    validate_token_digest, verify_release_manifest,
};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod config_edit;
mod state;
mod tui;
use state::{CreateEnrollmentError, State};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the HTTP server.
    Serve {
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Validate a server configuration.
    CheckConfig {
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Generate a token and its storable digest.
    GenerateToken,
    /// Generate raw Ed25519 signing and verification keys.
    GenerateKeys {
        /// Directory receiving signing.key and signing.pub.
        #[arg(long, default_value = ".")]
        output: PathBuf,
    },
    /// Generate a separate offline release-signing key pair.
    ReleaseKeygen {
        /// Directory receiving release.key and release.pub.
        #[arg(long, default_value = ".")]
        output: PathBuf,
    },
    /// Sign a release checksum manifest.
    ReleaseSign {
        /// Raw 32-byte Ed25519 release signing key.
        #[arg(long)]
        key: PathBuf,
        /// Checksum manifest to sign.
        #[arg(long)]
        manifest: PathBuf,
        /// Output signature file.
        #[arg(long)]
        output: PathBuf,
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
    /// Print the SHA-256 fingerprint of a release verification key.
    ReleaseFingerprint {
        /// Base64url-encoded release verification key.
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Manage enrollment requests.
    Enrollment {
        #[command(subcommand)]
        command: EnrollmentCommand,
    },
    /// Manage issued machine tokens.
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Manage key groups and CIDR rules.
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    /// Manage public key owners and group assignments.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Create an atomic snapshot of enrollment and token state.
    Backup {
        /// Directory receiving timestamped database snapshots.
        #[arg(long, default_value = "/var/lib/ssh-key-sync/backups")]
        output_directory: PathBuf,
        /// Number of matching snapshots to retain.
        #[arg(long, default_value_t = 14)]
        retain: usize,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Verify that a state snapshot is a compatible SQLite backup.
    BackupVerify {
        /// Snapshot to inspect.
        #[arg(long)]
        input: PathBuf,
    },
    /// Restore a state snapshot while the server service is stopped.
    BackupRestore {
        /// Snapshot to restore.
        #[arg(long)]
        input: PathBuf,
        /// Confirm the service is stopped and the snapshot has been reviewed.
        #[arg(long)]
        confirm: bool,
        /// Directory receiving a safety snapshot of the current state.
        #[arg(long, default_value = "/var/lib/ssh-key-sync/backups")]
        pre_restore_directory: PathBuf,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Open the local administration terminal UI.
    Tui {
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum EnrollmentCommand {
    /// List pending and decided requests.
    List {
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Show request details.
    Show {
        request_id: String,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Approve a request into a configured group.
    Approve {
        request_id: String,
        #[arg(long)]
        group: String,
        /// Approve despite an active identity conflict without retiring it.
        #[arg(long = "allow-identity-conflict", alias = "replace-existing")]
        allow_identity_conflict: bool,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Deny a request.
    Deny {
        request_id: String,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Hide a decided request while preserving its audit record.
    Hide {
        request_id: String,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Revoke the associated token and hide an old machine enrollment.
    Retire {
        request_id: String,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    /// List issued machine tokens.
    List {
        /// Only show tokens that are stale or have never connected.
        #[arg(long)]
        stale_only: bool,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Revoke a machine token.
    Revoke {
        token_id: String,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Hide a revoked token while preserving its audit record.
    Hide {
        token_id: String,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum GroupCommand {
    /// Add a group, optionally assigning existing key owners.
    Add {
        name: String,
        #[arg(long)]
        public: bool,
        /// Existing key owner to assign to the new group; repeat as needed.
        #[arg(long = "owner", value_name = "OWNER")]
        owners: Vec<String>,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Remove an unreferenced group.
    Remove {
        name: String,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Add a CIDR rule to a group.
    AddCidr {
        group: String,
        cidr: String,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Remove a CIDR rule from a group.
    RemoveCidr {
        group: String,
        cidr: String,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Explicitly enable or disable unauthenticated legacy XML-RPC for a group.
    SetLegacy {
        group: String,
        #[arg(action = clap::ArgAction::Set)]
        enabled: bool,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Add a public key and assign its owner to a group.
    Add {
        owner: String,
        group: String,
        key: String,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Remove a key by fingerprint.
    Remove {
        owner: String,
        fingerprint: String,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Assign or remove a key owner's group membership.
    Assign {
        owner: String,
        group: String,
        #[arg(long)]
        remove: bool,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// List keys and fingerprints.
    List {
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
}

#[derive(Clone)]
struct AppState {
    config: Arc<ArcSwap<Config>>,
    signing_key: Arc<SigningKey>,
    state: Arc<State>,
}

#[derive(Debug)]
struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = Json(ErrorBody { error: self.1 }).into_response();
        *response.status_mut() = self.0;
        response
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentRequest {
    name: String,
    hostname: String,
    local_addresses: Vec<String>,
    secret_digest: String,
    token_digest: String,
}

#[derive(Serialize)]
struct EnrollmentResponse {
    request_id: String,
    code: String,
    expires_at: u64,
    identity_conflict: bool,
}

#[derive(Serialize)]
struct EnrollmentStatus {
    request_id: String,
    status: String,
    group: Option<String>,
    expires_at: u64,
}

fn open_state(config: &Config) -> Result<State, Box<dyn std::error::Error>> {
    Ok(State::open(state_path(config))?)
}

fn state_path(config: &Config) -> &Path {
    Path::new(
        config
            .state_file
            .as_deref()
            .unwrap_or("/var/lib/ssh-key-sync/state.db"),
    )
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let log_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .with_ansi(false)
        .init();
    match Cli::parse().command {
        Command::CheckConfig { config } => {
            Config::load(config)?;
            println!("configuration is valid");
        }
        Command::GenerateToken => {
            let token = ssh_key_sync_core::new_token();
            println!("token={token}");
            println!("digest={}", token_digest(&token));
        }
        Command::GenerateKeys { output } => {
            std::fs::create_dir_all(&output)?;
            let signing = SigningKey::generate(&mut rand::rng());
            write_new_file(&output.join("signing.key"), &signing.to_bytes(), 0o600)?;
            write_new_file(
                &output.join("signing.pub"),
                &signing.verifying_key().to_bytes(),
                0o644,
            )?;
            println!("wrote signing.key and signing.pub to {}", output.display());
        }
        Command::ReleaseKeygen { output } => {
            std::fs::create_dir_all(&output)?;
            let signing = SigningKey::generate(&mut rand::rng());
            write_new_file(&output.join("release.key"), &signing.to_bytes(), 0o600)?;
            write_new_file(
                &output.join("release.pub"),
                encode_release_verifying_key(&signing.verifying_key()).as_bytes(),
                0o644,
            )?;
            println!("wrote release.key and release.pub to {}", output.display());
        }
        Command::ReleaseSign {
            key,
            manifest,
            output,
        } => {
            let key = load_signing_key(key)?;
            let manifest = std::fs::read(manifest)?;
            let signature = sign_release_manifest(&manifest, &key);
            std::fs::write(&output, format!("{signature}\n"))?;
            println!("wrote release signature to {}", output.display());
        }
        Command::ReleaseVerify {
            manifest,
            signature,
            public_key,
        } => {
            let manifest = std::fs::read(manifest)?;
            let signature = std::fs::read_to_string(signature)?;
            let key = load_release_verifying_key(public_key)?;
            verify_release_manifest(&manifest, &signature, &key)?;
            println!("release signature is valid");
        }
        Command::ReleaseFingerprint { public_key } => {
            let key = load_release_verifying_key(public_key)?;
            println!("{}", release_verifying_key_fingerprint(&key));
        }
        Command::Enrollment { command } => match command {
            EnrollmentCommand::List { config } => {
                let config = Config::load(config)?;
                for enrollment in open_state(&config)?.list_enrollments()? {
                    let id = sanitize_metadata(&enrollment.id, 128);
                    let code = sanitize_metadata(&enrollment.code, 16);
                    let status = sanitize_metadata(&enrollment.status, 16);
                    let name = sanitize_metadata(&enrollment.name, 128);
                    let hostname = sanitize_metadata(&enrollment.hostname, 255);
                    let source_ip = sanitize_metadata(&enrollment.source_ip, 64);
                    let addresses = sanitize_metadata(&enrollment.local_addresses, 4096);
                    let group =
                        sanitize_metadata(enrollment.group.as_deref().unwrap_or_default(), 128);
                    println!(
                        "{} {} {} {} host={} source={} addresses={} group={} expires={}",
                        id,
                        code,
                        status,
                        name,
                        hostname,
                        source_ip,
                        addresses,
                        group,
                        enrollment.expires_at
                    );
                }
            }
            EnrollmentCommand::Show { request_id, config } => {
                let config = Config::load(config)?;
                let state = open_state(&config)?;
                let enrollment = state
                    .enrollment_by_id(&request_id)?
                    .ok_or("request not found")?;
                let conflicts = state.enrollment_conflicts(&enrollment)?;
                let id = sanitize_metadata(&enrollment.id, 128);
                let code = sanitize_metadata(&enrollment.code, 16);
                let status = sanitize_metadata(&enrollment.status, 16);
                let name = sanitize_metadata(&enrollment.name, 128);
                let hostname = sanitize_metadata(&enrollment.hostname, 255);
                let source_ip = sanitize_metadata(&enrollment.source_ip, 64);
                let addresses = sanitize_metadata(&enrollment.local_addresses, 4096);
                let group = sanitize_metadata(enrollment.group.as_deref().unwrap_or_default(), 128);
                let conflicts = conflicts
                    .iter()
                    .map(|item| sanitize_metadata(&item.id, 128))
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "{} {} {} {} host={} source={} addresses={} group={} expires={} conflicts={}",
                    id,
                    code,
                    status,
                    name,
                    hostname,
                    source_ip,
                    addresses,
                    group,
                    enrollment.expires_at,
                    if conflicts.is_empty() {
                        "-".into()
                    } else {
                        conflicts
                    }
                );
            }
            EnrollmentCommand::Approve {
                request_id,
                group,
                allow_identity_conflict,
                config,
            } => {
                let config = Config::load(config)?;
                let Some(group_config) = config.groups.get(&group) else {
                    return Err(format!("unknown group: {group}").into());
                };
                let expires_at = group_config
                    .token_ttl_days
                    .map(|days| unix_now().saturating_add(days.saturating_mul(86_400)));
                let state = open_state(&config)?;
                let enrollment = state
                    .enrollment_by_id(&request_id)?
                    .ok_or("request not found")?;
                let conflicts = state.enrollment_conflicts(&enrollment)?;
                if !conflicts.is_empty() && !allow_identity_conflict {
                    let ids = conflicts
                        .iter()
                        .map(|item| item.id.as_str())
                        .collect::<Vec<_>>()
                        .join(",");
                    return Err(format!(
                        "active identity conflict: {ids}; verify the machine and use --allow-identity-conflict only if both identities must remain active"
                    )
                    .into());
                }
                if state.approve(&request_id, &group, expires_at)? {
                    println!("approved {request_id} into {group}");
                    if !conflicts.is_empty() {
                        println!(
                            "identity conflict acknowledged: {}; existing enrollments remain active",
                            conflicts.len()
                        );
                    }
                } else {
                    return Err("request is missing, expired, or already decided".into());
                }
            }
            EnrollmentCommand::Deny { request_id, config } => {
                let config = Config::load(config)?;
                if open_state(&config)?.deny(&request_id)? {
                    println!("denied {request_id}");
                } else {
                    return Err("request is missing or already decided".into());
                }
            }
            EnrollmentCommand::Hide { request_id, config } => {
                let config = Config::load(config)?;
                if open_state(&config)?.hide_enrollment(&request_id)? {
                    println!("hid {request_id}");
                } else {
                    return Err("request is missing, pending, or already hidden".into());
                }
            }
            EnrollmentCommand::Retire { request_id, config } => {
                let config = Config::load(config)?;
                if open_state(&config)?.retire_enrollment(&request_id)? {
                    println!("retired {request_id}");
                } else {
                    return Err("request is missing, pending, or already hidden".into());
                }
            }
        },
        Command::Token { command } => match command {
            TokenCommand::List { stale_only, config } => {
                let config = Config::load(config)?;
                let now = unix_now();
                for token in open_state(&config)?.list_tokens()? {
                    let check_in = token.check_in(now, config.stale_after_hours);
                    if stale_only && !check_in.needs_attention() {
                        continue;
                    }
                    let id = sanitize_metadata(&token.id, 128);
                    let group = sanitize_metadata(&token.group, 128);
                    let label = sanitize_metadata(&token.label, 255);
                    let source =
                        sanitize_metadata(token.last_source_ip.as_deref().unwrap_or("-"), 64);
                    let client =
                        sanitize_metadata(token.last_client_version.as_deref().unwrap_or("-"), 128);
                    println!(
                        "{} {} {} check_in={} age={}s expires={} last_used={} source={} client={}",
                        id,
                        group,
                        label,
                        check_in.label(),
                        now.saturating_sub(token.last_check_in_at()),
                        token
                            .expires_at
                            .map_or_else(|| "-".into(), |value| value.to_string()),
                        token
                            .last_used_at
                            .map_or_else(|| "-".into(), |value| value.to_string()),
                        source,
                        client,
                    );
                }
            }
            TokenCommand::Revoke { token_id, config } => {
                let config = Config::load(config)?;
                if open_state(&config)?.revoke_token(&token_id)? {
                    println!("revoked {token_id}");
                } else {
                    return Err("token is missing or already revoked".into());
                }
            }
            TokenCommand::Hide { token_id, config } => {
                let config = Config::load(config)?;
                if open_state(&config)?.hide_token(&token_id)? {
                    println!("hid {token_id}");
                } else {
                    return Err("token is missing, active, or already hidden".into());
                }
            }
        },
        Command::Group { command } => {
            use GroupCommand::{Add, AddCidr, Remove, RemoveCidr, SetLegacy};
            match command {
                Add {
                    name,
                    public,
                    owners,
                    config,
                } => {
                    config_edit::Editor::open(config)?
                        .add_group_with_owners(&name, public, &owners)?;
                    if owners.is_empty() {
                        eprintln!(
                            "warning: group {name} has no key owners; assign one with: ssh-key-sync-server key assign OWNER {name}"
                        );
                    }
                }
                Remove { name, config } => {
                    config_edit::Editor::open(config)?.remove_group(&name)?;
                }
                AddCidr {
                    group,
                    cidr,
                    config,
                } => {
                    config_edit::Editor::open(config)?.add_cidr(&group, &cidr)?;
                }
                RemoveCidr {
                    group,
                    cidr,
                    config,
                } => {
                    config_edit::Editor::open(config)?.remove_cidr(&group, &cidr)?;
                }
                SetLegacy {
                    group,
                    enabled,
                    config,
                } => {
                    config_edit::Editor::open(config)?.set_legacy_xmlrpc(&group, enabled)?;
                }
            }
            println!("configuration updated");
        }
        Command::Key { command } => {
            use KeyCommand::{Add, Assign, List, Remove};
            match command {
                Add {
                    owner,
                    group,
                    key,
                    config,
                } => {
                    config_edit::Editor::open(config)?.add_key(&owner, &group, &key)?;
                }
                Remove {
                    owner,
                    fingerprint,
                    config,
                } => {
                    config_edit::Editor::open(config)?.remove_key(&owner, &fingerprint)?;
                }
                Assign {
                    owner,
                    group,
                    remove,
                    config,
                } => {
                    config_edit::Editor::open(config)?.assign_key(&owner, &group, !remove)?;
                }
                List { config } => {
                    let config = Config::load(config)?;
                    for (owner, entry) in config.keys {
                        for key in entry.keys {
                            let fingerprint =
                                ssh_key_sync_core::parse_public_key(&key)?.fingerprint;
                            println!("{owner} {fingerprint} groups={}", entry.groups.join(","));
                        }
                    }
                    return Ok(());
                }
            }
            println!("configuration updated");
        }
        Command::Backup {
            output_directory,
            retain,
            config,
        } => {
            if retain == 0 {
                return Err("--retain must be at least 1".into());
            }
            let config = Config::load(config)?;
            let state = open_state(&config)?;
            std::fs::create_dir_all(&output_directory)?;
            let output = output_directory.join(format!("state-{}.db", unix_now()));
            let mut temporary = tempfile::NamedTempFile::new_in(&output_directory)?;
            temporary
                .as_file()
                .set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
            state.backup_to(temporary.path())?;
            temporary.as_file_mut().sync_all()?;
            temporary.persist(&output)?;
            prune_backups(&output_directory, retain)?;
            println!("{}", output.display());
        }
        Command::BackupVerify { input } => {
            State::verify_backup(&input)?;
            println!("backup is valid: {}", input.display());
        }
        Command::BackupRestore {
            input,
            confirm,
            pre_restore_directory,
            config,
        } => {
            if !confirm {
                return Err("--confirm is required for restore".into());
            }
            let config = Config::load(config)?;
            require_server_stopped()?;
            let pre_restore =
                restore_backup_database(&input, state_path(&config), &pre_restore_directory)?;
            if let Some(path) = pre_restore {
                println!("pre-restore backup: {}", path.display());
            }
            println!("restored {}", state_path(&config).display());
        }
        Command::Tui { config } => tui::run(config)?,
        Command::Serve { config } => run(config).await?,
    }
    Ok(())
}

fn prune_backups(
    directory: &std::path::Path,
    retain: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut backups = std::fs::read_dir(directory)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_file())
                && entry.file_name().to_str().is_some_and(|name| {
                    name.starts_with("state-")
                        && std::path::Path::new(name)
                            .extension()
                            .is_some_and(|extension| extension.eq_ignore_ascii_case("db"))
                })
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    backups.sort();
    backups.reverse();
    for path in backups.into_iter().skip(retain) {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn require_server_stopped() -> Result<(), Box<dyn std::error::Error>> {
    let status = ProcessCommand::new("systemctl")
        .args(["is-active", "--quiet", "ssh-key-sync-server.service"])
        .status()
        .map_err(|error| format!("could not verify the server service state: {error}"))?;
    if status.success() {
        return Err("stop ssh-key-sync-server.service before restoring state".into());
    }
    Ok(())
}

fn restore_backup_database(
    input: &Path,
    destination: &Path,
    pre_restore_directory: &Path,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    State::verify_backup(input)?;
    if let Ok(metadata) = fs::symlink_metadata(destination)
        && !metadata.file_type().is_file()
    {
        return Err("state destination must be a regular file".into());
    }

    let pre_restore = if destination.exists() {
        fs::create_dir_all(pre_restore_directory)?;
        let path = pre_restore_directory.join(format!(
            "state-before-restore-{}-{}.db",
            unix_now(),
            std::process::id()
        ));
        let current = State::open(destination)?;
        current.backup_to(&path)?;
        drop(current);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Some(path)
    } else {
        None
    };

    let parent = destination
        .parent()
        .ok_or("state destination has no parent directory")?;
    fs::create_dir_all(parent)?;
    let owner = fs::symlink_metadata(destination)
        .or_else(|_| fs::symlink_metadata(parent))?
        .uid();
    let group = fs::symlink_metadata(destination)
        .or_else(|_| fs::symlink_metadata(parent))?
        .gid();
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    let mut source = File::open(input)?;
    io::copy(&mut source, temporary.as_file_mut())?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    chown(temporary.path(), Some(owner), Some(group))?;
    temporary.as_file_mut().sync_all()?;

    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", destination.display()));
        if sidecar.exists() {
            fs::remove_file(sidecar)?;
        }
    }
    temporary.persist(destination)?;
    File::open(parent)?.sync_all()?;
    State::verify_backup(destination)?;
    Ok(pre_restore)
}

fn write_new_file(
    path: &Path,
    content: &[u8],
    mode: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(path)?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

async fn run(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(&path)?;
    let signing_key = load_signing_key_secure(&config.signing_key_file)?;
    let state = open_state(&config)?;
    let address: SocketAddr = config.listen.parse()?;
    let config = Arc::new(ArcSwap::from_pointee(config));
    let state = AppState {
        config: config.clone(),
        signing_key: Arc::new(signing_key),
        state: Arc::new(state),
    };
    let reload_path = path.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            match Config::load(&reload_path) {
                Ok(updated) => config.store(Arc::new(updated)),
                Err(error) => error!(%error, "configuration reload rejected"),
            }
        }
    });
    let app = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/keys/public", get(public_keys))
        .route("/v1/keys", get(private_keys))
        .route("/v1/signing-key", get(signing_key_handler))
        .route(
            "/v1/enrollments",
            post(create_enrollment).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route("/v1/enrollments/{id}", get(enrollment_status))
        .route(
            "/xmlrpc/",
            post(xmlrpc).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .with_state(state)
        .layer(ConcurrencyLimitLayer::new(64))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(15),
        ))
        .layer(middleware::from_fn(no_store));
    let listener = tokio::net::TcpListener::bind(address).await?;
    info!(%address, "server listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn health() -> &'static str {
    "ok\n"
}

async fn signing_key_handler(AxumState(state): AxumState<AppState>) -> Vec<u8> {
    state.signing_key.verifying_key().to_bytes().to_vec()
}

async fn create_enrollment(
    AxumState(state): AxumState<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<EnrollmentRequest>,
) -> Result<(StatusCode, Json<EnrollmentResponse>), ApiError> {
    let config = state.config.load();
    if !valid_label(&request.name, 128)
        || !valid_label(&request.hostname, 255)
        || request.local_addresses.len() > 32
        || !request
            .local_addresses
            .iter()
            .all(|address| valid_local_address(address))
        || validate_token_digest(&request.secret_digest).is_err()
        || validate_token_digest(&request.token_digest).is_err()
    {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid enrollment request",
        ));
    }
    let (request_id, code, expires_at) = state
        .state
        .create_enrollment(
            request.name.trim(),
            &request.hostname,
            &request.local_addresses,
            &client_ip(&headers, peer.ip(), config.require_forwarded_client_ip)?.to_string(),
            &request.secret_digest,
            &request.token_digest,
        )
        .map_err(|error| match error {
            CreateEnrollmentError::RateLimited => ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "enrollment rate limit exceeded",
            ),
            CreateEnrollmentError::QueueFull => {
                ApiError(StatusCode::SERVICE_UNAVAILABLE, "enrollment queue is full")
            }
            CreateEnrollmentError::Database(error) => {
                error!(%error, "enrollment state error");
                ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "unable to create enrollment",
                )
            }
        })?;
    let enrollment = state
        .state
        .enrollment_by_id(&request_id)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "state error"))?
        .ok_or(ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "enrollment state error",
        ))?;
    let identity_conflict = !state
        .state
        .enrollment_conflicts(&enrollment)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "state error"))?
        .is_empty();
    Ok((
        StatusCode::CREATED,
        Json(EnrollmentResponse {
            request_id,
            code,
            expires_at,
            identity_conflict,
        }),
    ))
}

async fn enrollment_status(
    AxumState(state): AxumState<AppState>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Json<EnrollmentStatus>, ApiError> {
    let secret = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError(
            StatusCode::UNAUTHORIZED,
            "missing enrollment secret",
        ))?;
    let enrollment = state
        .state
        .enrollment_for_secret(&id, secret)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "state error"))?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "enrollment not found"))?;
    Ok(Json(EnrollmentStatus {
        request_id: enrollment.id,
        status: enrollment.status,
        group: enrollment.group,
        expires_at: enrollment.expires_at,
    }))
}

fn nonce(headers: &HeaderMap) -> Result<String, ApiError> {
    let values = headers
        .get_all("x-request-nonce")
        .iter()
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid request nonce"));
    }
    let value = values[0]
        .to_str()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid request nonce"))?;
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid request nonce"));
    }
    Ok(value.to_owned())
}

fn signed(
    state: &AppState,
    config: &Config,
    group: &str,
    nonce: String,
) -> Result<Json<SignedEnvelope>, ApiError> {
    let now = unix_now();
    let keys = config
        .keys_for_group(group)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "configuration error"))?;
    let payload = KeySetPayload {
        schema: PROTOCOL_SCHEMA_VERSION,
        nonce,
        issued_at: now,
        expires_at: now + 300,
        group: group.to_owned(),
        keys,
    };
    sign_payload(&payload, &state.signing_key)
        .map(Json)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "signing failed"))
}

async fn public_keys(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
) -> Result<Json<SignedEnvelope>, ApiError> {
    let nonce = nonce(&headers)?;
    let config = state.config.load();
    signed(&state, &config, &config.default_group, nonce)
}

async fn private_keys(
    AxumState(state): AxumState<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<SignedEnvelope>, ApiError> {
    let nonce = nonce(&headers)?;
    let config = state.config.load();
    let source_ip = client_ip(&headers, peer.ip(), config.require_forwarded_client_ip)?;
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    let group = config
        .group_for_token(token)
        .map(str::to_owned)
        .or_else(|| {
            state
                .state
                .group_for_token(
                    token,
                    &source_ip.to_string(),
                    &sanitize_metadata(
                        headers
                            .get(axum::http::header::USER_AGENT)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("unknown"),
                        128,
                    ),
                )
                .ok()
                .flatten()
        });
    let group = group.ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid bearer token"))?;
    signed(&state, &config, &group, nonce)
}

async fn xmlrpc(
    AxumState(state): AxumState<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let valid_method = roxmltree::Document::parse(&body)
        .ok()
        .and_then(|document| {
            document
                .descendants()
                .find(|node| node.has_tag_name("methodName"))
                .and_then(|node| node.text())
                .map(|text| text == "ssh.getKeys")
        })
        .unwrap_or(false);
    if !valid_method {
        return xml_fault(404, "Unknown method");
    }
    let config = state.config.load();
    let Ok(source_ip) = client_ip(&headers, peer.ip(), config.require_forwarded_client_ip) else {
        return xml_fault(400, "Missing or invalid client address");
    };
    let Some(group) = config.group_for_ip(source_ip) else {
        info!(%source_ip, "legacy XML-RPC request without an enabled group");
        return xml_fault(403, "No legacy key group");
    };
    let keys = match config.keys_for_group(group) {
        Ok(keys) => keys,
        Err(error) => {
            error!(%error, "legacy key selection failed");
            return xml_fault(500, "Server error");
        }
    };
    info!(
        group,
        %source_ip,
        key_count = keys.len(),
        "legacy XML-RPC key request"
    );
    let mut text = keys
        .into_iter()
        .map(|key| key.authorized_keys)
        .collect::<Vec<_>>()
        .join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    (
        [(CONTENT_TYPE, "text/xml; charset=utf-8")],
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><methodResponse><params><param><value><string>{}</string></value></param></params></methodResponse>",
            xml_escape(&text)
        ),
    )
        .into_response()
}

fn xml_fault(code: u16, message: &str) -> Response {
    (
        [(CONTENT_TYPE, "text/xml; charset=utf-8")],
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><methodResponse><fault><value><struct><member><name>faultCode</name><value><int>{code}</int></value></member><member><name>faultString</name><value><string>{}</string></value></member></struct></value></fault></methodResponse>",
            xml_escape(message)
        ),
    )
        .into_response()
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn client_ip(
    headers: &HeaderMap,
    peer: std::net::IpAddr,
    require_forwarded: bool,
) -> Result<std::net::IpAddr, ApiError> {
    if !require_forwarded || !peer.is_loopback() {
        return Ok(peer);
    }
    let values = headers.get_all("x-real-ip").iter().collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "missing or invalid client address",
        ));
    }
    let value = values[0]
        .to_str()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid client address"))?;
    if value.trim() != value {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid client address"));
    }
    value
        .parse()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid client address"))
}

fn valid_label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn valid_local_address(value: &str) -> bool {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return false;
    }
    let Some((interface, address)) = value.split_once(':') else {
        return false;
    };
    valid_label(interface, 64) && address.parse::<std::net::IpAddr>().is_ok()
}

pub(crate) fn sanitize_metadata(value: &str, maximum: usize) -> String {
    let cleaned = value
        .chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .take(maximum)
        .collect::<String>();
    if cleaned.is_empty() {
        "unknown".into()
    } else {
        cleaned
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_fields_reject_control_and_ambiguous_values() {
        assert!(valid_label("panel.example.net", 255));
        assert!(!valid_label("panel\n.example", 255));
        assert!(!valid_label("", 255));
        assert!(valid_local_address("eth0:192.0.2.10"));
        assert!(valid_local_address("eth0:2001:db8::10"));
        assert!(!valid_local_address("eth0:not-an-ip"));
        assert!(!valid_local_address("eth0:192.0.2.10\n"));
    }

    #[test]
    fn forwarded_address_requirement_fails_closed() {
        let loopback = "127.0.0.1".parse().unwrap();
        assert!(client_ip(&HeaderMap::new(), loopback, true).is_err());
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("192.0.2.10"));
        assert_eq!(
            client_ip(&headers, loopback, true).unwrap().to_string(),
            "192.0.2.10"
        );
        headers.insert("x-real-ip", HeaderValue::from_static("192.0.2.10:443"));
        assert!(client_ip(&headers, loopback, true).is_err());
    }

    #[test]
    fn metadata_controls_are_replaced() {
        assert_eq!(sanitize_metadata("safe\x1b[2Jname", 64), "safe?[2Jname");
        assert_eq!(sanitize_metadata("\x00", 64), "?");
    }

    #[test]
    fn legacy_group_toggle_requires_an_explicit_value() {
        let cli =
            Cli::try_parse_from(["ssh-key-sync-server", "group", "set-legacy", "oeg", "true"])
                .unwrap();
        assert!(matches!(
            cli.command,
            Command::Group {
                command: GroupCommand::SetLegacy { enabled: true, .. }
            }
        ));
        assert!(
            Cli::try_parse_from(["ssh-key-sync-server", "group", "set-legacy", "oeg"]).is_err()
        );
    }

    #[test]
    fn token_list_accepts_stale_only_filter() {
        let cli =
            Cli::try_parse_from(["ssh-key-sync-server", "token", "list", "--stale-only"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Token {
                command: TokenCommand::List {
                    stale_only: true,
                    ..
                }
            }
        ));
    }

    #[test]
    fn restore_backup_replaces_state_and_keeps_a_pre_restore_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("source.db");
        let source = State::open(&source_path).unwrap();
        source
            .create_enrollment(
                "restored-host",
                "restored-host",
                &[],
                "192.0.2.10",
                &token_digest("restore-secret"),
                &token_digest("restore-token"),
            )
            .unwrap();
        let snapshot = directory.path().join("snapshot.db");
        source.backup_to(&snapshot).unwrap();
        drop(source);

        let destination = directory.path().join("state.db");
        let current = State::open(&destination).unwrap();
        current
            .create_enrollment(
                "current-host",
                "current-host",
                &[],
                "192.0.2.20",
                &token_digest("current-secret"),
                &token_digest("current-token"),
            )
            .unwrap();
        drop(current);

        let pre_restore_directory = directory.path().join("pre-restore");
        let pre_restore = restore_backup_database(&snapshot, &destination, &pre_restore_directory)
            .unwrap()
            .unwrap();
        let restored = State::open(&destination).unwrap();
        let enrollments = restored.list_enrollments().unwrap();
        assert_eq!(enrollments.len(), 1);
        assert_eq!(enrollments[0].name, "restored-host");
        drop(restored);

        let previous = State::open(&pre_restore).unwrap();
        let enrollments = previous.list_enrollments().unwrap();
        assert_eq!(enrollments.len(), 1);
        assert_eq!(enrollments[0].name, "current-host");
        assert_eq!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
