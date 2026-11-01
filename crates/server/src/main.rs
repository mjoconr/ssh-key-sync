//! SSH Key Sync server and administrative command line.

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path as AxumPath, State as AxumState},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::Deserialize;
use serde::Serialize;
use ssh_key_sync_core::{
    Config, KeySetPayload, PROTOCOL_SCHEMA_VERSION, SignedEnvelope, load_signing_key, sign_payload,
    token_digest, unix_now,
};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod state;
use state::State;

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
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Deny a request.
    Deny {
        request_id: String,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    /// List issued machine tokens.
    List {
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
    /// Revoke a machine token.
    Revoke {
        token_id: String,
        #[arg(long, default_value = "/etc/ssh-key-sync/server.toml")]
        config: PathBuf,
    },
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
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
}

#[derive(Serialize)]
struct EnrollmentStatus {
    request_id: String,
    status: String,
    group: Option<String>,
    expires_at: u64,
}

fn open_state(config: &Config) -> Result<State, Box<dyn std::error::Error>> {
    let path = config
        .state_file
        .as_deref()
        .unwrap_or("/var/lib/ssh-key-sync/state.db");
    Ok(State::open(path)?)
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
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
            let signing = SigningKey::generate(&mut OsRng);
            std::fs::write(output.join("signing.key"), signing.to_bytes())?;
            std::fs::write(
                output.join("signing.pub"),
                signing.verifying_key().to_bytes(),
            )?;
            println!("wrote signing.key and signing.pub to {}", output.display());
        }
        Command::Enrollment { command } => match command {
            EnrollmentCommand::List { config } => {
                let config = Config::load(config)?;
                for enrollment in open_state(&config)?.list_enrollments()? {
                    println!(
                        "{} {} {} {} host={} source={} addresses={} group={} expires={}",
                        enrollment.id,
                        enrollment.code,
                        enrollment.status,
                        enrollment.name,
                        enrollment.hostname,
                        enrollment.source_ip,
                        enrollment.local_addresses,
                        enrollment.group.unwrap_or_default(),
                        enrollment.expires_at
                    );
                }
            }
            EnrollmentCommand::Show { request_id, config } => {
                let config = Config::load(config)?;
                let enrollment = open_state(&config)?
                    .enrollment_by_id(&request_id)?
                    .ok_or("request not found")?;
                println!(
                    "{} {} {} {} host={} source={} addresses={} group={} expires={}",
                    enrollment.id,
                    enrollment.code,
                    enrollment.status,
                    enrollment.name,
                    enrollment.hostname,
                    enrollment.source_ip,
                    enrollment.local_addresses,
                    enrollment.group.unwrap_or_default(),
                    enrollment.expires_at
                );
            }
            EnrollmentCommand::Approve {
                request_id,
                group,
                config,
            } => {
                let config = Config::load(config)?;
                if !config.groups.contains_key(&group) {
                    return Err(format!("unknown group: {group}").into());
                }
                if open_state(&config)?.approve(&request_id, &group)? {
                    println!("approved {request_id} into {group}");
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
        },
        Command::Token { command } => match command {
            TokenCommand::List { config } => {
                let config = Config::load(config)?;
                for token in open_state(&config)?.list_tokens()? {
                    println!(
                        "{} {} {} {}",
                        token.id,
                        token.group,
                        token.label,
                        if token.revoked_at.is_some() {
                            "revoked"
                        } else {
                            "active"
                        }
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
        },
        Command::Serve { config } => run(config).await?,
    }
    Ok(())
}

async fn run(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(path)?;
    let signing_key = load_signing_key(&config.signing_key_file)?;
    let state = open_state(&config)?;
    let address: SocketAddr = config.listen.parse()?;
    let state = AppState {
        config: Arc::new(config),
        signing_key: Arc::new(signing_key),
        state: Arc::new(state),
    };
    let app = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/keys/public", get(public_keys))
        .route("/v1/keys", get(private_keys))
        .route("/v1/signing-key", get(signing_key_handler))
        .route("/v1/enrollments", post(create_enrollment))
        .route("/v1/enrollments/{id}", get(enrollment_status))
        .route("/xmlrpc/", post(xmlrpc))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(address).await?;
    info!(%address, "server listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
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
    if request.name.trim().is_empty()
        || request.name.len() > 128
        || request.local_addresses.len() > 32
        || !request.secret_digest.starts_with("sha256:")
        || !request.token_digest.starts_with("sha256:")
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
            &client_ip(&headers, peer.ip()).to_string(),
            &request.secret_digest,
            &request.token_digest,
        )
        .map_err(|_| ApiError(StatusCode::CONFLICT, "unable to create enrollment"))?;
    Ok((
        StatusCode::CREATED,
        Json(EnrollmentResponse {
            request_id,
            code,
            expires_at,
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
    headers
        .get("x-request-nonce")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or(ApiError(StatusCode::BAD_REQUEST, "missing request nonce"))
}

fn signed(state: &AppState, group: &str, nonce: String) -> Result<Json<SignedEnvelope>, ApiError> {
    let now = unix_now();
    let keys = state
        .config
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
    signed(&state, &state.config.default_group, nonce)
}

async fn private_keys(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
) -> Result<Json<SignedEnvelope>, ApiError> {
    let nonce = nonce(&headers)?;
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    let group = state
        .config
        .group_for_token(token)
        .map(str::to_owned)
        .or_else(|| state.state.group_for_token(token).ok().flatten());
    let group = group.ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid bearer token"))?;
    signed(&state, &group, nonce)
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
    let group = state.config.group_for_ip(client_ip(&headers, peer.ip()));
    let keys = match state.config.keys_for_group(group) {
        Ok(keys) => keys,
        Err(error) => {
            error!(%error, "legacy key selection failed");
            return xml_fault(500, "Server error");
        }
    };
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

fn client_ip(headers: &HeaderMap, peer: std::net::IpAddr) -> std::net::IpAddr {
    if !peer.is_loopback() {
        return peer;
    }
    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or(peer)
}
