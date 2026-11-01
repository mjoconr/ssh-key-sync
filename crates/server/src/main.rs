//! SSH Key Sync server and administrative command line.

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::Serialize;
use ssh_key_sync_core::{
    Config, KeySetPayload, PROTOCOL_SCHEMA_VERSION, SignedEnvelope, load_signing_key, sign_payload,
    token_digest, unix_now,
};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

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
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    signing_key: Arc<SigningKey>,
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

#[tokio::main]
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
        Command::Serve { config } => run(config).await?,
    }
    Ok(())
}

async fn run(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(path)?;
    let signing_key = load_signing_key(&config.signing_key_file)?;
    let address: SocketAddr = config.listen.parse()?;
    let state = AppState {
        config: Arc::new(config),
        signing_key: Arc::new(signing_key),
    };
    let app = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/keys/public", get(public_keys))
        .route("/v1/keys", get(private_keys))
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
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SignedEnvelope>, ApiError> {
    let nonce = nonce(&headers)?;
    signed(&state, &state.config.default_group, nonce)
}

async fn private_keys(
    State(state): State<AppState>,
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
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid bearer token"))?;
    signed(&state, group, nonce)
}

async fn xmlrpc(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
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
    let group = state.config.group_for_ip(peer.ip());
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
