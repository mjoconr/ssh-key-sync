//! Shared configuration, key selection, and signed protocol support.

#![allow(
    clippy::default_trait_access,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use ipnet::IpNet;
use rand::{RngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use ssh_key::PublicKey;
use thiserror::Error;
use url::Url;

/// Current configuration schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;
/// Current native protocol schema version.
pub const PROTOCOL_SCHEMA_VERSION: u32 = 1;
/// Default interval used by the managed client timer.
pub const DEFAULT_SYNC_INTERVAL_HOURS: u64 = 2;
const RELEASE_SIGNATURE_PREFIX: &str = "ssh-key-sync-release-v1:";
const RELEASE_SIGNATURE_CONTEXT: &[u8] = b"ssh-key-sync-release-manifest-v1\0";

/// Errors produced by shared validation and protocol logic.
#[derive(Debug, Error)]
pub enum Error {
    /// Filesystem operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Configuration syntax is invalid.
    #[error("invalid TOML configuration: {0}")]
    Toml(#[from] toml::de::Error),
    /// JSON data is malformed.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Configuration failed a semantic check.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// SSH public key is malformed.
    #[error("invalid SSH public key: {0}")]
    InvalidKey(String),
    /// Signature could not be decoded or verified.
    #[error("invalid signature")]
    Signature,
    /// Protocol schema is unsupported.
    #[error("unsupported protocol schema")]
    Schema,
    /// Response nonce differs from the request.
    #[error("response nonce mismatch")]
    Nonce,
    /// Response is outside its validity interval.
    #[error("response is not currently valid")]
    Expired,
}

/// Public or private group visibility.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// May be fetched without a token.
    Public,
    /// Requires a token.
    Private,
}

/// One key-selection group.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupConfig {
    /// Whether anonymous clients may fetch this group.
    pub visibility: Visibility,
    /// Optional lifetime for machine tokens approved into this group.
    #[serde(default)]
    pub token_ttl_days: Option<u64>,
    /// Whether the unauthenticated XML-RPC compatibility route may serve it.
    #[serde(default)]
    pub legacy_xmlrpc: bool,
    /// Legacy source networks mapped to this group.
    #[serde(default)]
    pub cidrs: Vec<IpNet>,
}

/// A named owner of one or more public keys.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// Groups receiving these keys.
    pub groups: Vec<String>,
    /// OpenSSH public key lines.
    pub keys: Vec<String>,
}

/// Group or machine token record containing only a digest.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenConfig {
    /// Stable token identifier.
    pub id: String,
    /// Group selected by this token.
    pub group: String,
    /// `sha256:` followed by lowercase hexadecimal.
    pub digest: String,
}

/// Complete validated server configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Configuration format version.
    pub schema_version: u32,
    /// Address on which the server listens.
    pub listen: String,
    /// File containing a raw 32-byte Ed25519 signing key.
    pub signing_key_file: String,
    /// Externally reachable HTTPS URL used by client bootstrap commands.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Permit binding the cleartext HTTP server beyond loopback.
    #[serde(default)]
    pub allow_non_loopback_http: bool,
    /// Require a trusted `X-Real-IP` header for requests arriving over loopback.
    #[serde(default = "default_true")]
    pub require_forwarded_client_ip: bool,
    /// Optional SQLite enrollment and token state path.
    #[serde(default)]
    pub state_file: Option<String>,
    /// Anonymous group returned by the public endpoint.
    pub default_group: String,
    /// Available groups.
    pub groups: BTreeMap<String, GroupConfig>,
    /// Key owners and group assignments.
    pub keys: BTreeMap<String, KeyConfig>,
    /// Restricted access tokens.
    #[serde(default)]
    pub tokens: Vec<TokenConfig>,
}

impl Config {
    /// Read and validate a server configuration file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text)
    }

    /// Parse and validate server configuration text.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let config: Self = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate references and cryptographic key material.
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(Error::InvalidConfig("unsupported schema_version".into()));
        }
        let listen = self
            .listen
            .parse::<std::net::SocketAddr>()
            .map_err(|_| Error::InvalidConfig("listen must be an IP socket address".into()))?;
        if !listen.ip().is_loopback() && !self.allow_non_loopback_http {
            return Err(Error::InvalidConfig(
                "cleartext listen address must be loopback".into(),
            ));
        }
        if let Some(public_url) = &self.public_url {
            let url = Url::parse(public_url)
                .map_err(|_| Error::InvalidConfig("public_url must be a valid URL".into()))?;
            if url.scheme() != "https"
                || url.host().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(Error::InvalidConfig(
                    "public_url must be HTTPS without credentials".into(),
                ));
            }
        }
        if self.groups.is_empty() {
            return Err(Error::InvalidConfig("no groups defined".into()));
        }
        let default = self
            .groups
            .get(&self.default_group)
            .ok_or_else(|| Error::InvalidConfig("default_group does not exist".into()))?;
        if default.visibility != Visibility::Public {
            return Err(Error::InvalidConfig("default_group must be public".into()));
        }
        for (name, group) in &self.groups {
            if name.trim().is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
            {
                return Err(Error::InvalidConfig("invalid group identifier".into()));
            }
            if group
                .token_ttl_days
                .is_some_and(|days| days == 0 || days > 3650)
            {
                return Err(Error::InvalidConfig(
                    "group token_ttl_days must be between 1 and 3650".into(),
                ));
            }
        }
        let mut fingerprints = BTreeSet::new();
        for owner in self.keys.values() {
            for group in &owner.groups {
                if !self.groups.contains_key(group) {
                    return Err(Error::InvalidConfig(format!("unknown group: {group}")));
                }
            }
            for key in &owner.keys {
                if !fingerprints.insert(parse_public_key(key)?.fingerprint) {
                    return Err(Error::InvalidConfig("duplicate public key".into()));
                }
            }
        }
        let mut token_ids = BTreeSet::new();
        for token in &self.tokens {
            if !token_ids.insert(token.id.as_str()) {
                return Err(Error::InvalidConfig("duplicate token id".into()));
            }
            if !self.groups.contains_key(&token.group) {
                return Err(Error::InvalidConfig("unknown token group".into()));
            }
            validate_token_digest(&token.digest)?;
        }
        Ok(())
    }

    /// Resolve a group's keys in deterministic order.
    pub fn keys_for_group(&self, group: &str) -> Result<Vec<KeyRecord>, Error> {
        if !self.groups.contains_key(group) {
            return Err(Error::InvalidConfig(format!("unknown group: {group}")));
        }
        let mut result = Vec::new();
        let mut seen = BTreeSet::new();
        for owner in self.keys.values() {
            if owner.groups.iter().any(|candidate| candidate == group) {
                for key in &owner.keys {
                    let record = parse_public_key(key)?;
                    if seen.insert(record.fingerprint.clone()) {
                        result.push(record);
                    }
                }
            }
        }
        Ok(result)
    }

    /// Select a legacy group using the most-specific matching CIDR.
    pub fn group_for_ip(&self, ip: IpAddr) -> Option<&str> {
        self.groups
            .iter()
            .flat_map(|(name, group)| {
                group.cidrs.iter().filter_map(move |network| {
                    (group.legacy_xmlrpc && network.contains(&ip))
                        .then_some((network.prefix_len(), name.as_str()))
                })
            })
            .max_by_key(|(prefix, _)| *prefix)
            .map(|(_, name)| name)
            .or_else(|| {
                self.groups
                    .get(&self.default_group)
                    .is_some_and(|group| group.legacy_xmlrpc)
                    .then_some(self.default_group.as_str())
            })
    }

    /// Authenticate a group token and return its group.
    pub fn group_for_token(&self, plaintext: &str) -> Option<&str> {
        let digest = token_digest(plaintext);
        self.tokens
            .iter()
            .find(|token| constant_time_eq(token.digest.as_bytes(), digest.as_bytes()))
            .map(|token| token.group.as_str())
    }
}

fn default_true() -> bool {
    true
}

/// One validated key and its fingerprint.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyRecord {
    /// OpenSSH SHA-256 fingerprint.
    pub fingerprint: String,
    /// Canonical OpenSSH public key line.
    pub authorized_keys: String,
}

/// Payload covered by the Ed25519 response signature.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeySetPayload {
    /// Protocol schema.
    pub schema: u32,
    /// Copied request nonce.
    pub nonce: String,
    /// Unix issue time.
    pub issued_at: u64,
    /// Unix expiry time.
    pub expires_at: u64,
    /// Selected group.
    pub group: String,
    /// Selected public keys.
    pub keys: Vec<KeyRecord>,
}

/// Signed native response envelope.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    /// Envelope schema.
    pub schema: u32,
    /// Base64url-encoded exact signed payload.
    pub payload: String,
    /// Base64url-encoded Ed25519 signature.
    pub signature: String,
}

/// Parse and canonicalize an OpenSSH public key.
pub fn parse_public_key(line: &str) -> Result<KeyRecord, Error> {
    let key =
        PublicKey::from_openssh(line).map_err(|error| Error::InvalidKey(error.to_string()))?;
    Ok(KeyRecord {
        fingerprint: key.fingerprint(Default::default()).to_string(),
        authorized_keys: key
            .to_openssh()
            .map_err(|error| Error::InvalidKey(error.to_string()))?,
    })
}

/// Return the canonical OpenSSH algorithm name for a public key.
pub fn public_key_algorithm(line: &str) -> Result<String, Error> {
    let key =
        PublicKey::from_openssh(line).map_err(|error| Error::InvalidKey(error.to_string()))?;
    Ok(key.algorithm().as_str().to_owned())
}

/// Hash a high-entropy token for server storage.
pub fn token_digest(plaintext: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(plaintext.as_bytes()))
}

/// Validate the canonical stored form of a SHA-256 token digest.
pub fn validate_token_digest(digest: &str) -> Result<(), Error> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(Error::InvalidConfig("token digest must use sha256".into()));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Error::InvalidConfig("invalid token digest".into()));
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

/// Generate a random 32-byte request nonce.
pub fn new_nonce() -> String {
    new_token()
}

/// Generate a random base64url-encoded 32-byte value suitable for a token.
pub fn new_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Sign a typed payload into the native response envelope.
pub fn sign_payload(payload: &KeySetPayload, key: &SigningKey) -> Result<SignedEnvelope, Error> {
    let bytes = serde_json::to_vec(payload)?;
    let signature = key.sign(&bytes);
    Ok(SignedEnvelope {
        schema: PROTOCOL_SCHEMA_VERSION,
        payload: URL_SAFE_NO_PAD.encode(bytes),
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

/// Verify a signed payload, nonce, time interval, and key fingerprints.
pub fn verify_envelope(
    envelope: &SignedEnvelope,
    key: &VerifyingKey,
    nonce: &str,
    now: u64,
) -> Result<KeySetPayload, Error> {
    if envelope.schema != PROTOCOL_SCHEMA_VERSION {
        return Err(Error::Schema);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(&envelope.payload)
        .map_err(|_| Error::Signature)?;
    let signature = Signature::from_slice(
        &URL_SAFE_NO_PAD
            .decode(&envelope.signature)
            .map_err(|_| Error::Signature)?,
    )
    .map_err(|_| Error::Signature)?;
    key.verify_strict(&bytes, &signature)
        .map_err(|_| Error::Signature)?;
    let payload: KeySetPayload = serde_json::from_slice(&bytes)?;
    if payload.schema != PROTOCOL_SCHEMA_VERSION {
        return Err(Error::Schema);
    }
    if payload.nonce != nonce {
        return Err(Error::Nonce);
    }
    if now < payload.issued_at || now > payload.expires_at {
        return Err(Error::Expired);
    }
    for record in &payload.keys {
        if parse_public_key(&record.authorized_keys)?.fingerprint != record.fingerprint {
            return Err(Error::InvalidKey("fingerprint mismatch".into()));
        }
    }
    Ok(payload)
}

/// Load a raw 32-byte Ed25519 signing key.
pub fn load_signing_key(path: impl AsRef<Path>) -> Result<SigningKey, Error> {
    let bytes: [u8; 32] = std::fs::read(path)?
        .try_into()
        .map_err(|_| Error::InvalidConfig("signing key must be 32 bytes".into()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Load a signing key after rejecting symlinks and world-readable files.
pub fn load_signing_key_secure(path: impl AsRef<Path>) -> Result<SigningKey, Error> {
    let path = path.as_ref();
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(Error::InvalidConfig(
            "signing key must be a regular file".into(),
        ));
    }
    if metadata.permissions().mode() & 0o007 != 0 {
        return Err(Error::InvalidConfig(
            "signing key must not be world-accessible".into(),
        ));
    }
    load_signing_key(path)
}

/// Load a raw 32-byte Ed25519 verification key.
pub fn load_verifying_key(path: impl AsRef<Path>) -> Result<VerifyingKey, Error> {
    let bytes: [u8; 32] = std::fs::read(path)?
        .try_into()
        .map_err(|_| Error::InvalidConfig("verification key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| Error::InvalidConfig("invalid verification key".into()))
}

/// Return the SHA-256 fingerprint of the public half of a signing key.
pub fn signing_key_fingerprint(path: impl AsRef<Path>) -> Result<String, Error> {
    let key = load_signing_key_secure(path)?;
    Ok(format!(
        "{:x}",
        Sha256::digest(key.verifying_key().to_bytes())
    ))
}

/// Sign a release checksum manifest with the release signing key.
pub fn sign_release_manifest(manifest: &[u8], key: &SigningKey) -> String {
    let mut message = Vec::with_capacity(RELEASE_SIGNATURE_CONTEXT.len() + manifest.len());
    message.extend_from_slice(RELEASE_SIGNATURE_CONTEXT);
    message.extend_from_slice(manifest);
    format!(
        "{RELEASE_SIGNATURE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(key.sign(&message).to_bytes())
    )
}

/// Verify a detached signature over a release checksum manifest.
pub fn verify_release_manifest(
    manifest: &[u8],
    signature: &str,
    key: &VerifyingKey,
) -> Result<(), Error> {
    let encoded = signature
        .trim()
        .strip_prefix(RELEASE_SIGNATURE_PREFIX)
        .ok_or(Error::Signature)?;
    let signature = Signature::from_slice(
        &URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| Error::Signature)?,
    )
    .map_err(|_| Error::Signature)?;
    let mut message = Vec::with_capacity(RELEASE_SIGNATURE_CONTEXT.len() + manifest.len());
    message.extend_from_slice(RELEASE_SIGNATURE_CONTEXT);
    message.extend_from_slice(manifest);
    key.verify_strict(&message, &signature)
        .map_err(|_| Error::Signature)
}

/// Encode a release verification key for storage as a public text file.
pub fn encode_release_verifying_key(key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(key.to_bytes())
}

/// Load a base64url-encoded release verification key.
pub fn load_release_verifying_key(path: impl AsRef<Path>) -> Result<VerifyingKey, Error> {
    let encoded = std::fs::read_to_string(path)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded.trim()).map_err(|_| {
        Error::InvalidConfig("release verification key is not valid base64url".into())
    })?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::InvalidConfig("release verification key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| Error::InvalidConfig("invalid release verification key".into()))
}

/// Return the SHA-256 fingerprint of a release verification key.
pub fn release_verifying_key_fingerprint(key: &VerifyingKey) -> String {
    format!("{:x}", Sha256::digest(key.to_bytes()))
}

/// Return the current Unix timestamp.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti test";

    fn config() -> Config {
        Config::parse(&format!(
            r#"
schema_version = 1
listen = "127.0.0.1:8080"
signing_key_file = "/tmp/signing.key"
default_group = "public"
[groups.public]
visibility = "public"
legacy_xmlrpc = true
[groups.private]
visibility = "private"
legacy_xmlrpc = true
cidrs = ["192.0.2.0/24", "192.0.2.1/32"]
[keys.test]
groups = ["public", "private"]
keys = ["{KEY}"]
[[tokens]]
id = "test"
group = "private"
digest = "{}"
"#,
            token_digest("secret")
        ))
        .unwrap()
    }

    #[test]
    fn selects_tokens_and_specific_cidrs() {
        let mut config = config();
        assert_eq!(
            config.group_for_ip("192.0.2.1".parse().unwrap()),
            Some("private")
        );
        config.groups.get_mut("private").unwrap().legacy_xmlrpc = false;
        assert_eq!(
            config.group_for_ip("192.0.2.1".parse().unwrap()),
            Some("public")
        );
        config.groups.get_mut("public").unwrap().legacy_xmlrpc = false;
        assert_eq!(config.group_for_ip("192.0.2.1".parse().unwrap()), None);
        assert_eq!(config.group_for_token("secret"), Some("private"));
        assert_eq!(config.group_for_token("wrong"), None);
    }

    #[test]
    fn group_token_ttl_is_optional_and_bounded() {
        let mut config = config();
        assert_eq!(config.groups["private"].token_ttl_days, None);
        config.groups.get_mut("private").unwrap().token_ttl_days = Some(90);
        assert!(config.validate().is_ok());
        config.groups.get_mut("private").unwrap().token_ttl_days = Some(0);
        assert!(config.validate().is_err());
        config.groups.get_mut("private").unwrap().token_ttl_days = Some(3651);
        assert!(config.validate().is_err());
    }

    #[test]
    fn signs_and_verifies_payloads() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let nonce = new_nonce();
        let payload = KeySetPayload {
            schema: PROTOCOL_SCHEMA_VERSION,
            nonce: nonce.clone(),
            issued_at: 100,
            expires_at: 200,
            group: "public".into(),
            keys: vec![parse_public_key(KEY).unwrap()],
        };
        let envelope = sign_payload(&payload, &signing_key).unwrap();
        assert_eq!(
            verify_envelope(&envelope, &signing_key.verifying_key(), &nonce, 150).unwrap(),
            payload
        );
    }

    #[test]
    fn reports_public_key_algorithm() {
        assert_eq!(public_key_algorithm(KEY).unwrap(), "ssh-ed25519");
    }

    #[test]
    fn release_manifest_signature_is_bound_to_exact_bytes() {
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let manifest = b"hash  archive.tar.gz\n";
        let signature = sign_release_manifest(manifest, &signing_key);
        assert!(
            verify_release_manifest(manifest, &signature, &signing_key.verifying_key()).is_ok()
        );
        assert!(
            verify_release_manifest(b"changed\n", &signature, &signing_key.verifying_key())
                .is_err()
        );
        assert!(
            verify_release_manifest(
                manifest,
                &signature,
                &SigningKey::from_bytes(&[10_u8; 32]).verifying_key()
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unsafe_listen_and_public_urls() {
        let mut config = config();
        config.listen = "0.0.0.0:18080".into();
        assert!(config.validate().is_err());
        config.allow_non_loopback_http = true;
        assert!(config.validate().is_ok());
        config.public_url = Some("http://keys.example.net".into());
        assert!(config.validate().is_err());
        config.public_url = Some("https://user@keys.example.net".into());
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_world_readable_signing_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing.key");
        std::fs::write(&path, [7_u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_signing_key_secure(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_signing_key_secure(&path).is_ok());
    }
}
