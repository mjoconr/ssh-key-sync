//! Shared contracts and key-selection logic for SSH Key Sync.

/// XML-RPC method retained for compatibility with legacy clients.
pub const LEGACY_XMLRPC_METHOD: &str = "ssh.getKeys";

/// Default interval used by the managed client timer.
pub const DEFAULT_SYNC_INTERVAL_HOURS: u64 = 2;
