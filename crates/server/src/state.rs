#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]

use std::{
    collections::BTreeSet,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, backup::Backup, params};
use serde::Serialize;
use ssh_key_sync_core::{new_token, token_digest, unix_now};

const REQUEST_TTL: u64 = 900;
const EXPIRED_ENROLLMENT_RETENTION: u64 = 3_600;
const MAX_ENROLLMENT_ROWS: i64 = 20_000;
const MAX_ENROLLMENTS_PER_SOURCE: i64 = 20;

#[derive(Debug)]
pub(crate) enum CreateEnrollmentError {
    RateLimited,
    QueueFull,
    Database(rusqlite::Error),
}

impl From<rusqlite::Error> for CreateEnrollmentError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

pub(crate) struct State {
    db: Mutex<Connection>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Enrollment {
    pub id: String,
    pub code: String,
    pub name: String,
    pub hostname: String,
    pub local_addresses: String,
    pub source_ip: String,
    pub status: String,
    pub group: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct TokenRecord {
    pub id: String,
    pub label: String,
    pub group: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub last_used_at: Option<u64>,
    pub last_source_ip: Option<String>,
    pub last_client_version: Option<String>,
}

/// Operator-facing check-in state for a machine token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenCheckIn {
    Revoked,
    Expired,
    NeverConnected,
    Stale,
    New,
    Connected,
}

impl TokenCheckIn {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::NeverConnected => "never-connected",
            Self::Stale => "stale",
            Self::New => "new",
            Self::Connected => "connected",
        }
    }

    pub(crate) const fn needs_attention(self) -> bool {
        matches!(self, Self::NeverConnected | Self::Stale)
    }
}

impl TokenRecord {
    /// Classify the token's last successful key request.
    pub(crate) fn check_in(&self, now: u64, stale_after_hours: u64) -> TokenCheckIn {
        if self.revoked_at.is_some() {
            return TokenCheckIn::Revoked;
        }
        if self.expires_at.is_some_and(|expiry| expiry <= now) {
            return TokenCheckIn::Expired;
        }

        let stale_after = stale_after_hours.saturating_mul(3_600);
        match self.last_used_at {
            None if now.saturating_sub(self.created_at) >= stale_after => {
                TokenCheckIn::NeverConnected
            }
            None => TokenCheckIn::New,
            Some(last_used) if now.saturating_sub(last_used) >= stale_after => TokenCheckIn::Stale,
            Some(_) => TokenCheckIn::Connected,
        }
    }

    pub(crate) const fn last_check_in_at(&self) -> u64 {
        match self.last_used_at {
            Some(last_used) => last_used,
            None => self.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AuditRecord {
    pub action: String,
    pub subject: String,
    pub details: String,
    pub created_at: u64,
}

impl State {
    pub(crate) fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| rusqlite::Error::InvalidParameterName(error.to_string()))?;
        }
        let db = Connection::open(&path)?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS enrollments (
               id TEXT PRIMARY KEY, code TEXT NOT NULL, secret_digest TEXT NOT NULL,
               token_digest TEXT NOT NULL UNIQUE, name TEXT NOT NULL, hostname TEXT NOT NULL,
               local_addresses TEXT NOT NULL, source_ip TEXT NOT NULL,
               status TEXT NOT NULL, group_name TEXT, created_at INTEGER NOT NULL,
               expires_at INTEGER NOT NULL, decided_at INTEGER, hidden_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS machine_tokens (
               id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE, label TEXT NOT NULL,
               group_name TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER,
               revoked_at INTEGER,
               hidden_at INTEGER, last_used_at INTEGER, last_source_ip TEXT,
               last_client_version TEXT
             );
             CREATE TABLE IF NOT EXISTS audit (
               id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL,
               subject TEXT NOT NULL, details TEXT NOT NULL, created_at INTEGER NOT NULL
             );",
        )?;
        ensure_column(&db, "enrollments", "hidden_at", "INTEGER")?;
        ensure_column(&db, "machine_tokens", "hidden_at", "INTEGER")?;
        ensure_column(&db, "machine_tokens", "expires_at", "INTEGER")?;
        ensure_column(&db, "machine_tokens", "last_used_at", "INTEGER")?;
        ensure_column(&db, "machine_tokens", "last_source_ip", "TEXT")?;
        ensure_column(&db, "machine_tokens", "last_client_version", "TEXT")?;
        set_private_permissions(path.as_ref())?;
        Ok(Self { db: Mutex::new(db) })
    }

    pub(crate) fn create_enrollment(
        &self,
        name: &str,
        hostname: &str,
        local_addresses: &[String],
        source_ip: &str,
        secret_digest: &str,
        token_digest: &str,
    ) -> Result<(String, String, u64), CreateEnrollmentError> {
        let id = new_token();
        let code = id.chars().take(8).collect::<String>().to_ascii_uppercase();
        let now = unix_now();
        let expires = now + REQUEST_TTL;
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        db.execute(
            "DELETE FROM enrollments WHERE status='pending' AND expires_at<?1",
            [now.saturating_sub(EXPIRED_ENROLLMENT_RETENTION) as i64],
        )?;
        let recent: i64 = db.query_row(
            "SELECT COUNT(*) FROM enrollments WHERE source_ip=?1 AND created_at>=?2",
            params![source_ip, now.saturating_sub(600) as i64],
            |row| row.get(0),
        )?;
        let pending: i64 = db.query_row(
            "SELECT COUNT(*) FROM enrollments WHERE status='pending' AND expires_at>=?1",
            [now as i64],
            |row| row.get(0),
        )?;
        let total: i64 = db.query_row("SELECT COUNT(*) FROM enrollments", [], |row| row.get(0))?;
        if recent >= MAX_ENROLLMENTS_PER_SOURCE {
            return Err(CreateEnrollmentError::RateLimited);
        }
        if pending >= 100 || total >= MAX_ENROLLMENT_ROWS {
            return Err(CreateEnrollmentError::QueueFull);
        }
        let addresses = serde_json::to_string(local_addresses)
            .map_err(|error| rusqlite::Error::InvalidParameterName(error.to_string()))?;
        db.execute(
            "INSERT INTO enrollments (id,code,secret_digest,token_digest,name,hostname,local_addresses,source_ip,status,created_at,expires_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'pending',?9,?10)",
            params![id, code, secret_digest, token_digest, name, hostname, addresses, source_ip, now as i64, expires as i64],
        )?;
        Self::audit_locked(&db, "enrollment.request", &id, "pending request created")?;
        Ok((id, code, expires))
    }

    pub(crate) fn enrollment_for_secret(
        &self,
        id: &str,
        secret: &str,
    ) -> rusqlite::Result<Option<Enrollment>> {
        let digest = token_digest(secret);
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        db.query_row(
            "SELECT id,code,name,hostname,local_addresses,source_ip,status,group_name,created_at,expires_at
             FROM enrollments WHERE id=?1 AND secret_digest=?2",
            params![id, digest],
            Self::map_enrollment,
        )
        .optional()
    }

    pub(crate) fn list_enrollments(&self) -> rusqlite::Result<Vec<Enrollment>> {
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut statement = db.prepare(
            "SELECT id,code,name,hostname,local_addresses,source_ip,status,group_name,created_at,expires_at
             FROM enrollments WHERE hidden_at IS NULL ORDER BY created_at DESC",
        )?;
        statement.query_map([], Self::map_enrollment)?.collect()
    }

    pub(crate) fn approve(
        &self,
        id: &str,
        group: &str,
        expires_at: Option<u64>,
    ) -> rusqlite::Result<bool> {
        let now = unix_now();
        let mut db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = db.transaction()?;
        let row: Option<(String, String, i64, String)> = tx
            .query_row(
                "SELECT token_digest,name,expires_at,status FROM enrollments WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((digest, name, expires, status)) = row else {
            return Ok(false);
        };
        if status != "pending" || now > expires as u64 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE enrollments SET status='approved',group_name=?1,decided_at=?2 WHERE id=?3",
            params![group, now as i64, id],
        )?;
        tx.execute(
            "INSERT INTO machine_tokens
               (id,digest,label,group_name,created_at,expires_at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                format!("machine-{id}"),
                digest,
                name,
                group,
                now as i64,
                expires_at.map(|value| value as i64)
            ],
        )?;
        let audit_details = expires_at.map_or_else(
            || group.to_owned(),
            |expiry| format!("{group}; expires_at={expiry}"),
        );
        Self::audit_locked(&tx, "enrollment.approve", id, &audit_details)?;
        tx.commit()?;
        Ok(true)
    }

    pub(crate) fn deny(&self, id: &str) -> rusqlite::Result<bool> {
        let now = unix_now();
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let changed = db.execute(
            "UPDATE enrollments SET status='denied',decided_at=?1 WHERE id=?2 AND status='pending'",
            params![now as i64, id],
        )?;
        if changed > 0 {
            Self::audit_locked(&db, "enrollment.deny", id, "denied")?;
        }
        Ok(changed > 0)
    }

    pub(crate) fn hide_enrollment(&self, id: &str) -> rusqlite::Result<bool> {
        let now = unix_now();
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let changed = db.execute(
            "UPDATE enrollments SET hidden_at=?1 WHERE id=?2 AND hidden_at IS NULL AND status!='pending'",
            params![now as i64, id],
        )?;
        if changed > 0 {
            Self::audit_locked(&db, "enrollment.hide", id, "hidden")?;
        }
        Ok(changed > 0)
    }

    pub(crate) fn retire_enrollment(&self, id: &str) -> rusqlite::Result<bool> {
        let now = unix_now();
        let mut db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = db.transaction()?;
        let changed = tx.execute(
            "UPDATE enrollments SET hidden_at=?1 WHERE id=?2 AND hidden_at IS NULL AND status!='pending'",
            params![now as i64, id],
        )?;
        if changed == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE machine_tokens SET revoked_at=COALESCE(revoked_at,?1),hidden_at=COALESCE(hidden_at,?1)
             WHERE id=?2",
            params![now as i64, format!("machine-{id}")],
        )?;
        Self::audit_locked(
            &tx,
            "enrollment.retire",
            id,
            "token revoked and record hidden",
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub(crate) fn group_for_token(
        &self,
        plaintext: &str,
        source_ip: &str,
        client_version: &str,
    ) -> rusqlite::Result<Option<String>> {
        let digest = token_digest(plaintext);
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let now = unix_now();
        let group = db
            .query_row(
                "SELECT group_name FROM machine_tokens
                 WHERE digest=?1 AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at>?2)",
                params![digest, now as i64],
                |row| row.get(0),
            )
            .optional()?;
        if group.is_some() {
            db.execute(
                "UPDATE machine_tokens SET last_used_at=?1,last_source_ip=?2,last_client_version=?3 WHERE digest=?4",
                params![now as i64, source_ip, client_version, digest],
            )?;
        }
        Ok(group)
    }

    pub(crate) fn list_tokens(&self) -> rusqlite::Result<Vec<TokenRecord>> {
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut statement = db.prepare(
            "SELECT id,label,group_name,created_at,expires_at,revoked_at,last_used_at,last_source_ip,last_client_version FROM machine_tokens
             WHERE hidden_at IS NULL ORDER BY created_at DESC",
        )?;
        statement
            .query_map([], |row| {
                Ok(TokenRecord {
                    id: row.get(0)?,
                    label: row.get(1)?,
                    group: row.get(2)?,
                    created_at: row.get::<_, i64>(3)? as u64,
                    expires_at: row.get::<_, Option<i64>>(4)?.map(|value| value as u64),
                    revoked_at: row.get::<_, Option<i64>>(5)?.map(|value| value as u64),
                    last_used_at: row.get::<_, Option<i64>>(6)?.map(|value| value as u64),
                    last_source_ip: row.get(7)?,
                    last_client_version: row.get(8)?,
                })
            })?
            .collect()
    }

    pub(crate) fn enrollment_by_id(&self, id: &str) -> rusqlite::Result<Option<Enrollment>> {
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        db.query_row(
            "SELECT id,code,name,hostname,local_addresses,source_ip,status,group_name,created_at,expires_at
             FROM enrollments WHERE id=?1",
            [id],
            Self::map_enrollment,
        )
        .optional()
    }

    pub(crate) fn enrollment_conflicts(
        &self,
        candidate: &Enrollment,
    ) -> rusqlite::Result<Vec<Enrollment>> {
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut statement = db.prepare(
            "SELECT e.id,e.code,e.name,e.hostname,e.local_addresses,e.source_ip,
                    e.status,e.group_name,e.created_at,e.expires_at
             FROM enrollments AS e
             JOIN machine_tokens AS token ON token.id='machine-' || e.id
             WHERE e.id<>?1 AND e.status='approved' AND e.hidden_at IS NULL
               AND token.revoked_at IS NULL
               AND (token.expires_at IS NULL OR token.expires_at>?2)",
        )?;
        let candidate_addresses = enrollment_addresses(&candidate.local_addresses);
        let candidates = statement
            .query_map(
                params![candidate.id, unix_now() as i64],
                Self::map_enrollment,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(candidates
            .into_iter()
            .filter(|existing| {
                candidate.name.eq_ignore_ascii_case(&existing.name)
                    || (candidate.source_ip == existing.source_ip
                        && (candidate.hostname.eq_ignore_ascii_case(&existing.hostname)
                            || !candidate_addresses
                                .is_disjoint(&enrollment_addresses(&existing.local_addresses))))
            })
            .collect())
    }

    pub(crate) fn revoke_token(&self, id: &str) -> rusqlite::Result<bool> {
        let now = unix_now();
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let changed = db.execute(
            "UPDATE machine_tokens SET revoked_at=?1 WHERE id=?2 AND revoked_at IS NULL",
            params![now as i64, id],
        )?;
        if changed > 0 {
            Self::audit_locked(&db, "token.revoke", id, "revoked")?;
        }
        Ok(changed > 0)
    }

    pub(crate) fn hide_token(&self, id: &str) -> rusqlite::Result<bool> {
        let now = unix_now();
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let changed = db.execute(
            "UPDATE machine_tokens SET hidden_at=?1
             WHERE id=?2 AND hidden_at IS NULL
               AND (revoked_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at<=?1))",
            params![now as i64, id],
        )?;
        if changed > 0 {
            Self::audit_locked(&db, "token.hide", id, "hidden")?;
        }
        Ok(changed > 0)
    }

    pub(crate) fn group_has_active_tokens(&self, group: &str) -> rusqlite::Result<bool> {
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        db.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM machine_tokens
               WHERE group_name=?1 AND revoked_at IS NULL
                 AND (expires_at IS NULL OR expires_at>?2)
             )",
            params![group, unix_now() as i64],
            |row| row.get(0),
        )
    }

    pub(crate) fn list_audit(&self, subject: Option<&str>) -> rusqlite::Result<Vec<AuditRecord>> {
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut statement = db.prepare(
            "SELECT action,subject,details,created_at FROM audit
             WHERE (?1 IS NULL OR subject=?1)
             ORDER BY created_at DESC,id DESC LIMIT 200",
        )?;
        statement
            .query_map([subject], |row| {
                Ok(AuditRecord {
                    action: row.get(0)?,
                    subject: row.get(1)?,
                    details: row.get(2)?,
                    created_at: row.get::<_, i64>(3)? as u64,
                })
            })?
            .collect()
    }

    pub(crate) fn backup_to(&self, path: impl AsRef<Path>) -> rusqlite::Result<()> {
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut destination = Connection::open(path)?;
        let backup = Backup::new(&db, &mut destination)?;
        backup.run_to_completion(5, Duration::from_millis(250), None)?;
        Ok(())
    }

    pub(crate) fn verify_backup(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() {
            return Err("backup must be a regular file".into());
        }
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let integrity: String = db.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(format!("SQLite integrity check failed: {integrity}").into());
        }
        for table in ["enrollments", "machine_tokens", "audit"] {
            db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get::<_, i64>(0)
            })?;
        }
        drop(db);

        let directory = tempfile::tempdir()?;
        let probe = directory.path().join("state.db");
        std::fs::copy(path, &probe)?;
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o600))?;
        let migrated = Self::open(&probe)?;
        migrated.list_enrollments()?;
        migrated.list_tokens()?;
        migrated.list_audit(None)?;
        Ok(())
    }

    fn map_enrollment(row: &rusqlite::Row<'_>) -> rusqlite::Result<Enrollment> {
        Ok(Enrollment {
            id: row.get(0)?,
            code: row.get(1)?,
            name: row.get(2)?,
            hostname: row.get(3)?,
            local_addresses: row.get(4)?,
            source_ip: row.get(5)?,
            status: row.get(6)?,
            group: row.get(7)?,
            created_at: row.get::<_, i64>(8)? as u64,
            expires_at: row.get::<_, i64>(9)? as u64,
        })
    }

    fn audit_locked(
        db: &Connection,
        action: &str,
        subject: &str,
        details: &str,
    ) -> rusqlite::Result<()> {
        db.execute(
            "INSERT INTO audit (action,subject,details,created_at) VALUES (?1,?2,?3,?4)",
            params![action, subject, details, unix_now() as i64],
        )?;
        Ok(())
    }
}

fn enrollment_addresses(value: &str) -> BTreeSet<String> {
    serde_json::from_str::<Vec<String>>(value)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|address| address.split_once(':').map(|(_, ip)| ip.to_owned()))
        .collect()
}

fn set_private_permissions(path: &Path) -> rusqlite::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|error| {
        rusqlite::Error::InvalidParameterName(format!("cannot secure {}: {error}", path.display()))
    })?;
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
        if sidecar.exists() {
            std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600)).map_err(
                |error| {
                    rusqlite::Error::InvalidParameterName(format!(
                        "cannot secure {}: {error}",
                        sidecar.display()
                    ))
                },
            )?;
        }
    }
    Ok(())
}

fn ensure_column(
    db: &Connection,
    table: &str,
    column: &str,
    declaration: &str,
) -> rusqlite::Result<()> {
    let mut statement = db.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !names.iter().any(|name| name == column) {
        db.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {declaration}"
        ))?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn token_record(created_at: u64, last_used_at: Option<u64>) -> TokenRecord {
        TokenRecord {
            id: "machine-test".into(),
            label: "test".into(),
            group: "restricted".into(),
            created_at,
            expires_at: None,
            revoked_at: None,
            last_used_at,
            last_source_ip: None,
            last_client_version: None,
        }
    }

    #[test]
    fn token_check_in_reports_new_connected_and_stale_machines() {
        let now = 1_000_000;
        let stale_after_hours = 48;
        assert_eq!(
            token_record(now - 60, None).check_in(now, stale_after_hours),
            TokenCheckIn::New
        );
        assert_eq!(
            token_record(now - 60, Some(now - 60)).check_in(now, stale_after_hours),
            TokenCheckIn::Connected
        );
        assert_eq!(
            token_record(now - 172_800, None).check_in(now, stale_after_hours),
            TokenCheckIn::NeverConnected
        );
        assert_eq!(
            token_record(now - 172_800, Some(now - 172_800)).check_in(now, stale_after_hours),
            TokenCheckIn::Stale
        );
    }

    #[test]
    fn token_check_in_keeps_lifecycle_states_authoritative() {
        let now = 1_000_000;
        let mut expired = token_record(now - 172_800, None);
        expired.expires_at = Some(now - 1);
        assert_eq!(expired.check_in(now, 48), TokenCheckIn::Expired);

        let mut revoked = token_record(now - 172_800, None);
        revoked.expires_at = Some(now - 1);
        revoked.revoked_at = Some(now - 2);
        assert_eq!(revoked.check_in(now, 48), TokenCheckIn::Revoked);
    }

    #[test]
    fn enrollment_approval_activates_the_client_token() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path().join("state.db")).unwrap();
        let secret = "request-secret";
        let token = "machine-token";
        let (id, _, _) = state
            .create_enrollment(
                "host-a",
                "host-a",
                &["eth0:192.0.2.10".into()],
                "198.51.100.20",
                &token_digest(secret),
                &token_digest(token),
            )
            .unwrap();
        assert!(state.enrollment_for_secret(&id, secret).unwrap().is_some());
        assert!(state.approve(&id, "restricted", None).unwrap());
        assert_eq!(
            state
                .group_for_token(token, "192.0.2.10", "test")
                .unwrap()
                .as_deref(),
            Some("restricted")
        );
        assert!(state.revoke_token(&format!("machine-{id}")).unwrap());
        assert!(
            state
                .group_for_token(token, "192.0.2.10", "test")
                .unwrap()
                .is_none()
        );
        assert!(state.hide_token(&format!("machine-{id}")).unwrap());
        assert!(state.list_tokens().unwrap().is_empty());
        assert!(state.retire_enrollment(&id).unwrap());
        assert!(state.list_enrollments().unwrap().is_empty());
    }

    #[test]
    fn expired_machine_tokens_are_rejected_and_can_be_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path().join("state.db")).unwrap();
        let token = "expiring-machine-token";
        let (id, _, _) = state
            .create_enrollment(
                "host-a",
                "host-a",
                &[],
                "192.0.2.1",
                &token_digest("secret"),
                &token_digest(token),
            )
            .unwrap();
        assert!(
            state
                .approve(&id, "restricted", Some(unix_now().saturating_add(60)))
                .unwrap()
        );
        assert_eq!(
            state
                .group_for_token(token, "192.0.2.10", "test")
                .unwrap()
                .as_deref(),
            Some("restricted")
        );
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE machine_tokens SET expires_at=?1 WHERE id=?2",
                params![unix_now() as i64 - 1, format!("machine-{id}")],
            )
            .unwrap();
        assert!(
            state
                .group_for_token(token, "192.0.2.10", "test")
                .unwrap()
                .is_none()
        );
        assert!(!state.group_has_active_tokens("restricted").unwrap());
        assert!(state.hide_token(&format!("machine-{id}")).unwrap());
        assert!(state.list_tokens().unwrap().is_empty());
    }

    #[test]
    fn enrollment_requires_the_request_secret() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path().join("state.db")).unwrap();
        let (id, _, _) = state
            .create_enrollment(
                "host-a",
                "host-a",
                &[],
                "192.0.2.1",
                &token_digest("correct"),
                &token_digest("token"),
            )
            .unwrap();
        assert!(state.enrollment_for_secret(&id, "wrong").unwrap().is_none());
    }

    #[test]
    fn conflicting_active_enrollments_are_detected() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path().join("state.db")).unwrap();
        let (old_id, _, _) = state
            .create_enrollment(
                "panel",
                "panel.example.net",
                &["eth0:192.0.2.10".into()],
                "198.51.100.10",
                &token_digest("old-secret"),
                &token_digest("old-token"),
            )
            .unwrap();
        assert!(state.approve(&old_id, "restricted", None).unwrap());

        let (new_id, _, _) = state
            .create_enrollment(
                "panel",
                "panel.example.net",
                &["eth0:192.0.2.10".into()],
                "198.51.100.11",
                &token_digest("new-secret"),
                &token_digest("new-token"),
            )
            .unwrap();
        let candidate = state.enrollment_by_id(&new_id).unwrap().unwrap();
        let conflicts = state.enrollment_conflicts(&candidate).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].id, old_id);

        let (separate_id, _, _) = state
            .create_enrollment(
                "other",
                "other.example.net",
                &["eth0:192.0.2.20".into()],
                "198.51.100.12",
                &token_digest("other-secret"),
                &token_digest("other-token"),
            )
            .unwrap();
        let separate = state.enrollment_by_id(&separate_id).unwrap().unwrap();
        assert!(state.enrollment_conflicts(&separate).unwrap().is_empty());

        assert!(state.retire_enrollment(&old_id).unwrap());
        assert!(state.enrollment_conflicts(&candidate).unwrap().is_empty());
    }

    #[test]
    fn shared_hostnames_and_private_overlay_addresses_at_different_sites_do_not_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path().join("state.db")).unwrap();
        let (old_id, _, _) = state
            .create_enrollment(
                "pve.pineview.net",
                "pve",
                &["vmbr0:192.0.2.10".into(), "zt0:172.24.42.1".into()],
                "198.51.100.10",
                &token_digest("old-secret"),
                &token_digest("old-token"),
            )
            .unwrap();
        assert!(state.approve(&old_id, "home", None).unwrap());

        let (new_id, _, _) = state
            .create_enrollment(
                "pve.wooltech.com.au",
                "pve",
                &["vmbr0:192.0.2.10".into(), "zt0:172.24.42.1".into()],
                "198.51.100.11",
                &token_digest("new-secret"),
                &token_digest("new-token"),
            )
            .unwrap();
        let candidate = state.enrollment_by_id(&new_id).unwrap().unwrap();
        assert!(state.enrollment_conflicts(&candidate).unwrap().is_empty());
    }

    #[test]
    fn enrollment_requests_are_rate_limited_by_source() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path().join("state.db")).unwrap();
        for index in 0..20 {
            state
                .create_enrollment(
                    &format!("host-{index}"),
                    "host",
                    &[],
                    "192.0.2.1",
                    &token_digest(&format!("secret-{index}")),
                    &token_digest(&format!("token-{index}")),
                )
                .unwrap();
        }
        assert!(matches!(
            state.create_enrollment(
                "host-21",
                "host",
                &[],
                "192.0.2.1",
                &token_digest("secret-21"),
                &token_digest("token-21"),
            ),
            Err(CreateEnrollmentError::RateLimited)
        ));
    }

    #[test]
    fn audit_records_are_available_to_operators() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path().join("state.db")).unwrap();
        let (id, _, _) = state
            .create_enrollment(
                "host-a",
                "host-a",
                &[],
                "192.0.2.1",
                &token_digest("secret"),
                &token_digest("token"),
            )
            .unwrap();
        assert!(state.approve(&id, "restricted", None).unwrap());

        let records = state.list_audit(Some(&id)).unwrap();
        assert_eq!(records[0].action, "enrollment.approve");
        assert_eq!(records[1].action, "enrollment.request");
        assert_eq!(state.list_audit(None).unwrap().len(), 2);
    }

    #[test]
    fn state_backup_is_a_consistent_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("state.db");
        let state = State::open(&database).unwrap();
        assert_eq!(
            std::fs::metadata(&database).unwrap().permissions().mode() & 0o777,
            0o600
        );
        state
            .create_enrollment(
                "host-a",
                "host-a",
                &[],
                "192.0.2.1",
                &token_digest("secret"),
                &token_digest("token"),
            )
            .unwrap();
        let backup = dir.path().join("backup.db");
        state.backup_to(&backup).unwrap();

        let copied = Connection::open(backup).unwrap();
        let count: i64 = copied
            .query_row("SELECT COUNT(*) FROM enrollments", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn backup_verification_accepts_current_state_and_rejects_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("state.db");
        let state = State::open(&database).unwrap();
        state
            .create_enrollment(
                "host-a",
                "host-a",
                &[],
                "192.0.2.1",
                &token_digest("secret"),
                &token_digest("token"),
            )
            .unwrap();
        let backup = dir.path().join("backup.db");
        state.backup_to(&backup).unwrap();
        State::verify_backup(&backup).unwrap();

        std::fs::write(&backup, b"not a sqlite database").unwrap();
        assert!(State::verify_backup(&backup).is_err());
    }

    #[test]
    fn backup_verification_migrates_a_compatible_older_schema_copy() {
        let dir = tempfile::tempdir().unwrap();
        let backup = dir.path().join("old-backup.db");
        let db = Connection::open(&backup).unwrap();
        db.execute_batch(
            "CREATE TABLE enrollments (
               id TEXT PRIMARY KEY, code TEXT NOT NULL, secret_digest TEXT NOT NULL,
               token_digest TEXT NOT NULL UNIQUE, name TEXT NOT NULL, hostname TEXT NOT NULL,
               local_addresses TEXT NOT NULL, source_ip TEXT NOT NULL,
               status TEXT NOT NULL, group_name TEXT, created_at INTEGER NOT NULL,
               expires_at INTEGER NOT NULL, decided_at INTEGER
             );
             CREATE TABLE machine_tokens (
               id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE, label TEXT NOT NULL,
               group_name TEXT NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER
             );
             CREATE TABLE audit (
               id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL,
               subject TEXT NOT NULL, details TEXT NOT NULL, created_at INTEGER NOT NULL
             );",
        )
        .unwrap();
        drop(db);

        State::verify_backup(&backup).unwrap();
        let migrated = State::open(&backup).unwrap();
        assert!(migrated.list_tokens().unwrap().is_empty());
    }

    #[test]
    fn old_expired_enrollment_rows_are_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path().join("state.db")).unwrap();
        state
            .create_enrollment(
                "old",
                "old",
                &[],
                "192.0.2.1",
                &token_digest("old-secret"),
                &token_digest("old-token"),
            )
            .unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute(
                "UPDATE enrollments SET expires_at=?1",
                [(unix_now() - EXPIRED_ENROLLMENT_RETENTION - 1) as i64],
            )
            .unwrap();
        }
        state
            .create_enrollment(
                "new",
                "new",
                &[],
                "192.0.2.2",
                &token_digest("new-secret"),
                &token_digest("new-token"),
            )
            .unwrap();
        assert_eq!(state.list_enrollments().unwrap().len(), 1);
    }
}
