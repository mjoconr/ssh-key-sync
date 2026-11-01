#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]

use std::{path::Path, sync::Mutex};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use ssh_key_sync_core::{new_token, token_digest, unix_now};

const REQUEST_TTL: u64 = 900;

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
    pub revoked_at: Option<u64>,
    pub last_used_at: Option<u64>,
    pub last_source_ip: Option<String>,
    pub last_client_version: Option<String>,
}

impl State {
    pub(crate) fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| rusqlite::Error::InvalidParameterName(error.to_string()))?;
        }
        let db = Connection::open(path)?;
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
               group_name TEXT NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER,
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
        ensure_column(&db, "machine_tokens", "last_used_at", "INTEGER")?;
        ensure_column(&db, "machine_tokens", "last_source_ip", "TEXT")?;
        ensure_column(&db, "machine_tokens", "last_client_version", "TEXT")?;
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
    ) -> rusqlite::Result<(String, String, u64)> {
        let id = new_token();
        let code = id.chars().take(8).collect::<String>().to_ascii_uppercase();
        let now = unix_now();
        let expires = now + REQUEST_TTL;
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
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
        if recent >= 3 || pending >= 100 {
            return Err(rusqlite::Error::InvalidQuery);
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

    pub(crate) fn approve(&self, id: &str, group: &str) -> rusqlite::Result<bool> {
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
            "INSERT INTO machine_tokens (id,digest,label,group_name,created_at)
             VALUES (?1,?2,?3,?4,?5)",
            params![format!("machine-{id}"), digest, name, group, now as i64],
        )?;
        Self::audit_locked(&tx, "enrollment.approve", id, group)?;
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
        let group = db
            .query_row(
                "SELECT group_name FROM machine_tokens WHERE digest=?1 AND revoked_at IS NULL",
                [digest],
                |row| row.get(0),
            )
            .optional()?;
        if group.is_some() {
            db.execute(
                "UPDATE machine_tokens SET last_used_at=?1,last_source_ip=?2,last_client_version=?3 WHERE digest=?4",
                params![unix_now() as i64, source_ip, client_version, token_digest(plaintext)],
            )?;
        }
        Ok(group)
    }

    pub(crate) fn list_tokens(&self) -> rusqlite::Result<Vec<TokenRecord>> {
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut statement = db.prepare(
            "SELECT id,label,group_name,created_at,revoked_at,last_used_at,last_source_ip,last_client_version FROM machine_tokens
             WHERE hidden_at IS NULL ORDER BY created_at DESC",
        )?;
        statement
            .query_map([], |row| {
                Ok(TokenRecord {
                    id: row.get(0)?,
                    label: row.get(1)?,
                    group: row.get(2)?,
                    created_at: row.get::<_, i64>(3)? as u64,
                    revoked_at: row.get::<_, Option<i64>>(4)?.map(|value| value as u64),
                    last_used_at: row.get::<_, Option<i64>>(5)?.map(|value| value as u64),
                    last_source_ip: row.get(6)?,
                    last_client_version: row.get(7)?,
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
            "UPDATE machine_tokens SET hidden_at=?1 WHERE id=?2 AND hidden_at IS NULL AND revoked_at IS NOT NULL",
            params![now as i64, id],
        )?;
        if changed > 0 {
            Self::audit_locked(&db, "token.hide", id, "hidden")?;
        }
        Ok(changed > 0)
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
        assert!(state.approve(&id, "restricted").unwrap());
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
    fn enrollment_requests_are_rate_limited_by_source() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path().join("state.db")).unwrap();
        for index in 0..3 {
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
        assert!(state
            .create_enrollment(
                "host-4",
                "host",
                &[],
                "192.0.2.1",
                &token_digest("secret-4"),
                &token_digest("token-4"),
            )
            .is_err());
    }
}
