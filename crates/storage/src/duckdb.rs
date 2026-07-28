//! DuckDB-backed storage implementation.
//!
//! DuckDB serves as both the configuration store and the time-series
//! results store. Complex domain objects (`Target`, `CheckResult`,
//! `Incident`, `StatusPage`) are serialised whole into a `JSON` payload
//! column; only the columns queries need (id / slug / target_id / org_id
//! / timestamp) are projected out as first-class SQL columns so indices
//! can serve lookups without touching the JSON.

// ponytail: parking_lot::Mutex guard lifetime is bounded by the spawn_blocking
// closure — the lock is never held across an .await point by design.
#![expect(clippy::significant_drop_tightening)]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use duckdb::{Connection, params};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use statuscore::domain::{
    ActionItem, ApiTokenRow, ApiTokenUpdate, AppTheme, AssetSlot, CheckResult, CheckStatus,
    ComponentDayHistory, CreatedShare, DashboardRow, DashboardSummary, DayState, DeliveryReason,
    DeliveryStatus, DomainExpiryState, EscalationPolicy, EscalationPolicySummary, Incident,
    IncidentEscalationState, IncidentMetricsRollup, IncidentOpsPatch, IncidentPostmortem,
    IncidentState, IncidentStatusPhase, IncidentTransition, LatencyBucket, MagicLinkRow,
    MaintenanceFilter, MaintenanceWindow, MonitorShare, MonitorShareId, NewApiToken,
    NewNotificationChannel, NewSilenceRule, NewUser, NotificationChannel,
    NotificationChannelUpdate, OnCallLayer, OnCallOverride, OnCallSchedule, OnCallScheduleDetail,
    OnCallScheduleSummary, OrgId, PageAsset, PostmortemUpsert, PublicIncidentUpdate, ResolvedShare,
    ScopeSet, SessionRow, SilenceFilter, SilenceRule, SilenceRuleUpdate, StatusPage,
    StatusPageComponent, Subscriber, SubscriberChannel, SubscriberDelivery, Target,
    TargetChannelBinding, TimeFormat, UptimeResult, User, UserId, UserUpdate, Variable, VariableId,
    WriteSource, generate_cookie_value, hash_cookie_value, next_state, normalize_oauth_email,
};
use statuscore::error::Result;
use uuid::Uuid;

use crate::{Storage, StorageError};

/// Reversible credential encryption (AES-256-GCM envelope). `None` when no
/// KEK is configured — the documented self-host fallback where credentials
/// are stored as plaintext. Set via [`DuckdbStorage::with_cipher`] before the
/// storage is wrapped in `Arc<dyn Storage>`.
type SharedCipher = Option<Arc<common::security::Cipher>>;

/// DuckDB-backed storage implementation.
///
/// `Connection` is synchronous; we wrap it in a `parking_lot::Mutex` and run
/// each operation inline inside the async trait method. DuckDB calls against
/// a local file are fast enough that holding the lock across one query is
/// cheaper than a `spawn_blocking` round-trip, and the trait is `Send + Sync`
/// so callers can share an `Arc<DuckdbStorage>` freely.
pub struct DuckdbStorage {
    conn: Arc<Mutex<Connection>>,
    /// Reversible encryption for credential-bearing JSON fields (notification
    /// channel `config`, secret variable `value`). Sealed on write, opened on
    /// read — the in-memory domain model is always plaintext.
    cipher: SharedCipher,
}

impl std::fmt::Debug for DuckdbStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DuckdbStorage")
            .field("cipher", &self.cipher.is_some())
            .finish_non_exhaustive()
    }
}

impl DuckdbStorage {
    /// Open or create a DuckDB database at the given path.
    /// Use ":memory:" for an in-memory database (tests).
    pub fn open(path: &str) -> Result<Self> {
        let conn =
            if path == ":memory:" { Connection::open_in_memory() } else { Connection::open(path) }
                .map_err(|e| StorageError::Duckdb(e.to_string()))?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)), cipher: None })
    }

    /// Attach a KEK cipher for envelope encryption of credential fields at
    /// the DB edge. Consumes self so it chains from [`Self::open`] before the
    /// storage is wrapped in `Arc<dyn Storage>`. Passing `None` is equivalent
    /// to not calling this — plaintext fallback.
    pub fn with_cipher(mut self, cipher: Option<Arc<common::security::Cipher>>) -> Self {
        self.cipher = cipher;
        self
    }

    /// Seal a credential JSON string at the DB edge. Falls back to plaintext
    /// when no KEK is configured (self-host dev mode).
    fn seal_config(&self, plaintext: &str) -> Result<String> {
        common::security::seal_str(plaintext, self.cipher.as_deref())
            .map_err(|e| StorageError::Duckdb(format!("seal config failed: {e}")).into())
    }

    /// Open a sealed credential JSON string. Returns `None` when the value is
    /// an envelope but the KEK can't open it (key rotated out) so callers
    /// treat it as unusable rather than handing back ciphertext.
    fn open_config(&self, stored: &str) -> Option<String> {
        common::security::open_str(stored, self.cipher.as_deref())
    }

    /// Serialise a [`NotificationChannel`] to its at-rest payload JSON, with
    /// the `config` field sealed by the KEK. When no KEK is configured the
    /// config stays as plaintext JSON — the documented self-host fallback.
    /// The payload is a JSON object with `config` replaced by a string
    /// holding the sealed envelope (or plaintext JSON when no cipher).
    fn channel_to_payload(&self, channel: &NotificationChannel) -> Result<String> {
        let mut value = serde_json::to_value(channel)
            .map_err(|e| StorageError::Duckdb(format!("serialise channel: {e}")))?;
        if let Some(obj) = value.as_object_mut()
            && let Some(config) = obj.remove("config")
        {
            let config_json = serde_json::to_string(&config)
                .map_err(|e| StorageError::Duckdb(format!("serialise config: {e}")))?;
            let sealed = self.seal_config(&config_json)?;
            obj.insert("config_sealed".to_string(), serde_json::Value::String(sealed));
        }
        serde_json::to_string(&value)
            .map_err(|e| StorageError::Duckdb(format!("serialise payload: {e}")).into())
    }

    /// Parse an at-rest payload JSON back into a [`NotificationChannel`],
    /// opening the sealed `config` field. Returns `None` for the config when
    /// the KEK can't open the envelope (key rotated out) so the caller can
    /// treat the channel as unusable.
    fn channel_from_payload(&self, json: &str) -> Result<NotificationChannel> {
        let mut value: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| StorageError::Duckdb(format!("deserialise channel payload: {e}")))?;
        if let Some(obj) = value.as_object_mut()
            && let Some(sealed) =
                obj.remove("config_sealed").and_then(|v| v.as_str().map(str::to_owned))
        {
            if let Some(plaintext) = self.open_config(&sealed) {
                let config: statuscore::domain::ChannelConfig = serde_json::from_str(&plaintext)
                    .map_err(|e| {
                        StorageError::Duckdb(format!(
                            "deserialise opened config: {e} (KEK mismatch or corrupt envelope)"
                        ))
                    })?;
                obj.insert(
                    "config".to_string(),
                    serde_json::to_value(&config)
                        .map_err(|e| StorageError::Duckdb(format!("re-serialise config: {e}")))?,
                );
            } else {
                // Envelope present but no KEK can open it. Mark the
                // channel as permanently misconfigured rather than
                // leaking ciphertext into the domain model.
                tracing::error!(
                    "notification channel payload has sealed config but KEK cannot open it; \
                         returning config as empty webhook",
                );
                return Err(StorageError::Duckdb(
                    "sealed config cannot be opened (KEK missing or rotated)".into(),
                )
                .into());
            }
        }
        let dto: NotificationChannelDto = serde_json::from_value(value)
            .map_err(|e| StorageError::Duckdb(format!("deserialise channel dto: {e}")))?;
        Ok(dto.into())
    }

    /// Initialise schema. Idempotent — safe to call on every boot.
    ///
    /// Wrapped in a single transaction so a partial failure (disk full,
    /// power loss mid-batch) rolls back every DDL statement instead of
    /// leaving the schema half-applied. DuckDB supports DDL inside
    /// transactions, and `CREATE TABLE IF NOT EXISTS` keeps the batch
    /// idempotent on re-run after a clean rollback.
    pub async fn migrate(&self) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            Self::with_transaction(&conn, |c| {
                c.execute_batch(include_str!("../../../migrations/001_initial.sql"))
                    .map_err(|e| StorageError::Duckdb(e.to_string()))?;
                tracing::info!("duckdb migration complete");
                Ok(())
            })
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    /// Map a `duckdb::Error` into the appropriate `StorageError`. Constraint
    /// violations surface as `Conflict` so callers can return 409; everything
    /// else becomes `Duckdb`.
    fn map_err(err: duckdb::Error) -> StorageError {
        let msg = err.to_string();
        if msg.contains("PRIMARY KEY") || msg.contains("UNIQUE") || msg.contains("Constraint") {
            StorageError::Conflict(msg)
        } else {
            StorageError::Duckdb(msg)
        }
    }

    /// Produce an owned clone cheap to move into a `spawn_blocking` closure:
    /// bumps only the `Arc` refcounts on `conn` and `cipher`, no DB
    /// connection duplication. Synchronous DuckDB I/O is offloaded to a
    /// blocking thread so the tokio runtime worker stays non-blocking.
    fn blocking_clone(&self) -> Self {
        Self { conn: self.conn.clone(), cipher: self.cipher.clone() }
    }

    /// Run a multi-statement operation inside a single DuckDB transaction.
    /// `BEGIN TRANSACTION` is issued before `f` runs; `COMMIT` on `Ok`, and a
    /// best-effort `ROLLBACK` on `Err` (rollback errors are swallowed so the
    /// original error surfaces). The closure receives the same `&Connection`
    /// the caller already holds the lock on, so no second lock acquisition is
    /// needed and the guard stays valid for the whole transaction.
    fn with_transaction<T, F>(conn: &Connection, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        conn.execute_batch("BEGIN TRANSACTION").map_err(Self::map_err)?;
        match f(conn) {
            Ok(v) => {
                conn.execute_batch("COMMIT").map_err(Self::map_err)?;
                Ok(v)
            }
            Err(e) => {
                // Best-effort rollback; swallow the rollback error so the
                // original failure surfaces unchanged.
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }
}

#[async_trait]
impl Storage for DuckdbStorage {
    async fn list_targets(&self) -> Result<Vec<Target>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<Target>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare("SELECT payload FROM targets ORDER BY created_at")
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map([], |row| {
                    let s: String = row.get(0)?;
                    Ok(s)
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let s = r.map_err(Self::map_err)?;
                let t: Target =
                    serde_json::from_str(&s).map_err(|e| StorageError::Duckdb(e.to_string()))?;
                out.push(t);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn get_target(&self, id: Uuid) -> Result<Target> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Target> {
            let conn = this.conn.lock();
            let mut stmt =
                conn.prepare("SELECT payload FROM targets WHERE id = ?").map_err(Self::map_err)?;
            let s: Option<String> = stmt
                .query_row(params![id], |row| row.get::<_, String>(0))
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            match s {
                None => Err(StorageError::NotFound(format!("target {id}")).into()),
                Some(json) => {
                    let t: Target = serde_json::from_str(&json)
                        .map_err(|e| StorageError::Duckdb(e.to_string()))?;
                    Ok(t)
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn create_target(&self, target: &Target) -> Result<Target> {
        let target = target.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Target> {
            let conn = this.conn.lock();
            let payload =
                serde_json::to_string(&target).map_err(|e| StorageError::Duckdb(e.to_string()))?;
            let res = conn.execute(
                "INSERT INTO targets (id, name, enabled, payload, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    target.id,
                    &target.name,
                    target.enabled,
                    &payload,
                    target.created_at,
                    target.updated_at,
                ],
            );
            match res {
                Ok(_) => Ok(target),
                Err(e) => {
                    let mapped = Self::map_err(e);
                    if matches!(mapped, StorageError::Conflict(_)) {
                        Err(StorageError::Conflict(format!("target {} exists", target.id)).into())
                    } else {
                        Err(mapped.into())
                    }
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn update_target(&self, target: &Target) -> Result<Target> {
        let target = target.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Target> {
            let conn = this.conn.lock();
            let exists: i64 = conn
                .query_row("SELECT 1 FROM targets WHERE id = ?", params![target.id], |row| {
                    row.get(0)
                })
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(0),
                    other => Err(Self::map_err(other)),
                })?;
            if exists == 0 {
                return Err(StorageError::NotFound(format!("target {}", target.id)).into());
            }
            let payload =
                serde_json::to_string(&target).map_err(|e| StorageError::Duckdb(e.to_string()))?;
            conn.execute(
                "UPDATE targets SET name = ?, enabled = ?, payload = ?, updated_at = ? WHERE id = ?",
                params![&target.name, target.enabled, &payload, target.updated_at, target.id,],
            )
            .map_err(Self::map_err)?;
            Ok(target)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_target(&self, id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            let affected = conn
                .execute("DELETE FROM targets WHERE id = ?", params![id])
                .map_err(Self::map_err)?;
            if affected == 0 {
                Err(StorageError::NotFound(format!("target {id}")).into())
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn record_result(&self, result: &CheckResult) -> Result<()> {
        let result = result.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            let payload =
                serde_json::to_string(&result).map_err(|e| StorageError::Duckdb(e.to_string()))?;
            // INSERT OR REPLACE so a re-recorded (target_id, timestamp) overwrites
            // the prior row instead of raising a PRIMARY KEY conflict.
            conn.execute(
                "INSERT OR REPLACE INTO check_results \
                 (target_id, org_id, timestamp, status, duration_ms, payload) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    result.target_id,
                    result.org_id.0,
                    result.timestamp,
                    result.status.as_str(),
                    result.duration_ms as i32,
                    &payload,
                ],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn list_results(&self, target_id: Uuid, limit: u32) -> Result<Vec<CheckResult>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<CheckResult>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT payload FROM check_results \
                     WHERE target_id = ? ORDER BY timestamp DESC LIMIT ?",
                )
                .map_err(Self::map_err)?;
            let limit_i64 = i64::from(limit);
            let rows = stmt
                .query_map(params![target_id, limit_i64], |row| {
                    let s: String = row.get(0)?;
                    Ok(s)
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let s = r.map_err(Self::map_err)?;
                let cr: CheckResult =
                    serde_json::from_str(&s).map_err(|e| StorageError::Duckdb(e.to_string()))?;
                out.push(cr);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn list_incidents(&self) -> Result<Vec<Incident>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<Incident>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare("SELECT payload FROM incidents ORDER BY started_at DESC LIMIT 200")
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map([], |row| {
                    let s: String = row.get(0)?;
                    Ok(s)
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let s = r.map_err(Self::map_err)?;
                let i: Incident =
                    serde_json::from_str(&s).map_err(|e| StorageError::Duckdb(e.to_string()))?;
                out.push(i);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn create_incident(&self, incident: &Incident) -> Result<Incident> {
        let incident = incident.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Incident> {
            let conn = this.conn.lock();
            let payload = serde_json::to_string(&incident)
                .map_err(|e| StorageError::Duckdb(e.to_string()))?;
            let res = conn.execute(
                "INSERT INTO incidents \
                 (id, target_id, started_at, ended_at, severity, payload, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    incident.id,
                    incident.target_id,
                    incident.started_at,
                    incident.ended_at,
                    incident.severity.as_db_str(),
                    &payload,
                    incident.created_at,
                ],
            );
            match res {
                Ok(_) => Ok(incident),
                Err(e) => {
                    let mapped = Self::map_err(e);
                    if matches!(mapped, StorageError::Conflict(_)) {
                        Err(StorageError::Conflict(format!("incident {} exists", incident.id))
                            .into())
                    } else {
                        Err(mapped.into())
                    }
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn list_status_pages(&self) -> Result<Vec<StatusPage>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<StatusPage>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare("SELECT payload, org_id FROM status_pages ORDER BY created_at")
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map([], |row| {
                    let payload: String = row.get(0)?;
                    let org_id: Uuid = row.get(1)?;
                    Ok((payload, org_id))
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let (json, org_id) = r.map_err(Self::map_err)?;
                let mut sp: StatusPage =
                    serde_json::from_str(&json).map_err(|e| StorageError::Duckdb(e.to_string()))?;
                sp.org_id = statuscore::domain::OrgId(org_id);
                out.push(sp);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn get_status_page(&self, id: Uuid) -> Result<StatusPage> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<StatusPage> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare("SELECT payload, org_id FROM status_pages WHERE id = ?")
                .map_err(Self::map_err)?;
            let row_opt: Option<(String, Uuid)> = stmt
                .query_row(params![id], |row| {
                    let payload: String = row.get(0)?;
                    let org_id: Uuid = row.get(1)?;
                    Ok((payload, org_id))
                })
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            match row_opt {
                None => Err(StorageError::NotFound(format!("status page {id}")).into()),
                Some((json, org_id)) => {
                    let mut sp: StatusPage = serde_json::from_str(&json)
                        .map_err(|e| StorageError::Duckdb(e.to_string()))?;
                    sp.org_id = statuscore::domain::OrgId(org_id);
                    Ok(sp)
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn create_status_page(&self, page: &StatusPage) -> Result<StatusPage> {
        let page = page.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<StatusPage> {
            let conn = this.conn.lock();
            let payload =
                serde_json::to_string(&page).map_err(|e| StorageError::Duckdb(e.to_string()))?;
            let res = conn.execute(
                "INSERT INTO status_pages \
                 (id, org_id, slug, name, enabled, payload, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    page.id.0,
                    page.org_id.0,
                    &page.slug,
                    &page.name,
                    page.enabled,
                    &payload,
                    page.created_at,
                    page.updated_at,
                ],
            );
            match res {
                Ok(_) => Ok(page),
                Err(e) => {
                    let mapped = Self::map_err(e);
                    if matches!(mapped, StorageError::Conflict(_)) {
                        Err(StorageError::Conflict(format!("status page {} exists", page.id.0))
                            .into())
                    } else {
                        Err(mapped.into())
                    }
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn update_status_page(&self, page: &StatusPage) -> Result<StatusPage> {
        let page = page.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<StatusPage> {
            let conn = this.conn.lock();
            let exists: i64 = conn
                .query_row("SELECT 1 FROM status_pages WHERE id = ?", params![page.id.0], |row| {
                    row.get(0)
                })
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(0),
                    other => Err(Self::map_err(other)),
                })?;
            if exists == 0 {
                return Err(StorageError::NotFound(format!("status page {}", page.id.0)).into());
            }
            let payload =
                serde_json::to_string(&page).map_err(|e| StorageError::Duckdb(e.to_string()))?;
            conn.execute(
                "UPDATE status_pages SET org_id = ?, slug = ?, name = ?, enabled = ?, payload = ?, \
                 updated_at = ? WHERE id = ?",
                params![
                    page.org_id.0,
                    &page.slug,
                    &page.name,
                    page.enabled,
                    &payload,
                    page.updated_at,
                    page.id.0,
                ],
            )
            .map_err(Self::map_err)?;
            Ok(page)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_status_page(&self, id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            let affected = conn
                .execute("DELETE FROM status_pages WHERE id = ?", params![id])
                .map_err(Self::map_err)?;
            if affected == 0 {
                Err(StorageError::NotFound(format!("status page {id}")).into())
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn list_recent_results(&self, limit: u32) -> Result<Vec<CheckResult>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<CheckResult>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare("SELECT payload FROM check_results ORDER BY timestamp DESC LIMIT ?")
                .map_err(Self::map_err)?;
            let limit_i64 = i64::from(limit);
            let rows = stmt
                .query_map(params![limit_i64], |row| {
                    let s: String = row.get(0)?;
                    Ok(s)
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let s = r.map_err(Self::map_err)?;
                let cr: CheckResult =
                    serde_json::from_str(&s).map_err(|e| StorageError::Duckdb(e.to_string()))?;
                out.push(cr);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn get_incident(&self, id: Uuid) -> Result<Incident> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Incident> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare("SELECT payload FROM incidents WHERE id = ?")
                .map_err(Self::map_err)?;
            let s: Option<String> = stmt
                .query_row(params![id], |row| row.get::<_, String>(0))
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            match s {
                None => Err(StorageError::NotFound(format!("incident {id}")).into()),
                Some(json) => {
                    let i: Incident = serde_json::from_str(&json)
                        .map_err(|e| StorageError::Duckdb(e.to_string()))?;
                    Ok(i)
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn update_incident(&self, incident: &Incident) -> Result<Incident> {
        let incident = incident.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Incident> {
            let conn = this.conn.lock();
            let exists: i64 = conn
                .query_row("SELECT 1 FROM incidents WHERE id = ?", params![incident.id], |row| {
                    row.get(0)
                })
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(0),
                    other => Err(Self::map_err(other)),
                })?;
            if exists == 0 {
                return Err(StorageError::NotFound(format!("incident {}", incident.id)).into());
            }
            let payload = serde_json::to_string(&incident)
                .map_err(|e| StorageError::Duckdb(e.to_string()))?;
            conn.execute(
                "UPDATE incidents SET target_id = ?, started_at = ?, ended_at = ?, severity = ?, \
                 payload = ?, created_at = ? WHERE id = ?",
                params![
                    incident.target_id,
                    incident.started_at,
                    incident.ended_at,
                    incident.severity.as_db_str(),
                    &payload,
                    incident.created_at,
                    incident.id,
                ],
            )
            .map_err(Self::map_err)?;
            Ok(incident)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn add_incident_update(
        &self,
        incident_id: Uuid,
        update: &PublicIncidentUpdate,
    ) -> Result<Incident> {
        let mut incident = self.get_incident(incident_id).await?;
        incident.updates.push(update.clone());
        self.update_incident(&incident).await
    }

    async fn find_open_incident_for_target(&self, target_id: Uuid) -> Result<Option<Incident>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Option<Incident>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT payload FROM incidents \
                     WHERE target_id = ? AND ended_at IS NULL \
                     ORDER BY started_at DESC LIMIT 1",
                )
                .map_err(Self::map_err)?;
            let s: Option<String> = stmt
                .query_row(params![target_id], |row| row.get::<_, String>(0))
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            match s {
                None => Ok(None),
                Some(json) => {
                    let i: Incident = serde_json::from_str(&json)
                        .map_err(|e| StorageError::Duckdb(e.to_string()))?;
                    Ok(Some(i))
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Status page components ───────────────────────────────────────────

    async fn list_status_page_components(
        &self,
        status_page_id: Uuid,
    ) -> Result<Vec<StatusPageComponent>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<StatusPageComponent>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT payload FROM status_page_components \
                     WHERE status_page_id = ? \
                     ORDER BY sort_order ASC, monitor_name ASC",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(params![status_page_id], |row| {
                    let s: String = row.get(0)?;
                    Ok(s)
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let s = r.map_err(Self::map_err)?;
                let c: StatusPageComponent =
                    serde_json::from_str(&s).map_err(|e| StorageError::Duckdb(e.to_string()))?;
                out.push(c);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn set_status_page_component(
        &self,
        status_page_id: Uuid,
        component: &StatusPageComponent,
    ) -> Result<()> {
        let component = component.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            let payload = serde_json::to_string(&component)
                .map_err(|e| StorageError::Duckdb(e.to_string()))?;
            conn.execute(
                "INSERT OR REPLACE INTO status_page_components \
                 (status_page_id, target_id, sort_order, monitor_name, payload) \
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    status_page_id,
                    component.target_id,
                    component.sort_order,
                    component.monitor_name,
                    &payload,
                ],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_status_page_component(
        &self,
        status_page_id: Uuid,
        target_id: Uuid,
    ) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute(
                "DELETE FROM status_page_components \
                 WHERE status_page_id = ? AND target_id = ?",
                params![status_page_id, target_id],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn reorder_status_page_components(
        &self,
        status_page_id: Uuid,
        ordered_target_ids: &[Uuid],
    ) -> Result<()> {
        // DuckDB has no positional `UPDATE ... SET sort_order = ? WHERE
        // (page, target) = (?, ?)` loop primitive, so we issue one prepared
        // statement per id. Page bindings are small (tens at most), so the
        // N small writes inside one transaction are cheap and atomic from the
        // caller's perspective. Wrapped in `BEGIN … COMMIT` so a failure
        // midway (e.g. a DB error) rolls back every prior sort_order change
        // instead of leaving the page in a half-reordered state.
        let ordered: Vec<Uuid> = ordered_target_ids.to_vec();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            Self::with_transaction(&conn, |conn| {
                let mut stmt = conn
                    .prepare(
                        "UPDATE status_page_components \
                         SET sort_order = ? \
                         WHERE status_page_id = ? AND target_id = ?",
                    )
                    .map_err(Self::map_err)?;
                for (i, target_id) in ordered.iter().enumerate() {
                    stmt.execute(params![i as i32, status_page_id, target_id])
                        .map_err(Self::map_err)?;
                }
                Ok(())
            })
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Page assets ──────────────────────────────────────────────────────

    async fn upload_page_asset(
        &self,
        status_page_id: Uuid,
        slot: AssetSlot,
        content_type: &str,
        data: &[u8],
    ) -> Result<PageAsset> {
        let content_type = content_type.to_string();
        let data = data.to_vec();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<PageAsset> {
            let conn = this.conn.lock();
            let now = Utc::now();
            let slot_str = slot.as_str();
            let hash = {
                use sha2::{Digest, Sha256};
                let digest = Sha256::digest(&data);
                hex::encode(digest)
            };
            let existing_created: Option<DateTime<Utc>> = conn
                .query_row(
                    "SELECT created_at FROM page_assets \
                     WHERE status_page_id = ? AND slot = ?",
                    params![status_page_id, slot_str],
                    |row| row.get::<_, DateTime<Utc>>(0),
                )
                .ok();
            let created_at = existing_created.unwrap_or(now);
            conn.execute(
                "INSERT OR REPLACE INTO page_assets \
                 (status_page_id, slot, content_type, data, hash, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![status_page_id, slot_str, &content_type, &data, &hash, created_at, now],
            )
            .map_err(Self::map_err)?;
            Ok(PageAsset {
                status_page_id,
                slot,
                content_type,
                data,
                hash,
                created_at,
                updated_at: now,
            })
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn get_page_asset(
        &self,
        status_page_id: Uuid,
        slot: AssetSlot,
    ) -> Result<Option<PageAsset>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Option<PageAsset>> {
            let conn = this.conn.lock();
            let row = conn
                .query_row(
                    "SELECT content_type, data, hash, created_at, updated_at \
                     FROM page_assets \
                     WHERE status_page_id = ? AND slot = ?",
                    params![status_page_id, slot.as_str()],
                    |row| {
                        let data: Vec<u8> = row.get(1)?;
                        Ok((
                            row.get::<_, String>(0)?,
                            data,
                            row.get::<_, String>(2)?,
                            row.get::<_, DateTime<Utc>>(3)?,
                            row.get::<_, DateTime<Utc>>(4)?,
                        ))
                    },
                )
                .ok();
            match row {
                Some((content_type, data, hash, created_at, updated_at)) => Ok(Some(PageAsset {
                    status_page_id,
                    slot,
                    content_type,
                    data,
                    hash,
                    created_at,
                    updated_at,
                })),
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_page_asset(&self, status_page_id: Uuid, slot: AssetSlot) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute(
                "DELETE FROM page_assets WHERE status_page_id = ? AND slot = ?",
                params![status_page_id, slot.as_str()],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn list_page_assets(&self, status_page_id: Uuid) -> Result<Vec<PageAsset>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<PageAsset>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT slot, content_type, data, hash, created_at, updated_at \
                     FROM page_assets WHERE status_page_id = ? ORDER BY slot ASC",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(params![status_page_id], |row| {
                    let slot_str: String = row.get(0)?;
                    let content_type: String = row.get(1)?;
                    let data: Vec<u8> = row.get(2)?;
                    let hash: String = row.get(3)?;
                    let created_at: DateTime<Utc> = row.get(4)?;
                    let updated_at: DateTime<Utc> = row.get(5)?;
                    Ok((slot_str, content_type, data, hash, created_at, updated_at))
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let (slot_str, content_type, data, hash, created_at, updated_at) =
                    r.map_err(Self::map_err)?;
                let slot = AssetSlot::parse(&slot_str).ok_or_else(|| {
                    StorageError::Duckdb(format!(
                        "unknown asset slot `{slot_str}` in page_assets for page {status_page_id}"
                    ))
                })?;
                out.push(PageAsset {
                    status_page_id,
                    slot,
                    content_type,
                    data,
                    hash,
                    created_at,
                    updated_at,
                });
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Heartbeat pings ──────────────────────────────────────────────────

    async fn record_heartbeat_ping(&self, target_id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            let now = Utc::now();
            conn.execute(
                "INSERT OR REPLACE INTO heartbeat_pings (target_id, last_ping_at) VALUES (?, ?)",
                params![target_id, now],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn get_last_heartbeat_ping(&self, target_id: Uuid) -> Result<Option<DateTime<Utc>>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Option<DateTime<Utc>>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare("SELECT last_ping_at FROM heartbeat_pings WHERE target_id = ?")
                .map_err(Self::map_err)?;
            let ts: Option<DateTime<Utc>> = stmt
                .query_row(params![target_id], |row| row.get::<_, DateTime<Utc>>(0))
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            Ok(ts)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Maintenance windows ──────────────────────────────────────────────

    async fn list_maintenance_windows(
        &self,
        filter: MaintenanceFilter,
    ) -> Result<Vec<MaintenanceWindow>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<MaintenanceWindow>> {
            let conn = this.conn.lock();
            let now = Utc::now();
            let (sql, param_vec): (&str, Vec<&dyn duckdb::ToSql>) = match filter {
                MaintenanceFilter::Active => (
                    "SELECT payload FROM maintenance_windows \
                     WHERE starts_at <= ? AND ends_at > ? \
                     ORDER BY starts_at ASC",
                    vec![&now, &now],
                ),
                MaintenanceFilter::Upcoming => (
                    "SELECT payload FROM maintenance_windows \
                     WHERE starts_at > ? \
                     ORDER BY starts_at ASC",
                    vec![&now],
                ),
                MaintenanceFilter::Past => (
                    "SELECT payload FROM maintenance_windows \
                     WHERE ends_at <= ? \
                     ORDER BY ends_at DESC",
                    vec![&now],
                ),
                MaintenanceFilter::All => {
                    ("SELECT payload FROM maintenance_windows ORDER BY starts_at DESC", Vec::new())
                }
                // MaintenanceFilter is #[non_exhaustive]; unknown future
                // variants fall back to the unfiltered listing.
                _ => {
                    ("SELECT payload FROM maintenance_windows ORDER BY starts_at DESC", Vec::new())
                }
            };
            let mut stmt = conn.prepare(sql).map_err(Self::map_err)?;
            let rows = stmt
                .query_map(param_vec.as_slice(), |row| row.get::<_, String>(0))
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let s = r.map_err(Self::map_err)?;
                let w: MaintenanceWindow =
                    serde_json::from_str(&s).map_err(|e| StorageError::Duckdb(e.to_string()))?;
                out.push(w);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn get_maintenance_window(&self, id: Uuid) -> Result<MaintenanceWindow> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<MaintenanceWindow> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare("SELECT payload FROM maintenance_windows WHERE id = ?")
                .map_err(Self::map_err)?;
            let s: Option<String> = stmt
                .query_row(params![id], |row| row.get::<_, String>(0))
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            match s {
                None => Err(StorageError::NotFound(format!("maintenance window {id}")).into()),
                Some(json) => {
                    let w: MaintenanceWindow = serde_json::from_str(&json)
                        .map_err(|e| StorageError::Duckdb(e.to_string()))?;
                    Ok(w)
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn create_maintenance_window(
        &self,
        window: &MaintenanceWindow,
    ) -> Result<MaintenanceWindow> {
        let window = window.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<MaintenanceWindow> {
            let conn = this.conn.lock();
            let payload =
                serde_json::to_string(&window).map_err(|e| StorageError::Duckdb(e.to_string()))?;
            let res = conn.execute(
                "INSERT INTO maintenance_windows \
                 (id, title, starts_at, ends_at, payload, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    window.id,
                    &window.title,
                    window.starts_at,
                    window.ends_at,
                    &payload,
                    window.created_at,
                    window.updated_at,
                ],
            );
            match res {
                Ok(_) => Ok(window),
                Err(e) => {
                    let mapped = Self::map_err(e);
                    if matches!(mapped, StorageError::Conflict(_)) {
                        Err(StorageError::Conflict(format!(
                            "maintenance window {} exists",
                            window.id
                        ))
                        .into())
                    } else {
                        Err(mapped.into())
                    }
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn update_maintenance_window(
        &self,
        window: &MaintenanceWindow,
    ) -> Result<MaintenanceWindow> {
        let window = window.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<MaintenanceWindow> {
            let conn = this.conn.lock();
            let exists: i64 = conn
                .query_row(
                    "SELECT 1 FROM maintenance_windows WHERE id = ?",
                    params![window.id],
                    |row| row.get(0),
                )
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(0),
                    other => Err(Self::map_err(other)),
                })?;
            if exists == 0 {
                return Err(
                    StorageError::NotFound(format!("maintenance window {}", window.id)).into()
                );
            }
            let payload =
                serde_json::to_string(&window).map_err(|e| StorageError::Duckdb(e.to_string()))?;
            conn.execute(
                "UPDATE maintenance_windows SET title = ?, starts_at = ?, ends_at = ?, \
                 payload = ?, updated_at = ? WHERE id = ?",
                params![
                    &window.title,
                    window.starts_at,
                    window.ends_at,
                    &payload,
                    window.updated_at,
                    window.id,
                ],
            )
            .map_err(Self::map_err)?;
            Ok(window)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_maintenance_window(&self, id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            let affected = conn
                .execute("DELETE FROM maintenance_windows WHERE id = ?", params![id])
                .map_err(Self::map_err)?;
            if affected == 0 {
                Err(StorageError::NotFound(format!("maintenance window {id}")).into())
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn is_target_in_active_maintenance(&self, target_id: Uuid) -> Result<bool> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<bool> {
            let conn = this.conn.lock();
            let now = Utc::now();
            let mut stmt = conn
                .prepare(
                    "SELECT COUNT(*) FROM maintenance_windows \
                     WHERE starts_at <= ? AND ends_at > ? \
                     AND array_contains(payload->'$.component_ids', ?)",
                )
                .map_err(Self::map_err)?;
            let count: i64 = stmt
                .query_row(params![now, now, target_id], |row| row.get(0))
                .map_err(Self::map_err)?;
            Ok(count > 0)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Silence rules ───────────────────────────────────────────────────

    async fn list_silence_rules(&self, filter: SilenceFilter) -> Result<Vec<SilenceRule>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<SilenceRule>> {
            let conn = this.conn.lock();
            let now = Utc::now();
            let sql = match filter {
                SilenceFilter::Active => {
                    "SELECT payload FROM silence_rules \
                     WHERE starts_at <= ? AND ends_at > ? \
                     ORDER BY starts_at ASC"
                }
                SilenceFilter::Upcoming => {
                    "SELECT payload FROM silence_rules \
                     WHERE starts_at > ? \
                     ORDER BY starts_at ASC"
                }
                SilenceFilter::Past => {
                    "SELECT payload FROM silence_rules \
                     WHERE ends_at <= ? \
                     ORDER BY ends_at DESC"
                }
                SilenceFilter::All => "SELECT payload FROM silence_rules ORDER BY starts_at DESC",
                // `SilenceFilter` is `#[non_exhaustive]`: a future variant
                // falls through to the unfiltered listing (same as `All`).
                _ => "SELECT payload FROM silence_rules ORDER BY starts_at DESC",
            };
            let mut stmt = conn.prepare(sql).map_err(Self::map_err)?;
            let param_vec: Vec<&dyn duckdb::ToSql> = match filter {
                SilenceFilter::All => Vec::new(),
                _ => vec![&now, &now],
            };
            let rows = stmt
                .query_map(param_vec.as_slice(), |row| row.get::<_, String>(0))
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let s = r.map_err(Self::map_err)?;
                let rule: SilenceRule =
                    serde_json::from_str(&s).map_err(|e| StorageError::Duckdb(e.to_string()))?;
                out.push(rule);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn get_silence_rule(&self, id: Uuid) -> Result<SilenceRule> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<SilenceRule> {
            let conn = this.conn.lock();
            let s: Option<String> = conn
                .query_row("SELECT payload FROM silence_rules WHERE id = ?", params![id], |row| {
                    row.get::<_, String>(0)
                })
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            match s {
                None => Err(StorageError::NotFound(format!("silence rule {id}")).into()),
                Some(json) => {
                    let rule: SilenceRule = serde_json::from_str(&json)
                        .map_err(|e| StorageError::Duckdb(e.to_string()))?;
                    Ok(rule)
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn create_silence_rule(&self, new_rule: &NewSilenceRule) -> Result<SilenceRule> {
        let new_rule = new_rule.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<SilenceRule> {
            let conn = this.conn.lock();
            let now = Utc::now();
            let id = Uuid::new_v4();
            let rule = SilenceRule {
                id,
                title: new_rule.title.clone(),
                description: new_rule.description.clone(),
                target_id: new_rule.target_id,
                channel_id: new_rule.channel_id,
                reasons: new_rule.reasons.clone(),
                starts_at: new_rule.starts_at,
                ends_at: new_rule.ends_at,
                created_at: now,
                updated_at: now,
                write_source: WriteSource::Ui,
            };
            let payload =
                serde_json::to_string(&rule).map_err(|e| StorageError::Duckdb(e.to_string()))?;
            let res = conn.execute(
                "INSERT INTO silence_rules \
                 (id, title, target_id, channel_id, starts_at, ends_at, payload, \
                 created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    rule.id,
                    &rule.title,
                    rule.target_id,
                    rule.channel_id,
                    rule.starts_at,
                    rule.ends_at,
                    &payload,
                    rule.created_at,
                    rule.updated_at,
                ],
            );
            match res {
                Ok(_) => Ok(rule),
                Err(e) => {
                    let mapped = Self::map_err(e);
                    if matches!(mapped, StorageError::Conflict(_)) {
                        Err(StorageError::Conflict(format!("silence rule {id} exists")).into())
                    } else {
                        Err(mapped.into())
                    }
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn update_silence_rule(
        &self,
        id: Uuid,
        update: &SilenceRuleUpdate,
    ) -> Result<SilenceRule> {
        // Load-then-write: read the existing rule, validate the post-patch
        // time window BEFORE mutating any field, then apply the patch and
        // write once. Validating first means a rejected patch leaves the
        // stored rule untouched. Runs on a blocking thread so the synchronous
        // DuckDB I/O does not stall the tokio worker.
        let this = self.blocking_clone();
        let update = update.clone();
        tokio::task::spawn_blocking(move || -> Result<SilenceRule> {
            let conn = this.conn.lock();
            let existing_json: Option<String> = conn
                .query_row("SELECT payload FROM silence_rules WHERE id = ?", params![id], |row| {
                    row.get::<_, String>(0)
                })
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            let Some(json) = existing_json else {
                return Err(not_found("silence rule", id).into());
            };
            let mut rule: SilenceRule =
                serde_json::from_str(&json).map_err(|e| StorageError::Duckdb(e.to_string()))?;

            // Validate the post-patch time window before applying any change.
            // `starts_at >= ends_at` is a 400 input error (the rule is fine,
            // the request is not), not a 409 conflict.
            let new_starts_at = update.starts_at.unwrap_or(rule.starts_at);
            let new_ends_at = update.ends_at.unwrap_or(rule.ends_at);
            if new_starts_at >= new_ends_at {
                return Err(StorageError::InvalidInput(
                    "silence rule: starts_at must be before ends_at".into(),
                )
                .into());
            }

            if let Some(title) = &update.title {
                rule.title.clone_from(title);
            }
            if let Some(description) = &update.description {
                rule.description = Some(description.clone());
            }
            if let Some(target_id) = update.target_id {
                rule.target_id = target_id;
            }
            if let Some(channel_id) = update.channel_id {
                rule.channel_id = channel_id;
            }
            if let Some(reasons) = &update.reasons {
                rule.reasons.clone_from(reasons);
            }
            rule.starts_at = new_starts_at;
            rule.ends_at = new_ends_at;
            rule.updated_at = Utc::now();
            let payload =
                serde_json::to_string(&rule).map_err(|e| StorageError::Duckdb(e.to_string()))?;
            conn.execute(
                "UPDATE silence_rules SET title = ?, target_id = ?, channel_id = ?, \
                 starts_at = ?, ends_at = ?, payload = ?, updated_at = ? WHERE id = ?",
                params![
                    &rule.title,
                    rule.target_id,
                    rule.channel_id,
                    rule.starts_at,
                    rule.ends_at,
                    &payload,
                    rule.updated_at,
                    id,
                ],
            )
            .map_err(Self::map_err)?;
            Ok(rule)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_silence_rule(&self, id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            let affected = conn
                .execute("DELETE FROM silence_rules WHERE id = ?", params![id])
                .map_err(Self::map_err)?;
            if affected == 0 {
                Err(StorageError::NotFound(format!("silence rule {id}")).into())
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn list_active_silences_for_target(&self, target_id: Uuid) -> Result<Vec<SilenceRule>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<SilenceRule>> {
            let conn = this.conn.lock();
            let now = Utc::now();
            let mut stmt = conn
                .prepare(
                    "SELECT payload FROM silence_rules \
                     WHERE starts_at <= ? AND ends_at > ? \
                     AND (target_id IS NULL OR target_id = ?) \
                     ORDER BY starts_at ASC",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(params![now, now, target_id], |row| row.get::<_, String>(0))
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let s = r.map_err(Self::map_err)?;
                let rule: SilenceRule =
                    serde_json::from_str(&s).map_err(|e| StorageError::Duckdb(e.to_string()))?;
                out.push(rule);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Subscribers ──────────────────────────────────────────────────────

    async fn list_subscribers(&self, status_page_id: Uuid) -> Result<Vec<Subscriber>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<Subscriber>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT id, status_page_id, org_id, channel, target, config, \
                     verified_at, created_at, updated_at \
                     FROM subscribers WHERE status_page_id = ? \
                     ORDER BY created_at ASC",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(params![status_page_id], |row| {
                    let config_str: String = row.get(5)?;
                    Ok(SubRow {
                        id: row.get(0)?,
                        status_page_id: row.get(1)?,
                        org_id: row.get(2)?,
                        channel: row.get(3)?,
                        target: row.get(4)?,
                        config_str,
                        verified_at: row.get(6)?,
                        created_at: row.get(7)?,
                        updated_at: row.get(8)?,
                    })
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let row = r.map_err(Self::map_err)?;
                out.push(map_subscriber_row(row)?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn create_subscriber(&self, subscriber: &Subscriber) -> Result<Subscriber> {
        let this = self.blocking_clone();
        let subscriber = subscriber.clone();
        tokio::task::spawn_blocking(move || -> Result<Subscriber> {
            let conn = this.conn.lock();
            let config_str = serde_json::to_string(&subscriber.config)
                .map_err(|e| StorageError::Duckdb(e.to_string()))?;
            let res = conn.execute(
                "INSERT INTO subscribers \
                 (id, status_page_id, org_id, channel, target, config, verified_at, \
                  created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    subscriber.id,
                    subscriber.status_page_id,
                    subscriber.org_id.0,
                    subscriber.channel.as_db_str(),
                    &subscriber.target,
                    &config_str,
                    subscriber.verified_at,
                    subscriber.created_at,
                    subscriber.updated_at,
                ],
            );
            match res {
                Ok(_) => Ok(subscriber),
                Err(e) => {
                    let mapped = Self::map_err(e);
                    if matches!(mapped, StorageError::Conflict(_)) {
                        Err(StorageError::Conflict(format!("subscriber {} exists", subscriber.id))
                            .into())
                    } else {
                        Err(mapped.into())
                    }
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn verify_subscriber(&self, id: Uuid) -> Result<Subscriber> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Subscriber> {
            let conn = this.conn.lock();
            // Single-statement read-then-write via `UPDATE ... RETURNING`:
            // one transaction, no second lock acquisition, no race window
            // between marking verified and re-reading the row. Returns 0 rows
            // (None) when the subscriber id does not exist.
            let now = Utc::now();
            let mut stmt = conn
                .prepare(
                    "UPDATE subscribers SET verified_at = ?, updated_at = ? \
                     WHERE id = ? \
                     RETURNING id, status_page_id, org_id, channel, target, config, \
                     verified_at, created_at, updated_at",
                )
                .map_err(Self::map_err)?;
            let row = stmt
                .query_row(params![now, now, id], |row| {
                    let config_str: String = row.get(5)?;
                    Ok(SubRow {
                        id: row.get(0)?,
                        status_page_id: row.get(1)?,
                        org_id: row.get(2)?,
                        channel: row.get(3)?,
                        target: row.get(4)?,
                        config_str,
                        verified_at: row.get(6)?,
                        created_at: row.get(7)?,
                        updated_at: row.get(8)?,
                    })
                })
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            match row {
                None => Err(not_found("subscriber", id).into()),
                Some(row) => map_subscriber_row(row),
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_subscriber(&self, id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            let affected = conn
                .execute("DELETE FROM subscribers WHERE id = ?", params![id])
                .map_err(Self::map_err)?;
            if affected == 0 { Err(not_found("subscriber", id).into()) } else { Ok(()) }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Variables ────────────────────────────────────────────────────────

    async fn list_variables(&self) -> Result<Vec<Variable>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<Variable>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare("SELECT id, key, is_secret, value, updated_at FROM variables ORDER BY key")
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(VarRow {
                        id: row.get(0)?,
                        key: row.get(1)?,
                        is_secret: row.get(2)?,
                        value: row.get(3)?,
                        updated_at: row.get(4)?,
                    })
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let row = r.map_err(Self::map_err)?;
                // Secrets are redacted on read: `value` becomes `None`. The
                // cleartext is only consumed by the interpolation resolver,
                // which reads via a dedicated path (future work).
                let value = if row.is_secret { None } else { Some(row.value) };
                out.push(Variable {
                    id: VariableId(row.id),
                    org_id: statuscore::domain::OrgId(Uuid::nil()),
                    key: row.key,
                    is_secret: row.is_secret,
                    value,
                    updated_at: row.updated_at,
                    updated_by: None,
                });
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn create_variable(&self, variable: &Variable) -> Result<Variable> {
        let this = self.blocking_clone();
        let variable = variable.clone();
        tokio::task::spawn_blocking(move || -> Result<Variable> {
            let conn = this.conn.lock();
            // `value` is `Option<String>` on the domain type (None for secrets),
            // but the storage column is NOT NULL. We store the empty string for
            // a secret whose cleartext was never set; the create path always
            // carries a cleartext value via `NewVariable`.
            // Secrets are sealed with the KEK at the DB edge so the at-rest value
            // is an envelope, not plaintext. The list path returns `None` for
            // secrets; the interpolation resolver (future work) opens them.
            let cleartext = variable.value.clone().unwrap_or_default();
            let stored_value =
                if variable.is_secret { this.seal_config(&cleartext)? } else { cleartext };
            let res = conn.execute(
                "INSERT INTO variables (id, key, is_secret, value, updated_at) VALUES (?, ?, ?, ?, ?)",
                params![
                    variable.id.0,
                    &variable.key,
                    variable.is_secret,
                    &stored_value,
                    variable.updated_at,
                ],
            );
            match res {
                Ok(_) => {
                    // Re-read with redaction applied so the caller sees the
                    // canonical view (secret → value: None).
                    let mut out = variable.clone();
                    if variable.is_secret {
                        out.value = None;
                    }
                    Ok(out)
                }
                Err(e) => {
                    let mapped = Self::map_err(e);
                    if matches!(mapped, StorageError::Conflict(_)) {
                        Err(StorageError::Conflict(format!("variable key '{}' exists", variable.key))
                            .into())
                    } else {
                        Err(mapped.into())
                    }
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn update_variable(&self, variable: &Variable) -> Result<Variable> {
        let this = self.blocking_clone();
        let variable = variable.clone();
        tokio::task::spawn_blocking(move || -> Result<Variable> {
            let conn = this.conn.lock();
            let exists: i64 = conn
                .query_row("SELECT 1 FROM variables WHERE id = ?", params![variable.id.0], |row| {
                    row.get(0)
                })
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(0),
                    other => Err(Self::map_err(other)),
                })?;
            if exists == 0 {
                return Err(not_found("variable", variable.id.0).into());
            }
            // Seal secret values at the DB edge (same as create).
            let cleartext = variable.value.clone().unwrap_or_default();
            let stored_value =
                if variable.is_secret { this.seal_config(&cleartext)? } else { cleartext };
            conn.execute(
                "UPDATE variables SET key = ?, is_secret = ?, value = ?, updated_at = ? WHERE id = ?",
                params![
                    &variable.key,
                    variable.is_secret,
                    &stored_value,
                    variable.updated_at,
                    variable.id.0,
                ],
            )
            .map_err(Self::map_err)?;
            let mut out = variable.clone();
            if variable.is_secret {
                out.value = None;
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_variable(&self, id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            let affected = conn
                .execute("DELETE FROM variables WHERE id = ?", params![id])
                .map_err(Self::map_err)?;
            if affected == 0 { Err(not_found("variable", id).into()) } else { Ok(()) }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Results aggregations ─────────────────────────────────────────────

    async fn latency_buckets(
        &self,
        target_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        bucket_count: u32,
    ) -> Result<Vec<LatencyBucket>> {
        let n = bucket_count.max(1) as usize;
        let total_secs = (to - from).num_seconds().max(1) as f64;
        let bucket_secs = total_secs / n as f64;

        // Use DuckDB's time_bucket + quantile_cont for efficient server-side
        // aggregation. The interval is a computed float (not user input), so
        // formatting it into the SQL string is safe.
        let sql = format!(
            "SELECT \
                time_bucket(INTERVAL '{bs} seconds', timestamp, ?) AS bucket_ts, \
                quantile_cont(duration_ms, 0.5) AS p50, \
                quantile_cont(duration_ms, 0.95) AS p95, \
                quantile_cont(duration_ms, 0.99) AS p99, \
                COUNT(*) AS cnt \
             FROM check_results \
             WHERE target_id = ? AND timestamp >= ? AND timestamp <= ? \
             GROUP BY bucket_ts \
             ORDER BY bucket_ts",
            bs = bucket_secs
        );

        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<LatencyBucket>> {
            let conn = this.conn.lock();
            let mut stmt = conn.prepare(&sql).map_err(Self::map_err)?;
            let rows = stmt
                .query_map(params![from, target_id, from, to], |row| {
                    Ok(LatencyRow {
                        bucket_ts: row.get(0)?,
                        p50: row.get(1)?,
                        p95: row.get(2)?,
                        p99: row.get(3)?,
                        cnt: row.get(4)?,
                    })
                })
                .map_err(Self::map_err)?;

            // Index results by bucket index for O(1) lookup when filling gaps.
            let mut by_idx: std::collections::HashMap<usize, LatencyRow> = HashMap::new();
            for r in rows {
                let row = r.map_err(Self::map_err)?;
                let idx =
                    ((row.bucket_ts - from).num_seconds() as f64 / bucket_secs).round() as usize;
                by_idx.insert(idx.min(n - 1), row);
            }

            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                let ts = from + chrono::Duration::seconds((i as f64 * bucket_secs) as i64);
                match by_idx.get(&i) {
                    Some(row) if row.cnt > 0 => {
                        out.push(LatencyBucket {
                            ts,
                            p50: Some(row.p50),
                            p95: Some(row.p95),
                            p99: Some(row.p99),
                            count: row.cnt as u64,
                        });
                    }
                    _ => {
                        out.push(LatencyBucket { ts, p50: None, p95: None, p99: None, count: 0 });
                    }
                }
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn uptime(
        &self,
        target_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Option<UptimeResult>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Option<UptimeResult>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT \
                        COUNT(*) FILTER (WHERE status = 'up') AS up_count, \
                        COUNT(*) AS total \
                     FROM check_results \
                     WHERE target_id = ? AND timestamp >= ? AND timestamp <= ?",
                )
                .map_err(Self::map_err)?;
            let (up_count, total): (i64, i64) = stmt
                .query_row(params![target_id, from, to], |row| Ok((row.get(0)?, row.get(1)?)))
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok((0, 0)),
                    other => Err(Self::map_err(other)),
                })?;
            if total == 0 {
                return Ok(None);
            }
            let failed = total - up_count;
            let uptime_pct = (up_count as f64 / total as f64) * 100.0;
            Ok(Some(UptimeResult {
                target_id,
                uptime_pct,
                total_checks: total as u64,
                failed_checks: failed as u64,
            }))
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn dashboard_rollup(&self) -> Result<Vec<DashboardRow>> {
        // Single blocking task that runs four queries against one connection
        // hold: targets, latest result per target, 24h stats per target, and
        // a 90-day day-strip for ALL targets at once. The previous
        // implementation called `component_day_history` once per target (N+1);
        // this version groups by `(target_id, day)` in one query and assembles
        // per-target strips on the client.
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<DashboardRow>> {
            let conn = this.conn.lock();
            let now = Utc::now();
            let day_ago = now - chrono::Duration::hours(24);
            let ninety_days_ago = now - chrono::Duration::days(90);

            // 1. Fetch all targets.
            let targets = {
                let mut stmt = conn
                    .prepare("SELECT payload FROM targets ORDER BY created_at")
                    .map_err(Self::map_err)?;
                let rows = stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(Self::map_err)?;
                let mut v = Vec::new();
                for r in rows {
                    let s = r.map_err(Self::map_err)?;
                    let t: Target = serde_json::from_str(&s)
                        .map_err(|e| StorageError::Duckdb(e.to_string()))?;
                    v.push(t);
                }
                v
            };

            // 2. Latest result per target (DISTINCT ON → one row per target).
            let latest_map: HashMap<Uuid, (DateTime<Utc>, CheckStatus)> = {
                let mut stmt = conn
                    .prepare(
                        "SELECT DISTINCT ON (target_id) target_id, timestamp, status \
                         FROM check_results \
                         ORDER BY target_id, timestamp DESC",
                    )
                    .map_err(Self::map_err)?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, Uuid>(0)?,
                            row.get::<_, DateTime<Utc>>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })
                    .map_err(Self::map_err)?;
                let mut m = HashMap::new();
                for r in rows {
                    let (tid, ts, status_str) = r.map_err(Self::map_err)?;
                    m.insert(tid, (ts, check_status_from_str(&status_str)));
                }
                m
            };

            // 3. Trailing 24h uptime + p95 per target.
            let stats_map: HashMap<Uuid, (Option<f64>, Option<f64>)> = {
                let mut stmt = conn
                    .prepare(
                        "SELECT \
                            target_id, \
                            COUNT(*) FILTER (WHERE status = 'up')::float / NULLIF(COUNT(*), 0) * 100 AS uptime_pct, \
                            quantile_cont(duration_ms, 0.95) AS p95 \
                         FROM check_results \
                         WHERE timestamp >= ? \
                         GROUP BY target_id",
                    )
                    .map_err(Self::map_err)?;
                let rows = stmt
                    .query_map(params![day_ago], |row| {
                        Ok((
                            row.get::<_, Uuid>(0)?,
                            row.get::<_, Option<f64>>(1)?,
                            row.get::<_, Option<f64>>(2)?,
                        ))
                    })
                    .map_err(Self::map_err)?;
                let mut m = HashMap::new();
                for r in rows {
                    let (tid, uptime, p95) = r.map_err(Self::map_err)?;
                    m.insert(tid, (uptime, p95));
                }
                m
            };

            // 4. 90-day day-strip for ALL targets in one query
            //    (`GROUP BY target_id, day`), replacing the previous
            //    per-target `component_day_history` N+1 call pattern.
            let history_map: HashMap<Uuid, std::collections::BTreeMap<NaiveDate, DayState>> = {
                let mut stmt = conn
                    .prepare(
                        "SELECT target_id, CAST(timestamp AS DATE) AS day, \
                                MAX(CASE \
                                    WHEN status = 'down' OR status = 'error' THEN 4 \
                                    WHEN status = 'degraded' THEN 3 \
                                    WHEN status = 'up' THEN 1 \
                                    ELSE 0 \
                                END) AS worst_rank \
                         FROM check_results \
                         WHERE timestamp >= ? AND timestamp <= ? \
                         GROUP BY target_id, day",
                    )
                    .map_err(Self::map_err)?;
                let rows = stmt
                    .query_map(params![ninety_days_ago, now], |row| {
                        Ok((
                            row.get::<_, Uuid>(0)?,
                            row.get::<_, NaiveDate>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })
                    .map_err(Self::map_err)?;
                let mut m: HashMap<Uuid, std::collections::BTreeMap<NaiveDate, DayState>> =
                    HashMap::new();
                for r in rows {
                    let (tid, day, worst_rank) = r.map_err(Self::map_err)?;
                    m.entry(tid).or_default().insert(day, rank_to_day_state(worst_rank));
                }
                m
            };

            // 5. Assemble per-target DashboardRow, filling missing days with
            //    NoData so every strip spans the full window.
            let mut out = Vec::with_capacity(targets.len());
            for target in &targets {
                let by_day = history_map.get(&target.id);
                let mut history: Vec<DayState> = Vec::new();
                let mut cursor = ninety_days_ago.date_naive();
                let end = now.date_naive();
                while cursor <= end {
                    let state = by_day
                        .and_then(|m| m.get(&cursor))
                        .copied()
                        .unwrap_or(DayState::NoData);
                    history.push(state);
                    cursor += chrono::Duration::days(1);
                }
                let (last_check_at, current_status) = latest_map
                    .get(&target.id)
                    .map_or((None, CheckStatus::Up), |(ts, s)| (Some(*ts), *s));
                let (uptime_pct_24h, p95_24h) =
                    stats_map.get(&target.id).copied().unwrap_or((None, None));
                out.push(DashboardRow {
                    target_id: target.id,
                    name: target.name.clone(),
                    kind: target.check.kind().to_string(),
                    enabled: target.enabled,
                    current_status,
                    last_check_at,
                    uptime_pct_24h,
                    p95_24h,
                    history,
                });
            }
            out.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn dashboard_summary(&self) -> Result<DashboardSummary> {
        let targets = self.list_targets().await?;
        let mut summary = DashboardSummary { total: targets.len() as u64, ..Default::default() };

        // Fetch latest status per target in one query.
        let this = self.blocking_clone();
        let latest_map: HashMap<Uuid, CheckStatus> =
            tokio::task::spawn_blocking(move || -> Result<HashMap<Uuid, CheckStatus>> {
                let conn = this.conn.lock();
                let mut stmt = conn
                    .prepare(
                        "SELECT DISTINCT ON (target_id) target_id, status \
                         FROM check_results \
                         ORDER BY target_id, timestamp DESC",
                    )
                    .map_err(Self::map_err)?;
                let rows = stmt
                    .query_map([], |row| Ok((row.get::<_, Uuid>(0)?, row.get::<_, String>(1)?)))
                    .map_err(Self::map_err)?;
                let mut m = HashMap::new();
                for r in rows {
                    let (tid, status_str) = r.map_err(Self::map_err)?;
                    m.insert(tid, check_status_from_str(&status_str));
                }
                Ok(m)
            })
            .await
            .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))??;

        for target in &targets {
            if target.enabled {
                match latest_map.get(&target.id) {
                    Some(CheckStatus::Up) => summary.up += 1,
                    Some(CheckStatus::Down) => summary.down += 1,
                    Some(CheckStatus::Degraded) => summary.degraded += 1,
                    Some(CheckStatus::Error) => summary.error += 1,
                    // `CheckStatus` is `#[non_exhaustive]`: a future variant
                    // is ignored for the summary counters (no-op).
                    Some(_) => {}
                    None => {}
                }
            } else {
                summary.disabled += 1;
            }
        }
        Ok(summary)
    }

    async fn component_day_history(
        &self,
        target_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<ComponentDayHistory>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<ComponentDayHistory>> {
            let conn = this.conn.lock();
            // Group by date, take worst status rank per day.
            let mut stmt = conn
                .prepare(
                    "SELECT \
                        CAST(timestamp AS DATE) AS day, \
                        MAX(CASE \
                            WHEN status = 'down' OR status = 'error' THEN 4 \
                            WHEN status = 'degraded' THEN 3 \
                            WHEN status = 'up' THEN 1 \
                            ELSE 0 \
                        END) AS worst_rank \
                     FROM check_results \
                     WHERE target_id = ? AND timestamp >= ? AND timestamp <= ? \
                     GROUP BY day \
                     ORDER BY day",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(params![target_id, from, to], |row| {
                    Ok(DayHistoryRow { day: row.get(0)?, worst_rank: row.get(1)? })
                })
                .map_err(Self::map_err)?;

            let mut by_day: std::collections::BTreeMap<NaiveDate, DayState> =
                std::collections::BTreeMap::new();
            for r in rows {
                let row = r.map_err(Self::map_err)?;
                by_day.insert(row.day, rank_to_day_state(row.worst_rank));
            }

            // Fill in every day in the window; NoData for missing days.
            let mut out = Vec::new();
            let mut cursor = from.date_naive();
            let end = to.date_naive();
            while cursor <= end {
                let state = *by_day.get(&cursor).unwrap_or(&DayState::NoData);
                out.push(ComponentDayHistory { target_id, day: cursor, state });
                cursor += chrono::Duration::days(1);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn recent_results_for_targets(
        &self,
        target_ids: &[Uuid],
        limit_per_target: u32,
    ) -> Result<HashMap<Uuid, Vec<CheckResult>>> {
        if target_ids.is_empty() {
            return Ok(HashMap::new());
        }
        // Single query with ROW_NUMBER() OVER (PARTITION BY target_id ...)
        // fetches the top-N newest results per target in one round-trip,
        // replacing the previous one-query-per-target N+1 pattern. The
        // dynamic IN clause is built with one `?` per id; the trailing `?`
        // binds `limit_per_target`. Results are grouped per target on the
        // client side.
        let tids: Vec<Uuid> = target_ids.to_vec();
        let limit_i64 = i64::from(limit_per_target);
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<HashMap<Uuid, Vec<CheckResult>>> {
            let conn = this.conn.lock();
            let placeholders = tids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let sql = format!(
                "WITH ranked AS (\
                    SELECT target_id, payload, \
                           ROW_NUMBER() OVER (PARTITION BY target_id ORDER BY timestamp DESC) AS rn \
                    FROM check_results WHERE target_id IN ({placeholders})\
                ) SELECT target_id, payload FROM ranked WHERE rn <= ?",
                placeholders = placeholders
            );
            let mut stmt = conn.prepare(&sql).map_err(Self::map_err)?;
            // Build a heterogeneous parameter slice: the target ids (Uuid)
            // followed by the per-target limit (i64). `&[&dyn ToSql]` is the
            // canonical duckdb shape for dynamic parameter counts.
            let mut sql_params: Vec<&dyn duckdb::ToSql> =
                tids.iter().map(|id| id as &dyn duckdb::ToSql).collect();
            sql_params.push(&limit_i64);
            let rows = stmt
                .query_map(sql_params.as_slice(), |row| {
                    Ok((row.get::<_, Uuid>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(Self::map_err)?;
            // Pre-populate every requested target so callers see an empty vec
            // (not a missing key) for targets that produced no rows — matches
            // the previous per-target query behaviour.
            let mut out: HashMap<Uuid, Vec<CheckResult>> =
                tids.iter().copied().map(|tid| (tid, Vec::new())).collect();
            for r in rows {
                let (tid, s) = r.map_err(Self::map_err)?;
                let cr: CheckResult = serde_json::from_str(&s)
                    .map_err(|e| StorageError::Duckdb(e.to_string()))?;
                out.entry(tid).or_default().push(cr);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Notification channels ────────────────────────────────────────────

    async fn list_notification_channels(&self) -> Result<Vec<NotificationChannel>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<NotificationChannel>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare("SELECT payload FROM notification_channels ORDER BY created_at")
                .map_err(Self::map_err)?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0)).map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let s = r.map_err(Self::map_err)?;
                // A channel whose config can't be opened (KEK rotated out) is
                // skipped rather than failing the whole list — one bad row
                // shouldn't blank the channel picker.
                match this.channel_from_payload(&s) {
                    Ok(ch) => out.push(ch),
                    Err(e) => {
                        tracing::error!(error = %e, "list_notification_channels: skipping unopenable channel");
                    }
                }
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn get_notification_channel(&self, id: Uuid) -> Result<NotificationChannel> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<NotificationChannel> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare("SELECT payload FROM notification_channels WHERE id = ?")
                .map_err(Self::map_err)?;
            let s: Option<String> = stmt
                .query_row(params![id], |row| row.get::<_, String>(0))
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            match s {
                None => Err(not_found("notification channel", id).into()),
                Some(json) => this.channel_from_payload(&json),
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn create_notification_channel(
        &self,
        channel: &NewNotificationChannel,
    ) -> Result<NotificationChannel> {
        let now = Utc::now();
        let created = NotificationChannel {
            id: Uuid::now_v7(),
            name: channel.name.clone(),
            kind: channel.config.kind(),
            config: channel.config.clone(),
            enabled: channel.enabled,
            disabled_reason: None,
            verified_at: None,
            created_at: now,
            updated_at: now,
            write_source: WriteSource::Ui,
        };
        let this = self.blocking_clone();
        let created_for_block = created.clone();
        tokio::task::spawn_blocking(move || -> Result<NotificationChannel> {
            let payload = this.channel_to_payload(&created_for_block)?;
            let conn = this.conn.lock();
            let res = conn.execute(
                "INSERT INTO notification_channels \
                 (id, name, kind, enabled, payload, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    created_for_block.id,
                    &created_for_block.name,
                    created_for_block.kind.as_db_str(),
                    created_for_block.enabled,
                    &payload,
                    now,
                    now,
                ],
            );
            match res {
                Ok(_) => Ok(created_for_block),
                Err(e) => {
                    let mapped = Self::map_err(e);
                    if matches!(mapped, StorageError::Conflict(_)) {
                        Err(StorageError::Conflict(format!(
                            "notification channel {} exists",
                            created_for_block.id
                        ))
                        .into())
                    } else {
                        Err(mapped.into())
                    }
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))??;
        Ok(created)
    }

    async fn update_notification_channel(
        &self,
        id: Uuid,
        update: &NotificationChannelUpdate,
    ) -> Result<NotificationChannel> {
        // Read existing, apply patch, write back.
        let mut channel = self.get_notification_channel(id).await?;
        if let Some(name) = &update.name {
            channel.name = name.clone();
        }
        if let Some(config) = &update.config {
            channel.config = config.clone();
            channel.kind = config.kind();
        }
        if let Some(enabled) = update.enabled {
            channel.enabled = enabled;
            if enabled {
                channel.disabled_reason = None;
            }
        }
        channel.updated_at = Utc::now();

        let this = self.blocking_clone();
        let channel_for_block = channel.clone();
        tokio::task::spawn_blocking(move || -> Result<NotificationChannel> {
            let payload = this.channel_to_payload(&channel_for_block)?;
            let conn = this.conn.lock();
            let affected = conn
                .execute(
                    "UPDATE notification_channels \
                     SET name = ?, kind = ?, enabled = ?, payload = ?, updated_at = ? \
                     WHERE id = ?",
                    params![
                        &channel_for_block.name,
                        channel_for_block.kind.as_db_str(),
                        channel_for_block.enabled,
                        &payload,
                        channel_for_block.updated_at,
                        id,
                    ],
                )
                .map_err(Self::map_err)?;
            if affected == 0 {
                Err(not_found("notification channel", id).into())
            } else {
                Ok(channel_for_block)
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_notification_channel(&self, id: Uuid) -> Result<()> {
        // Wrap the channel delete + binding cleanup in one transaction so a
        // failure on the second statement cannot leave orphan bindings
        // pointing at a deleted channel. The 404 check (affected == 0) also
        // rolls back, leaving the row untouched when callers mistake the id.
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            Self::with_transaction(&conn, |conn| {
                let affected = conn
                    .execute("DELETE FROM notification_channels WHERE id = ?", params![id])
                    .map_err(Self::map_err)?;
                if affected == 0 {
                    return Err(not_found("notification channel", id).into());
                }
                // Clean up all bindings for this channel.
                conn.execute(
                    "DELETE FROM target_channel_bindings WHERE channel_id = ?",
                    params![id],
                )
                .map_err(Self::map_err)?;
                Ok(())
            })
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Channel verification tokens ─────────────────────────────────────

    async fn create_channel_verification_token(
        &self,
        channel_id: Uuid,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        let now = Utc::now();
        let id = Uuid::now_v7();
        let token_hash = token_hash.to_string();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute(
                "INSERT INTO channel_verification_tokens \
                 (id, channel_id, token_hash, expires_at, used_at, created_at) \
                 VALUES (?, ?, ?, ?, NULL, ?)",
                params![id, channel_id, token_hash, expires_at, now],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn consume_channel_verification_token(&self, token_hash: &str) -> Result<Option<Uuid>> {
        let token_hash = token_hash.to_string();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Option<Uuid>> {
            let conn = this.conn.lock();
            // Atomically claim the first unused, non-expired row matching the
            // hash. `affected == 0` covers missing / expired / already-used.
            let now = Utc::now();
            let affected = conn
                .execute(
                    "UPDATE channel_verification_tokens SET used_at = ? \
                     WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
                    params![now, token_hash, now],
                )
                .map_err(Self::map_err)?;
            if affected == 0 {
                return Ok(None);
            }
            let mut stmt = conn
                .prepare(
                    "SELECT channel_id FROM channel_verification_tokens \
                     WHERE token_hash = ? AND used_at IS NOT NULL \
                     ORDER BY used_at DESC LIMIT 1",
                )
                .map_err(Self::map_err)?;
            let channel_id: Option<Uuid> = stmt
                .query_row(params![token_hash], |row| row.get::<_, Uuid>(0))
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            Ok(channel_id)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn set_channel_verified(&self, channel_id: Uuid) -> Result<()> {
        // Read-modify-write the JSON payload so `verified_at` lands in the
        // serialised `NotificationChannel` the read path returns.
        let mut channel = self.get_notification_channel(channel_id).await?;
        channel.verified_at = Some(Utc::now());
        channel.updated_at = Utc::now();
        let payload =
            serde_json::to_string(&channel).map_err(|e| StorageError::Duckdb(e.to_string()))?;
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute(
                "UPDATE notification_channels SET payload = ?, updated_at = ? WHERE id = ?",
                params![payload, channel.updated_at, channel_id],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn set_channel_disabled_reason(&self, channel_id: Uuid, reason: &str) -> Result<()> {
        let mut channel = self.get_notification_channel(channel_id).await?;
        channel.disabled_reason = if reason.is_empty() { None } else { Some(reason.to_string()) };
        channel.updated_at = Utc::now();
        let payload =
            serde_json::to_string(&channel).map_err(|e| StorageError::Duckdb(e.to_string()))?;
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute(
                "UPDATE notification_channels SET payload = ?, updated_at = ? WHERE id = ?",
                params![payload, channel.updated_at, channel_id],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Target ↔ notification channel bindings ───────────────────────────

    async fn list_target_channels(&self, target_id: Uuid) -> Result<Vec<TargetChannelBinding>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<TargetChannelBinding>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT target_id, channel_id, created_at \
                     FROM target_channel_bindings \
                     WHERE target_id = ? \
                     ORDER BY created_at ASC",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(params![target_id], |row| {
                    Ok(TargetChannelBinding {
                        target_id: row.get(0)?,
                        channel_id: row.get(1)?,
                        created_at: row.get(2)?,
                    })
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(Self::map_err)?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn bind_target_channel(&self, target_id: Uuid, channel_id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            // INSERT OR IGNORE for idempotency.
            conn.execute(
                "INSERT OR IGNORE INTO target_channel_bindings (target_id, channel_id, created_at) \
                 VALUES (?, ?, ?)",
                params![target_id, channel_id, Utc::now()],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn unbind_target_channel(&self, target_id: Uuid, channel_id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute(
                "DELETE FROM target_channel_bindings WHERE target_id = ? AND channel_id = ?",
                params![target_id, channel_id],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn unbind_channel_everywhere(&self, channel_id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute(
                "DELETE FROM target_channel_bindings WHERE channel_id = ?",
                params![channel_id],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Incident ops ─────────────────────────────────────────────────────

    async fn apply_incident_ops(
        &self,
        incident_id: Uuid,
        patch: &IncidentOpsPatch,
    ) -> Result<Incident> {
        // Read-modify-write on the incidents table, wrapped in a single
        // transaction so a concurrent writer cannot interleave between the
        // SELECT payload and the UPDATE. The whole block runs on a
        // blocking thread so the synchronous DuckDB I/O does not stall the
        // tokio runtime worker.
        let this = self.blocking_clone();
        let patch = patch.clone();
        tokio::task::spawn_blocking(move || -> Result<Incident> {
            let conn = this.conn.lock();
            Self::with_transaction(&conn, |conn| {
                // Read the incident payload within the transaction.
                let mut stmt = conn
                    .prepare("SELECT payload FROM incidents WHERE id = ?")
                    .map_err(Self::map_err)?;
                let json: Option<String> = stmt
                    .query_row(params![incident_id], |row| row.get::<_, String>(0))
                    .map(Some)
                    .or_else(|e| match e {
                        duckdb::Error::QueryReturnedNoRows => Ok(None),
                        other => Err(Self::map_err(other)),
                    })?;
                let Some(json) = json else {
                    return Err(not_found("incident", incident_id).into());
                };
                let mut incident: Incident =
                    serde_json::from_str(&json).map_err(|e| StorageError::Duckdb(e.to_string()))?;

                // Determine current state from ended_at.
                let current_state = if incident.ended_at.is_some() {
                    IncidentState::Resolved
                } else {
                    IncidentState::Triggered
                };

                // Apply transition.
                if let Some(transition_str) = &patch.transition {
                    let transition = match transition_str.as_str() {
                        "acknowledge" => IncidentTransition::Acknowledge,
                        "resolve" => IncidentTransition::Resolve,
                        "reopen" => IncidentTransition::Reopen,
                        other => {
                            return Err(StorageError::InvalidInput(format!(
                                "unknown transition: {other}"
                            ))
                            .into());
                        }
                    };
                    let new_state = next_state(current_state, transition)
                        .map_err(|e| StorageError::Conflict(e.to_string()))?;
                    match new_state {
                        IncidentState::Resolved => {
                            let now = Utc::now();
                            let duration = (now - incident.started_at).num_seconds().max(0) as u64;
                            incident.ended_at = Some(now);
                            incident.duration_secs = Some(duration);
                        }
                        IncidentState::Triggered => {
                            incident.ended_at = None;
                            incident.duration_secs = None;
                        }
                        IncidentState::Acknowledged => {}
                        // IncidentState is #[non_exhaustive]; unknown future
                        // states leave the incident body untouched.
                        _ => {}
                    }
                }

                // Apply severity change.
                if let Some(severity) = patch.severity {
                    incident.severity = severity;
                }

                // Apply note.
                if let Some(note) = &patch.note {
                    incident.updates.push(PublicIncidentUpdate {
                        posted_at: Utc::now(),
                        phase: IncidentStatusPhase::Investigating,
                        message: note.clone(),
                    });
                }

                incident.updated_at = Some(Utc::now());

                // Write back within the same transaction. The payload column
                // holds the full Incident JSON; the projected columns are
                // updated to match so indices stay consistent.
                let payload = serde_json::to_string(&incident)
                    .map_err(|e| StorageError::Duckdb(e.to_string()))?;
                let affected = conn
                    .execute(
                        "UPDATE incidents SET target_id = ?, started_at = ?, ended_at = ?, \
                         severity = ?, payload = ?, created_at = ? WHERE id = ?",
                        params![
                            incident.target_id,
                            incident.started_at,
                            incident.ended_at,
                            incident.severity.as_db_str(),
                            &payload,
                            incident.created_at,
                            incident.id,
                        ],
                    )
                    .map_err(Self::map_err)?;
                if affected == 0 {
                    return Err(not_found("incident", incident.id).into());
                }
                Ok(incident)
            })
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn incident_metrics(&self, window_days: u32) -> Result<IncidentMetricsRollup> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<IncidentMetricsRollup> {
            let conn = this.conn.lock();
            let now = Utc::now();
            let cutoff = now - chrono::Duration::days(i64::from(window_days));
            let mut stmt = conn
                .prepare(
                    "SELECT \
                        COUNT(*) AS total, \
                        COUNT(*) FILTER (WHERE ended_at IS NULL) AS open_count, \
                        COUNT(*) FILTER (WHERE ended_at IS NOT NULL) AS resolved_count, \
                        AVG(CASE WHEN duration_secs IS NOT NULL THEN duration_secs ELSE NULL END) AS mttr \
                     FROM incidents \
                     WHERE started_at >= ?",
                )
                .map_err(Self::map_err)?;
            let (total, open_count, resolved_count, mttr): (i64, i64, i64, Option<f64>) = stmt
                .query_row(params![cutoff], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok((0, 0, 0, None)),
                    other => Err(Self::map_err(other)),
                })?;
            Ok(IncidentMetricsRollup {
                window_days,
                total: total as u64,
                open: open_count as u64,
                resolved: resolved_count as u64,
                mttr_secs: mttr,
            })
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Subscriber deliveries ────────────────────────────────────────────

    async fn list_pending_deliveries(&self, limit: u32) -> Result<Vec<SubscriberDelivery>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<SubscriberDelivery>> {
            let conn = this.conn.lock();
            // Include both Pending deliveries and Failed deliveries whose
            // `next_attempt_at` has elapsed (retry sweep). Claimed rows are
            // excluded — they're being worked by another dispatcher.
            let mut stmt = conn
                .prepare(
                    "SELECT id, subscriber_id, status_page_id, channel, target, payload, \
                     reason, status, attempts, last_error, created_at, sent_at, next_attempt_at \
                     FROM subscriber_deliveries \
                     WHERE status = 'pending' \
                        OR (status = 'failed' AND next_attempt_at IS NOT NULL \
                            AND next_attempt_at <= CURRENT_TIMESTAMP) \
                     ORDER BY created_at ASC \
                     LIMIT ?",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(params![i64::from(limit)], |row| {
                    Ok(DeliveryRow {
                        id: row.get(0)?,
                        subscriber_id: row.get(1)?,
                        status_page_id: row.get(2)?,
                        channel: row.get(3)?,
                        target: row.get(4)?,
                        payload: row.get(5)?,
                        reason: row.get(6)?,
                        status: row.get(7)?,
                        attempts: row.get(8)?,
                        last_error: row.get(9)?,
                        created_at: row.get(10)?,
                        sent_at: row.get(11)?,
                        next_attempt_at: row.get(12)?,
                    })
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(delivery_row_to_domain(r.map_err(Self::map_err)?)?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn claim_delivery(&self, id: Uuid) -> Result<Option<SubscriberDelivery>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Option<SubscriberDelivery>> {
            let conn = this.conn.lock();
            // Atomically claim: update if currently pending OR a failed delivery
            // whose retry timer has elapsed. This prevents two workers from
            // processing the same delivery concurrently.
            let affected = conn
                .execute(
                    "UPDATE subscriber_deliveries SET status = 'claimed' \
                     WHERE id = ? AND ( \
                        status = 'pending' \
                        OR (status = 'failed' AND next_attempt_at IS NOT NULL \
                            AND next_attempt_at <= CURRENT_TIMESTAMP) \
                     )",
                    params![id],
                )
                .map_err(Self::map_err)?;
            if affected == 0 {
                return Ok(None);
            }
            // Read back the claimed row.
            let mut stmt = conn
                .prepare(
                    "SELECT id, subscriber_id, status_page_id, channel, target, payload, \
                     reason, status, attempts, last_error, created_at, sent_at, next_attempt_at \
                     FROM subscriber_deliveries WHERE id = ?",
                )
                .map_err(Self::map_err)?;
            let row = stmt
                .query_row(params![id], |row| {
                    Ok(DeliveryRow {
                        id: row.get(0)?,
                        subscriber_id: row.get(1)?,
                        status_page_id: row.get(2)?,
                        channel: row.get(3)?,
                        target: row.get(4)?,
                        payload: row.get(5)?,
                        reason: row.get(6)?,
                        status: row.get(7)?,
                        attempts: row.get(8)?,
                        last_error: row.get(9)?,
                        created_at: row.get(10)?,
                        sent_at: row.get(11)?,
                        next_attempt_at: row.get(12)?,
                    })
                })
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            row.map(delivery_row_to_domain).transpose()
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn mark_delivery(
        &self,
        id: Uuid,
        status: DeliveryStatus,
        error: Option<&str>,
    ) -> Result<()> {
        let error = error.map(str::to_string);
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            // Read current attempts to compute backoff.
            let current_attempts: Option<i32> = conn
                .query_row(
                    "SELECT attempts FROM subscriber_deliveries WHERE id = ?",
                    params![id],
                    |row| row.get(0),
                )
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            let current_attempts =
                current_attempts.ok_or_else(|| not_found("delivery", id))?;

            let now = Utc::now();
            let new_attempts = current_attempts + 1;
            let (sent_at, next_attempt_at) = match status {
                DeliveryStatus::Sent => (Some(now), None),
                DeliveryStatus::DeadLetter => (None, None),
                DeliveryStatus::Failed => {
                    let backoff_secs = (30 * 2i64.pow(new_attempts.min(7) as u32)).min(3600);
                    (None, Some(now + chrono::Duration::seconds(backoff_secs)))
                }
                _ => (None, None),
            };

            let affected = conn
                .execute(
                    "UPDATE subscriber_deliveries \
                     SET status = ?, attempts = ?, last_error = ?, sent_at = ?, next_attempt_at = ? \
                     WHERE id = ?",
                    params![status.as_db_str(), new_attempts, error, sent_at, next_attempt_at, id,],
                )
                .map_err(Self::map_err)?;
            if affected == 0 {
                Err(not_found("delivery", id).into())
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn enqueue_delivery(
        &self,
        subscriber_id: Uuid,
        status_page_id: Uuid,
        channel: SubscriberChannel,
        target: &str,
        payload: &str,
        reason: DeliveryReason,
    ) -> Result<()> {
        let target = target.to_string();
        let payload = payload.to_string();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            let id = Uuid::now_v7();
            let now = Utc::now();
            conn.execute(
                "INSERT INTO subscriber_deliveries \
                 (id, subscriber_id, status_page_id, channel, target, payload, reason, \
                  status, attempts, last_error, created_at, sent_at, next_attempt_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 0, NULL, ?, NULL, ?)",
                params![
                    id,
                    subscriber_id,
                    status_page_id,
                    channel.as_db_str(),
                    target,
                    payload,
                    reason.as_db_str(),
                    now,
                    now,
                ],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_old_deliveries(&self, older_than: chrono::DateTime<Utc>) -> Result<u64> {
        // Purge by the most recent activity timestamp: prefer `sent_at`
        // (when the delivery actually went out), fall back to `created_at`
        // (the enqueue time). A `dead_letter` row with `sent_at IS NULL`
        // never succeeded, so `created_at` is the only signal we have; a
        // `sent` row carries `sent_at`. The schema has no `updated_at`
        // column, so COALESCE covers the two timestamps that exist.
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<u64> {
            let conn = this.conn.lock();
            let deleted = conn
                .execute(
                    "DELETE FROM subscriber_deliveries \
                     WHERE status IN ('sent', 'dead_letter') \
                       AND COALESCE(sent_at, created_at) < ?",
                    params![older_than],
                )
                .map_err(Self::map_err)?;
            Ok(deleted as u64)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_unverified_subscribers(
        &self,
        older_than: chrono::DateTime<Utc>,
    ) -> Result<u64> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<u64> {
            let conn = this.conn.lock();
            let deleted = conn
                .execute(
                    "DELETE FROM subscribers \
                     WHERE verified_at IS NULL \
                       AND created_at < ?",
                    params![older_than],
                )
                .map_err(Self::map_err)?;
            Ok(deleted as u64)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_old_check_results(&self, older_than: chrono::DateTime<Utc>) -> Result<u64> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<u64> {
            let conn = this.conn.lock();
            let deleted = conn
                .execute("DELETE FROM check_results WHERE timestamp < ?", params![older_than])
                .map_err(Self::map_err)?;
            Ok(deleted as u64)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Domain expiry state ──────────────────────────────────────────────

    async fn get_domain_expiry_state(&self, target_id: Uuid) -> Result<Option<DomainExpiryState>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Option<DomainExpiryState>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT target_id, domain, expires_at, registrar, fetched_at \
                     FROM domain_expiry_states WHERE target_id = ?",
                )
                .map_err(Self::map_err)?;
            let row = stmt
                .query_row(params![target_id], |row| {
                    Ok(DomainExpiryRow {
                        target_id: row.get(0)?,
                        domain: row.get(1)?,
                        expires_at: row.get(2)?,
                        registrar: row.get(3)?,
                        fetched_at: row.get(4)?,
                    })
                })
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            Ok(row.map(|r| DomainExpiryState {
                target_id: r.target_id,
                domain: r.domain,
                expires_at: r.expires_at,
                registrar: r.registrar,
                fetched_at: r.fetched_at,
            }))
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn set_domain_expiry_state(&self, state: &DomainExpiryState) -> Result<()> {
        let this = self.blocking_clone();
        let state = state.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute(
                "INSERT OR REPLACE INTO domain_expiry_states \
                 (target_id, domain, expires_at, registrar, fetched_at) \
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    state.target_id,
                    &state.domain,
                    state.expires_at,
                    &state.registrar,
                    state.fetched_at,
                ],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Auth: users ──────────────────────────────────────────────────────

    async fn create_user(&self, new: &NewUser) -> Result<User> {
        let now = Utc::now();
        let id = Uuid::now_v7();
        let email = normalize_oauth_email(&new.email);
        let email_verified_at = new.email_verified.then_some(now);
        let user = User {
            id: UserId(id),
            email: email.clone(),
            display_name: new.display_name.clone(),
            email_verified_at,
            last_seen_at: None,
            theme: AppTheme::Default,
            time_format: TimeFormat::Auto,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let this = self.blocking_clone();
        let user_for_block = user.clone();
        tokio::task::spawn_blocking(move || -> Result<User> {
            let conn = this.conn.lock();
            let res = conn.execute(
                "INSERT INTO users \
                 (id, email, display_name, email_verified_at, last_seen_at, theme, time_format, \
                  created_at, updated_at, deleted_at) \
                 VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, NULL)",
                params![
                    id,
                    &user_for_block.email,
                    &user_for_block.display_name,
                    email_verified_at,
                    user_for_block.theme.as_str(),
                    user_for_block.time_format.as_str(),
                    now,
                    now,
                ],
            );
            match res {
                Ok(_) => Ok(user_for_block),
                Err(e) => {
                    let mapped = Self::map_err(e);
                    if matches!(mapped, StorageError::Conflict(_)) {
                        Err(StorageError::Conflict(format!(
                            "user email '{}' exists",
                            user_for_block.email
                        ))
                        .into())
                    } else {
                        Err(mapped.into())
                    }
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))??;
        Ok(user)
    }

    async fn get_user(&self, id: Uuid) -> Result<User> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<User> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT id, email, display_name, email_verified_at, last_seen_at, \
                     theme, time_format, created_at, updated_at, deleted_at \
                     FROM users WHERE id = ? AND deleted_at IS NULL",
                )
                .map_err(Self::map_err)?;
            let user: Option<User> = stmt
                .query_row(params![id], |row| {
                    let theme_str: String = row.get(5)?;
                    let time_format_str: String = row.get(6)?;
                    Ok(User {
                        id: UserId(row.get(0)?),
                        email: row.get(1)?,
                        display_name: row.get(2)?,
                        email_verified_at: row.get(3)?,
                        last_seen_at: row.get(4)?,
                        theme: AppTheme::from_db(&theme_str),
                        time_format: TimeFormat::from_db(&time_format_str),
                        created_at: row.get(7)?,
                        updated_at: row.get(8)?,
                        deleted_at: row.get(9)?,
                    })
                })
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            user.ok_or_else(|| not_found("user", id).into())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let normalized = normalize_oauth_email(email);
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Option<User>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT id, email, display_name, email_verified_at, last_seen_at, \
                     theme, time_format, created_at, updated_at, deleted_at \
                     FROM users WHERE email = ? AND deleted_at IS NULL",
                )
                .map_err(Self::map_err)?;
            let user: Option<User> = stmt
                .query_row(params![&normalized], |row| {
                    let theme_str: String = row.get(5)?;
                    let time_format_str: String = row.get(6)?;
                    Ok(User {
                        id: UserId(row.get(0)?),
                        email: row.get(1)?,
                        display_name: row.get(2)?,
                        email_verified_at: row.get(3)?,
                        last_seen_at: row.get(4)?,
                        theme: AppTheme::from_db(&theme_str),
                        time_format: TimeFormat::from_db(&time_format_str),
                        created_at: row.get(7)?,
                        updated_at: row.get(8)?,
                        deleted_at: row.get(9)?,
                    })
                })
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            Ok(user)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn count_users(&self) -> Result<i64> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<i64> {
            let conn = this.conn.lock();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL", [], |row| {
                    row.get(0)
                })
                .map_err(Self::map_err)?;
            Ok(count)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn update_user(&self, id: Uuid, update: &UserUpdate) -> Result<User> {
        // Read existing (returns NotFound if missing or soft-deleted).
        let existing = self.get_user(id).await?;
        let mut patched = existing;
        if let Some(display_name) = &update.display_name {
            patched.display_name = Some(display_name.clone());
        }
        if let Some(theme) = update.theme {
            patched.theme = theme;
        }
        if let Some(time_format) = update.time_format {
            patched.time_format = time_format;
        }
        patched.updated_at = Utc::now();

        let this = self.blocking_clone();
        let patched_for_block = patched.clone();
        tokio::task::spawn_blocking(move || -> Result<User> {
            let conn = this.conn.lock();
            let affected = conn
                .execute(
                    "UPDATE users SET display_name = ?, theme = ?, time_format = ?, \
                     updated_at = ? WHERE id = ? AND deleted_at IS NULL",
                    params![
                        &patched_for_block.display_name,
                        patched_for_block.theme.as_str(),
                        patched_for_block.time_format.as_str(),
                        patched_for_block.updated_at,
                        id,
                    ],
                )
                .map_err(Self::map_err)?;
            if affected == 0 { Err(not_found("user", id).into()) } else { Ok(patched_for_block) }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn touch_user(&self, id: Uuid, at: DateTime<Utc>) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute(
                "UPDATE users SET last_seen_at = ? WHERE id = ? AND deleted_at IS NULL",
                params![at, id],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Auth: sessions ───────────────────────────────────────────────────

    async fn create_session(
        &self,
        id_hash: &str,
        new: &statuscore::domain::NewSession,
    ) -> Result<SessionRow> {
        let now = Utc::now();
        let row = SessionRow {
            id_hash: id_hash.to_string(),
            user_id: new.user_id,
            created_at: now,
            last_used_at: now,
            expires_at: new.expires_at,
            ip_hash: new.ip_hash.clone(),
            user_agent_hash: new.user_agent_hash.clone(),
        };
        let this = self.blocking_clone();
        let row_for_block = row.clone();
        tokio::task::spawn_blocking(move || -> Result<SessionRow> {
            let conn = this.conn.lock();
            let res = conn.execute(
                "INSERT INTO sessions \
                 (id_hash, user_id, created_at, last_used_at, expires_at, ip_hash, user_agent_hash) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    row_for_block.id_hash,
                    row_for_block.user_id.0,
                    now,
                    now,
                    row_for_block.expires_at,
                    &row_for_block.ip_hash,
                    &row_for_block.user_agent_hash,
                ],
            );
            match res {
                Ok(_) => Ok(row_for_block),
                Err(e) => {
                    let mapped = Self::map_err(e);
                    if matches!(mapped, StorageError::Conflict(_)) {
                        Err(StorageError::Conflict(format!("session id_hash '{}' exists", row_for_block.id_hash))
                            .into())
                    } else {
                        Err(mapped.into())
                    }
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))??;
        Ok(row)
    }

    async fn lookup_session(&self, id_hash: &str) -> Result<Option<SessionRow>> {
        let id_hash = id_hash.to_string();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Option<SessionRow>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT id_hash, user_id, created_at, last_used_at, expires_at, \
                     ip_hash, user_agent_hash FROM sessions WHERE id_hash = ?",
                )
                .map_err(Self::map_err)?;
            let row: Option<SessionRow> = stmt
                .query_row(params![id_hash], |row| {
                    Ok(SessionRow {
                        id_hash: row.get(0)?,
                        user_id: UserId(row.get(1)?),
                        created_at: row.get(2)?,
                        last_used_at: row.get(3)?,
                        expires_at: row.get(4)?,
                        ip_hash: row.get(5)?,
                        user_agent_hash: row.get(6)?,
                    })
                })
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            Ok(row)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn touch_session(&self, id_hash: &str, at: DateTime<Utc>) -> Result<()> {
        let id_hash = id_hash.to_string();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute(
                "UPDATE sessions SET last_used_at = ? WHERE id_hash = ?",
                params![at, id_hash],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_session(&self, id_hash: &str) -> Result<()> {
        let id_hash = id_hash.to_string();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute("DELETE FROM sessions WHERE id_hash = ?", params![id_hash])
                .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_other_sessions(&self, user_id: Uuid, keep_id_hash: &str) -> Result<u64> {
        let keep_id_hash = keep_id_hash.to_string();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<u64> {
            let conn = this.conn.lock();
            let affected = conn
                .execute(
                    "DELETE FROM sessions WHERE user_id = ? AND id_hash != ?",
                    params![user_id, keep_id_hash],
                )
                .map_err(Self::map_err)?;
            Ok(affected as u64)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<SessionRow>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<SessionRow>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT id_hash, user_id, created_at, last_used_at, expires_at, \
                     ip_hash, user_agent_hash FROM sessions \
                     WHERE user_id = ? ORDER BY created_at DESC",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(params![user_id], |row| {
                    Ok(SessionRow {
                        id_hash: row.get(0)?,
                        user_id: UserId(row.get(1)?),
                        created_at: row.get(2)?,
                        last_used_at: row.get(3)?,
                        expires_at: row.get(4)?,
                        ip_hash: row.get(5)?,
                        user_agent_hash: row.get(6)?,
                    })
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(Self::map_err)?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_expired_sessions(&self, now: DateTime<Utc>) -> Result<u64> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<u64> {
            let conn = this.conn.lock();
            let affected = conn
                .execute("DELETE FROM sessions WHERE expires_at < ?", params![now])
                .map_err(Self::map_err)?;
            Ok(affected as u64)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Auth: API tokens ─────────────────────────────────────────────────

    async fn create_api_token(
        &self,
        user_id: Uuid,
        new: &NewApiToken,
        token_hash: &str,
        token_prefix: &str,
    ) -> Result<ApiTokenRow> {
        let now = Utc::now();
        let id = Uuid::now_v7();
        let scopes = new.scopes.clone().unwrap_or_else(ScopeSet::full_access);
        let expires_at =
            new.expires_in_days.map(|days| now + chrono::Duration::days(i64::from(days)));
        let name = new.name.clone();
        let token_hash = token_hash.to_string();
        let token_prefix = token_prefix.to_string();
        let scopes_json = scopes.to_json();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<ApiTokenRow> {
            let conn = this.conn.lock();
            let res = conn.execute(
                "INSERT INTO api_tokens \
                 (id, user_id, name, token_hash, token_prefix, scopes, created_at, \
                  last_used_at, expires_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)",
                params![
                    id,
                    user_id,
                    &name,
                    &token_hash,
                    &token_prefix,
                    &scopes_json,
                    now,
                    expires_at,
                ],
            );
            match res {
                Ok(_) => Ok(ApiTokenRow {
                    id,
                    user_id: UserId(user_id),
                    name,
                    token_hash,
                    token_prefix,
                    scopes,
                    created_at: now,
                    last_used_at: None,
                    expires_at,
                }),
                Err(e) => {
                    let mapped = Self::map_err(e);
                    if matches!(mapped, StorageError::Conflict(_)) {
                        Err(StorageError::Conflict(format!("api token {id} exists")).into())
                    } else {
                        Err(mapped.into())
                    }
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn find_api_tokens_by_prefix(&self, prefix: &str) -> Result<Vec<ApiTokenRow>> {
        let prefix = prefix.to_string();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<ApiTokenRow>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT id, user_id, name, token_hash, token_prefix, scopes, \
                     created_at, last_used_at, expires_at FROM api_tokens \
                     WHERE token_prefix = ? ORDER BY created_at DESC",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(params![&prefix], |row| {
                    let scopes_str: String = row.get(5)?;
                    Ok(ApiTokenDbRow {
                        id: row.get(0)?,
                        user_id: row.get(1)?,
                        name: row.get(2)?,
                        token_hash: row.get(3)?,
                        token_prefix: row.get(4)?,
                        scopes_str,
                        created_at: row.get(6)?,
                        last_used_at: row.get(7)?,
                        expires_at: row.get(8)?,
                    })
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(api_token_row_to_domain(r.map_err(Self::map_err)?)?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn list_api_tokens(&self, user_id: Uuid) -> Result<Vec<ApiTokenRow>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<ApiTokenRow>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT id, user_id, name, token_hash, token_prefix, scopes, \
                     created_at, last_used_at, expires_at FROM api_tokens \
                     WHERE user_id = ? ORDER BY created_at DESC",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(params![user_id], |row| {
                    let scopes_str: String = row.get(5)?;
                    Ok(ApiTokenDbRow {
                        id: row.get(0)?,
                        user_id: row.get(1)?,
                        name: row.get(2)?,
                        token_hash: row.get(3)?,
                        token_prefix: row.get(4)?,
                        scopes_str,
                        created_at: row.get(6)?,
                        last_used_at: row.get(7)?,
                        expires_at: row.get(8)?,
                    })
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(api_token_row_to_domain(r.map_err(Self::map_err)?)?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn update_api_token(&self, id: Uuid, update: &ApiTokenUpdate) -> Result<ApiTokenRow> {
        let name = update.name.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<ApiTokenRow> {
            let conn = this.conn.lock();
            let affected = conn
                .execute("UPDATE api_tokens SET name = ? WHERE id = ?", params![&name, id])
                .map_err(Self::map_err)?;
            if affected == 0 {
                return Err(StorageError::NotFound(format!("api token {id}")).into());
            }
            let mut stmt = conn
                .prepare(
                    "SELECT id, user_id, name, token_hash, token_prefix, scopes, \
                     created_at, last_used_at, expires_at FROM api_tokens WHERE id = ?",
                )
                .map_err(Self::map_err)?;
            let row = stmt
                .query_row(params![id], |row| {
                    let scopes_str: String = row.get(5)?;
                    Ok(ApiTokenDbRow {
                        id: row.get(0)?,
                        user_id: row.get(1)?,
                        name: row.get(2)?,
                        token_hash: row.get(3)?,
                        token_prefix: row.get(4)?,
                        scopes_str,
                        created_at: row.get(6)?,
                        last_used_at: row.get(7)?,
                        expires_at: row.get(8)?,
                    })
                })
                .map_err(Self::map_err)?;
            api_token_row_to_domain(row)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn touch_api_token(&self, id: Uuid, at: DateTime<Utc>) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", params![at, id])
                .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_api_token(&self, id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute("DELETE FROM api_tokens WHERE id = ?", params![id])
                .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_api_tokens_for_user(&self, user_id: Uuid) -> Result<u64> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<u64> {
            let conn = this.conn.lock();
            let affected = conn
                .execute("DELETE FROM api_tokens WHERE user_id = ?", params![user_id])
                .map_err(Self::map_err)?;
            Ok(affected as u64)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_expired_api_tokens(&self, cutoff: DateTime<Utc>) -> Result<u64> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<u64> {
            let conn = this.conn.lock();
            let affected = conn
                .execute(
                    "DELETE FROM api_tokens \
                     WHERE expires_at IS NOT NULL \
                       AND expires_at < ?",
                    params![cutoff],
                )
                .map_err(Self::map_err)?;
            Ok(affected as u64)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Auth: magic links ────────────────────────────────────────────────

    async fn create_magic_link(
        &self,
        email: &str,
        token_hash: &str,
        token_prefix: &str,
        expires_at: DateTime<Utc>,
        ip_hash: Option<&str>,
        redirect_after: Option<&str>,
    ) -> Result<MagicLinkRow> {
        let now = Utc::now();
        let id = Uuid::now_v7();
        let normalized = normalize_oauth_email(email);
        let token_hash = token_hash.to_string();
        let token_prefix = token_prefix.to_string();
        let ip_hash = ip_hash.map(|s| s.to_string());
        let redirect_after = redirect_after.map(|s| s.to_string());
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<MagicLinkRow> {
            let conn = this.conn.lock();
            let res = conn.execute(
                "INSERT INTO magic_link_tokens \
                 (id, email, token_hash, token_prefix, created_at, expires_at, \
                  used_at, ip_hash, redirect_after) \
                 VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)",
                params![
                    id,
                    &normalized,
                    &token_hash,
                    &token_prefix,
                    now,
                    expires_at,
                    &ip_hash,
                    &redirect_after,
                ],
            );
            match res {
                Ok(_) => Ok(MagicLinkRow {
                    id,
                    email: normalized,
                    token_hash,
                    token_prefix,
                    created_at: now,
                    expires_at,
                    used_at: None,
                    ip_hash,
                    redirect_after,
                }),
                Err(e) => {
                    let mapped = Self::map_err(e);
                    if matches!(mapped, StorageError::Conflict(_)) {
                        Err(StorageError::Conflict(format!("magic link {id} exists")).into())
                    } else {
                        Err(mapped.into())
                    }
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn find_magic_links_by_prefix(&self, prefix: &str) -> Result<Vec<MagicLinkRow>> {
        let prefix = prefix.to_string();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<MagicLinkRow>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT id, email, token_hash, token_prefix, created_at, expires_at, \
                     used_at, ip_hash, redirect_after FROM magic_link_tokens \
                     WHERE token_prefix = ? AND used_at IS NULL \
                     ORDER BY created_at DESC",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(params![&prefix], |row| {
                    Ok(MagicLinkRow {
                        id: row.get(0)?,
                        email: row.get(1)?,
                        token_hash: row.get(2)?,
                        token_prefix: row.get(3)?,
                        created_at: row.get(4)?,
                        expires_at: row.get(5)?,
                        used_at: row.get(6)?,
                        ip_hash: row.get(7)?,
                        redirect_after: row.get(8)?,
                    })
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(Self::map_err)?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn consume_magic_link(&self, id: Uuid) -> Result<Option<MagicLinkRow>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Option<MagicLinkRow>> {
            let conn = this.conn.lock();
            let now = Utc::now();
            let affected = conn
                .execute(
                    "UPDATE magic_link_tokens SET used_at = ? \
                     WHERE id = ? AND used_at IS NULL",
                    params![now, id],
                )
                .map_err(Self::map_err)?;
            if affected == 0 {
                return Ok(None);
            }
            let mut stmt = conn
                .prepare(
                    "SELECT id, email, token_hash, token_prefix, created_at, expires_at, \
                     used_at, ip_hash, redirect_after FROM magic_link_tokens WHERE id = ?",
                )
                .map_err(Self::map_err)?;
            let row: Option<MagicLinkRow> = stmt
                .query_row(params![id], |row| {
                    Ok(MagicLinkRow {
                        id: row.get(0)?,
                        email: row.get(1)?,
                        token_hash: row.get(2)?,
                        token_prefix: row.get(3)?,
                        created_at: row.get(4)?,
                        expires_at: row.get(5)?,
                        used_at: row.get(6)?,
                        ip_hash: row.get(7)?,
                        redirect_after: row.get(8)?,
                    })
                })
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            Ok(row)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_expired_magic_links(&self, now: DateTime<Utc>) -> Result<u64> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<u64> {
            let conn = this.conn.lock();
            let affected = conn
                .execute(
                    "DELETE FROM magic_link_tokens WHERE expires_at < ? AND used_at IS NULL",
                    params![now],
                )
                .map_err(Self::map_err)?;
            Ok(affected as u64)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Escalation policies ──────────────────────────────────────────────

    async fn list_escalation_policies(&self) -> Result<Vec<EscalationPolicySummary>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<EscalationPolicySummary>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, description, repeat_count, payload, created_at, updated_at \
                     FROM escalation_policies ORDER BY created_at",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map([], |row| {
                    let payload: String = row.get(4)?;
                    Ok(EscalationPolicyRow {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        description: row.get(2)?,
                        repeat_count: row.get(3)?,
                        payload,
                        created_at: row.get(5)?,
                        updated_at: row.get(6)?,
                    })
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let r = r.map_err(Self::map_err)?;
                let policy: EscalationPolicy = serde_json::from_str(&r.payload)
                    .map_err(|e| StorageError::Duckdb(e.to_string()))?;
                out.push(EscalationPolicySummary {
                    id: r.id,
                    name: r.name,
                    description: r.description,
                    repeat_count: r.repeat_count,
                    step_count: policy.steps.len() as i64,
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                });
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn get_escalation_policy(&self, id: Uuid) -> Result<EscalationPolicy> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<EscalationPolicy> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare("SELECT payload FROM escalation_policies WHERE id = ?")
                .map_err(Self::map_err)?;
            let s: Option<String> = stmt
                .query_row(params![id], |row| row.get::<_, String>(0))
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            match s {
                None => Err(StorageError::NotFound(format!("escalation policy {id}")).into()),
                Some(json) => {
                    let policy: EscalationPolicy = serde_json::from_str(&json)
                        .map_err(|e| StorageError::Duckdb(e.to_string()))?;
                    Ok(policy)
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn upsert_escalation_policy(
        &self,
        policy: &EscalationPolicy,
    ) -> Result<EscalationPolicy> {
        let payload =
            serde_json::to_string(policy).map_err(|e| StorageError::Duckdb(e.to_string()))?;
        let policy = policy.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<EscalationPolicy> {
            let conn = this.conn.lock();
            conn.execute(
                "INSERT OR REPLACE INTO escalation_policies \
                 (id, name, description, repeat_count, payload, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    policy.id,
                    &policy.name,
                    &policy.description,
                    policy.repeat_count,
                    &payload,
                    policy.created_at,
                    policy.updated_at,
                ],
            )
            .map_err(Self::map_err)?;
            Ok(policy)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_escalation_policy(&self, id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            let affected = conn
                .execute("DELETE FROM escalation_policies WHERE id = ?", params![id])
                .map_err(Self::map_err)?;
            if affected == 0 {
                Err(StorageError::NotFound(format!("escalation policy {id}")).into())
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── On-call schedules ────────────────────────────────────────────────

    async fn list_on_call_schedules(&self) -> Result<Vec<OnCallScheduleSummary>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<OnCallScheduleSummary>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, timezone, payload, created_at, updated_at \
                     FROM on_call_schedules ORDER BY created_at",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map([], |row| {
                    let payload: String = row.get(3)?;
                    Ok(OnCallScheduleRow {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        timezone: row.get(2)?,
                        payload,
                        created_at: row.get(4)?,
                        updated_at: row.get(5)?,
                    })
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                let r = r.map_err(Self::map_err)?;
                let payload: OnCallSchedulePayload = serde_json::from_str(&r.payload)
                    .map_err(|e| StorageError::Duckdb(e.to_string()))?;
                out.push(OnCallScheduleSummary {
                    id: r.id,
                    name: r.name,
                    timezone: r.timezone,
                    layer_count: payload.layers.len() as i64,
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                });
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn get_on_call_schedule(&self, id: Uuid) -> Result<OnCallScheduleDetail> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<OnCallScheduleDetail> {
            // Scope the connection lock so we don't recurse into it via
            // `list_on_call_overrides_inner` (parking_lot::Mutex is non-reentrant).
            let payload = {
                let conn = this.conn.lock();
                let mut stmt = conn
                    .prepare("SELECT payload FROM on_call_schedules WHERE id = ?")
                    .map_err(Self::map_err)?;
                let s: Option<String> = stmt
                    .query_row(params![id], |row| row.get::<_, String>(0))
                    .map(Some)
                    .or_else(|e| match e {
                        duckdb::Error::QueryReturnedNoRows => Ok(None),
                        other => Err(Self::map_err(other)),
                    })?;
                let Some(json) = s else {
                    return Err(StorageError::NotFound(format!("on-call schedule {id}")).into());
                };
                serde_json::from_str::<OnCallSchedulePayload>(&json)
                    .map_err(|e| StorageError::Duckdb(e.to_string()))?
            };
            // Lock released here; safe to re-acquire inside the helper.
            let overrides = this.list_on_call_overrides_inner(id)?;
            Ok(OnCallScheduleDetail {
                schedule: payload.schedule,
                layers: payload.layers,
                overrides,
            })
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn upsert_on_call_schedule(
        &self,
        detail: &OnCallScheduleDetail,
    ) -> Result<OnCallSchedule> {
        let payload = OnCallSchedulePayload {
            schedule: detail.schedule.clone(),
            layers: detail.layers.clone(),
        };
        let payload_json =
            serde_json::to_string(&payload).map_err(|e| StorageError::Duckdb(e.to_string()))?;
        let schedule = detail.schedule.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<OnCallSchedule> {
            let conn = this.conn.lock();
            conn.execute(
                "INSERT OR REPLACE INTO on_call_schedules \
                 (id, name, timezone, payload, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    schedule.id,
                    &schedule.name,
                    &schedule.timezone,
                    &payload_json,
                    schedule.created_at,
                    schedule.updated_at,
                ],
            )
            .map_err(Self::map_err)?;
            Ok(schedule)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_on_call_schedule(&self, id: Uuid) -> Result<()> {
        // Wrap schedule + override deletes in one transaction so the second
        // DELETE failing cannot leave orphan overrides pointing at a removed
        // schedule. The 404 check rolls back too, so a wrong id is a no-op.
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            Self::with_transaction(&conn, |conn| {
                let affected = conn
                    .execute("DELETE FROM on_call_schedules WHERE id = ?", params![id])
                    .map_err(Self::map_err)?;
                // Clean up overrides for the schedule too — they cannot exist
                // without their parent.
                conn.execute("DELETE FROM on_call_overrides WHERE schedule_id = ?", params![id])
                    .map_err(Self::map_err)?;
                if affected == 0 {
                    return Err(not_found("on-call schedule", id).into());
                }
                Ok(())
            })
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── On-call overrides ───────────────────────────────────────────────

    async fn list_on_call_overrides(&self, schedule_id: Uuid) -> Result<Vec<OnCallOverride>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || this.list_on_call_overrides_inner(schedule_id))
            .await
            .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn create_on_call_override(
        &self,
        schedule_id: Uuid,
        r#override: &OnCallOverride,
    ) -> Result<OnCallOverride> {
        let r#override = r#override.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<OnCallOverride> {
            let conn = this.conn.lock();
            let res = conn.execute(
                "INSERT INTO on_call_overrides \
                 (id, schedule_id, user_id, starts_at, ends_at, created_by, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    r#override.id,
                    schedule_id,
                    r#override.user_id.0,
                    r#override.starts_at,
                    r#override.ends_at,
                    r#override.created_by.map(|u| u.0),
                    r#override.created_at,
                ],
            );
            match res {
                Ok(_) => Ok(r#override),
                Err(e) => {
                    let mapped = Self::map_err(e);
                    if matches!(mapped, StorageError::Conflict(_)) {
                        Err(StorageError::Conflict(format!(
                            "on-call override {} exists",
                            r#override.id
                        ))
                        .into())
                    } else {
                        Err(mapped.into())
                    }
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_on_call_override(&self, id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            let affected = conn
                .execute("DELETE FROM on_call_overrides WHERE id = ?", params![id])
                .map_err(Self::map_err)?;
            if affected == 0 {
                Err(StorageError::NotFound(format!("on-call override {id}")).into())
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Incident escalation state ────────────────────────────────────────

    async fn get_escalation_state(
        &self,
        incident_id: Uuid,
    ) -> Result<Option<IncidentEscalationState>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Option<IncidentEscalationState>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT incident_id, policy_id, current_level, current_round, \
                     last_paged_at, next_check_at, acked \
                     FROM incident_escalation_state WHERE incident_id = ?",
                )
                .map_err(Self::map_err)?;
            let row: Option<IncidentEscalationState> = stmt
                .query_row(params![incident_id], |row| {
                    Ok(IncidentEscalationState {
                        incident_id: row.get(0)?,
                        policy_id: row.get(1)?,
                        current_level: row.get(2)?,
                        current_round: row.get(3)?,
                        last_paged_at: row.get(4)?,
                        next_check_at: row.get(5)?,
                        acked: row.get(6)?,
                    })
                })
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            Ok(row)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn upsert_escalation_state(&self, state: &IncidentEscalationState) -> Result<()> {
        let state = state.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute(
                "INSERT OR REPLACE INTO incident_escalation_state \
                 (incident_id, policy_id, current_level, current_round, \
                  last_paged_at, next_check_at, acked) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    state.incident_id,
                    state.policy_id,
                    state.current_level,
                    state.current_round,
                    state.last_paged_at,
                    state.next_check_at,
                    state.acked,
                ],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn list_due_escalation_states(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<IncidentEscalationState>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<IncidentEscalationState>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT incident_id, policy_id, current_level, current_round, \
                     last_paged_at, next_check_at, acked \
                     FROM incident_escalation_state \
                     WHERE next_check_at <= ? AND acked = FALSE \
                     ORDER BY next_check_at ASC",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(params![now], |row| {
                    Ok(IncidentEscalationState {
                        incident_id: row.get(0)?,
                        policy_id: row.get(1)?,
                        current_level: row.get(2)?,
                        current_round: row.get(3)?,
                        last_paged_at: row.get(4)?,
                        next_check_at: row.get(5)?,
                        acked: row.get(6)?,
                    })
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(Self::map_err)?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn ack_escalation_state(&self, incident_id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            let affected = conn
                .execute(
                    "UPDATE incident_escalation_state SET acked = TRUE WHERE incident_id = ?",
                    params![incident_id],
                )
                .map_err(Self::map_err)?;
            if affected == 0 {
                Err(StorageError::NotFound(format!("escalation state for incident {incident_id}"))
                    .into())
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_escalation_state(&self, incident_id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            // Idempotent: deleting a non-existent state is a no-op (the incident
            // may have been resolved before any escalation was recorded).
            conn.execute(
                "DELETE FROM incident_escalation_state WHERE incident_id = ?",
                params![incident_id],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Postmortems ─────────────────────────────────────────────────────

    async fn get_postmortem(&self, incident_id: Uuid) -> Result<Option<IncidentPostmortem>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Option<IncidentPostmortem>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT incident_id, summary, root_cause, impact, action_items, \
                     author_id, created_at, updated_at, published_at \
                     FROM incident_postmortems WHERE incident_id = ?",
                )
                .map_err(Self::map_err)?;
            let row: Option<PostmortemRow> = stmt
                .query_row(params![incident_id], |row| {
                    Ok(PostmortemRow {
                        incident_id: row.get(0)?,
                        summary: row.get(1)?,
                        root_cause: row.get(2)?,
                        impact: row.get(3)?,
                        action_items_json: row.get(4)?,
                        author_id: row.get(5)?,
                        created_at: row.get(6)?,
                        updated_at: row.get(7)?,
                        published_at: row.get(8)?,
                    })
                })
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            row.map(postmortem_row_to_domain).transpose()
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn upsert_postmortem(
        &self,
        incident_id: Uuid,
        author_id: Option<Uuid>,
        body: &PostmortemUpsert,
    ) -> Result<IncidentPostmortem> {
        let now = Utc::now();
        let action_items_json = serde_json::to_value(&body.action_items)
            .map_err(|e| StorageError::Duckdb(e.to_string()))?;
        let summary = body.summary.clone();
        let root_cause = body.root_cause.clone();
        let impact = body.impact.clone();
        let action_items = body.action_items.clone();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<IncidentPostmortem> {
            let conn = this.conn.lock();
            // Preserve `published_at` (so an operator can edit a published
            // postmortem without un-publishing it) and `created_at` (so the
            // original creation timestamp survives subsequent edits). Both are
            // read in a single round-trip before the INSERT OR REPLACE.
            let existing: Option<(Option<DateTime<Utc>>, Option<DateTime<Utc>>)> = match conn.query_row(
                "SELECT published_at, created_at FROM incident_postmortems WHERE incident_id = ?",
                params![incident_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ) {
                Ok(v) => Some(v),
                Err(duckdb::Error::QueryReturnedNoRows) => None,
                Err(other) => return Err(Self::map_err(other).into()),
            };
            let existing_published_at = existing.and_then(|(p, _)| p);
            let created_at = existing.and_then(|(_, c)| c).unwrap_or(now);
            conn.execute(
                "INSERT OR REPLACE INTO incident_postmortems \
                 (incident_id, summary, root_cause, impact, action_items, author_id, \
                  created_at, updated_at, published_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    incident_id,
                    &summary,
                    &root_cause,
                    &impact,
                    &action_items_json,
                    author_id,
                    created_at,
                    now,
                    existing_published_at,
                ],
            )
            .map_err(Self::map_err)?;
            Ok(IncidentPostmortem {
                incident_id,
                summary,
                root_cause,
                impact,
                action_items,
                author_id: author_id.map(UserId),
                created_at,
                updated_at: now,
                published_at: existing_published_at,
            })
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn publish_postmortem(&self, incident_id: Uuid) -> Result<IncidentPostmortem> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<IncidentPostmortem> {
            let conn = this.conn.lock();
            let now = Utc::now();
            let affected = conn
                .execute(
                    "UPDATE incident_postmortems SET published_at = ?, updated_at = ? \
                     WHERE incident_id = ?",
                    params![now, now, incident_id],
                )
                .map_err(Self::map_err)?;
            if affected == 0 {
                return Err(StorageError::NotFound(format!(
                    "postmortem for incident {incident_id}"
                ))
                .into());
            }
            // Re-read to return the full row (created_at / author_id / etc.).
            let mut stmt = conn
                .prepare(
                    "SELECT incident_id, summary, root_cause, impact, action_items, \
                     author_id, created_at, updated_at, published_at \
                     FROM incident_postmortems WHERE incident_id = ?",
                )
                .map_err(Self::map_err)?;
            let row: PostmortemRow = stmt
                .query_row(params![incident_id], |row| {
                    Ok(PostmortemRow {
                        incident_id: row.get(0)?,
                        summary: row.get(1)?,
                        root_cause: row.get(2)?,
                        impact: row.get(3)?,
                        action_items_json: row.get(4)?,
                        author_id: row.get(5)?,
                        created_at: row.get(6)?,
                        updated_at: row.get(7)?,
                        published_at: row.get(8)?,
                    })
                })
                .map_err(Self::map_err)?;
            postmortem_row_to_domain(row)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn unpublish_postmortem(&self, incident_id: Uuid) -> Result<IncidentPostmortem> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<IncidentPostmortem> {
            let conn = this.conn.lock();
            let now = Utc::now();
            let affected = conn
                .execute(
                    "UPDATE incident_postmortems SET published_at = NULL, updated_at = ? \
                     WHERE incident_id = ?",
                    params![now, incident_id],
                )
                .map_err(Self::map_err)?;
            if affected == 0 {
                return Err(StorageError::NotFound(format!(
                    "postmortem for incident {incident_id}"
                ))
                .into());
            }
            let mut stmt = conn
                .prepare(
                    "SELECT incident_id, summary, root_cause, impact, action_items, \
                     author_id, created_at, updated_at, published_at \
                     FROM incident_postmortems WHERE incident_id = ?",
                )
                .map_err(Self::map_err)?;
            let row: PostmortemRow = stmt
                .query_row(params![incident_id], |row| {
                    Ok(PostmortemRow {
                        incident_id: row.get(0)?,
                        summary: row.get(1)?,
                        root_cause: row.get(2)?,
                        impact: row.get(3)?,
                        action_items_json: row.get(4)?,
                        author_id: row.get(5)?,
                        created_at: row.get(6)?,
                        updated_at: row.get(7)?,
                        published_at: row.get(8)?,
                    })
                })
                .map_err(Self::map_err)?;
            postmortem_row_to_domain(row)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_postmortem(&self, incident_id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute(
                "DELETE FROM incident_postmortems WHERE incident_id = ?",
                params![incident_id],
            )
            .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Monitor share links ─────────────────────────────────────────────

    async fn list_monitor_shares(&self, target_id: Uuid) -> Result<Vec<MonitorShare>> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<MonitorShare>> {
            let conn = this.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT id, target_id, label, created_at, expires_at, view_count, last_viewed_at \
                     FROM monitor_shares WHERE target_id = ? \
                     ORDER BY created_at DESC",
                )
                .map_err(Self::map_err)?;
            let rows = stmt
                .query_map(params![target_id], |row| {
                    Ok(MonitorShare {
                        id: MonitorShareId(row.get(0)?),
                        org_id: OrgId(Uuid::nil()),
                        target_id: row.get(1)?,
                        label: row.get(2)?,
                        // Raw token is never persisted; always `None` on read.
                        token: None,
                        created_at: row.get(3)?,
                        expires_at: row.get(4)?,
                        view_count: row.get(5)?,
                        last_viewed_at: row.get(6)?,
                    })
                })
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(Self::map_err)?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn create_monitor_share(
        &self,
        target_id: Uuid,
        label: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<CreatedShare> {
        // Generate the raw capability token (32 random bytes, base64url) and
        // its sha256_hex hash. Only the hash is persisted; the raw token is
        // returned once via `CreatedShare.token`.
        let raw_token = generate_cookie_value();
        let token_hash = hash_cookie_value(&raw_token);
        let now = Utc::now();
        let id = Uuid::now_v7();
        let label = label.map(|s| s.to_string());
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<CreatedShare> {
            let conn = this.conn.lock();
            let res = conn.execute(
                "INSERT INTO monitor_shares \
                 (id, target_id, label, token_hash, created_at, expires_at, view_count, last_viewed_at) \
                 VALUES (?, ?, ?, ?, ?, ?, 0, NULL)",
                params![id, target_id, &label, &token_hash, now, expires_at],
            );
            match res {
                Ok(_) => {
                    let share = MonitorShare {
                        id: MonitorShareId(id),
                        // v1 single-tenant: nil org, mirroring status pages.
                        org_id: OrgId(Uuid::nil()),
                        target_id,
                        label,
                        // Raw token is never stored; `None` on the persisted view.
                        token: None,
                        created_at: now,
                        expires_at,
                        view_count: 0,
                        last_viewed_at: None,
                    };
                    Ok(CreatedShare { share, token: raw_token })
                }
                Err(e) => {
                    let mapped = Self::map_err(e);
                    if matches!(mapped, StorageError::Conflict(_)) {
                        Err(StorageError::Conflict(format!(
                            "monitor share token collision for target {target_id}"
                        ))
                        .into())
                    } else {
                        Err(mapped.into())
                    }
                }
            }
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn delete_monitor_share(&self, id: Uuid) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            conn.execute("DELETE FROM monitor_shares WHERE id = ?", params![id])
                .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    async fn resolve_monitor_share(&self, token_hash: &str) -> Result<Option<ResolvedShare>> {
        let token_hash = token_hash.to_string();
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<Option<ResolvedShare>> {
            let conn = this.conn.lock();
            let now = Utc::now();
            // Atomically increment view_count + stamp last_viewed_at on the
            // matching non-expired row. `affected == 0` covers missing / expired
            // / deleted tokens.
            let affected = conn
                .execute(
                    "UPDATE monitor_shares \
                     SET view_count = view_count + 1, last_viewed_at = ? \
                     WHERE token_hash = ? AND (expires_at IS NULL OR expires_at > ?)",
                    params![now, &token_hash, now],
                )
                .map_err(Self::map_err)?;
            if affected == 0 {
                return Ok(None);
            }
            let mut stmt = conn
                .prepare("SELECT id, target_id FROM monitor_shares WHERE token_hash = ?")
                .map_err(Self::map_err)?;
            let resolved: Option<ResolvedShare> = stmt
                .query_row(params![&token_hash], |row| {
                    Ok(ResolvedShare {
                        share_id: MonitorShareId(row.get(0)?),
                        target_id: row.get(1)?,
                        org: OrgId(Uuid::nil()),
                    })
                })
                .map(Some)
                .or_else(|e| match e {
                    duckdb::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(Self::map_err(other)),
                })?;
            Ok(resolved)
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }

    // ── Health check ─────────────────────────────────────────────────────

    async fn ping(&self) -> Result<()> {
        let this = self.blocking_clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = this.conn.lock();
            let _ = conn
                .query_row("SELECT 1", [], |row| row.get::<_, i32>(0))
                .map_err(Self::map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Duckdb(format!("storage task join error: {e}")))?
    }
}

impl DuckdbStorage {
    /// Shared read path for `list_on_call_overrides` and `get_on_call_schedule`.
    /// Returns overrides for `schedule_id` ordered by `starts_at` descending
    /// (matching the index order so the planner can serve it from the index).
    fn list_on_call_overrides_inner(&self, schedule_id: Uuid) -> Result<Vec<OnCallOverride>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, user_id, starts_at, ends_at, created_by, created_at \
                 FROM on_call_overrides WHERE schedule_id = ? \
                 ORDER BY starts_at DESC",
            )
            .map_err(Self::map_err)?;
        let rows = stmt
            .query_map(params![schedule_id], |row| {
                let user_id: Uuid = row.get(1)?;
                let created_by: Option<Uuid> = row.get(4)?;
                Ok(OnCallOverride {
                    id: row.get(0)?,
                    user_id: UserId(user_id),
                    starts_at: row.get(2)?,
                    ends_at: row.get(3)?,
                    created_by: created_by.map(UserId),
                    created_at: row.get(5)?,
                })
            })
            .map_err(Self::map_err)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(Self::map_err)?);
        }
        Ok(out)
    }
}

// Helper row types for `query_map` closures (DuckDB's `FromRow` derive is not
// available for ad-hoc local structs without pulling in the macro, so we use
// plain tuples wrapped in named structs for readability).

#[derive(Debug)]
struct SubRow {
    id: Uuid,
    status_page_id: Uuid,
    org_id: Uuid,
    channel: String,
    target: String,
    config_str: String,
    verified_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug)]
struct VarRow {
    id: Uuid,
    key: String,
    is_secret: bool,
    value: String,
    updated_at: DateTime<Utc>,
}

#[derive(Debug)]
struct LatencyRow {
    bucket_ts: DateTime<Utc>,
    p50: f64,
    p95: f64,
    p99: f64,
    cnt: i64,
}

#[derive(Debug)]
struct DayHistoryRow {
    day: NaiveDate,
    worst_rank: i64,
}

#[derive(Debug)]
struct DeliveryRow {
    id: Uuid,
    subscriber_id: Uuid,
    status_page_id: Uuid,
    channel: String,
    target: String,
    payload: String,
    reason: String,
    status: String,
    attempts: i32,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
    next_attempt_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
struct DomainExpiryRow {
    target_id: Uuid,
    domain: String,
    expires_at: Option<NaiveDate>,
    registrar: Option<String>,
    fetched_at: DateTime<Utc>,
}

#[derive(Debug)]
struct ApiTokenDbRow {
    id: Uuid,
    user_id: Uuid,
    name: String,
    token_hash: String,
    token_prefix: String,
    scopes_str: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}

/// Row helper for `incident_postmortems`. `action_items_json` is the raw JSON
/// column value; it's deserialized into `Vec<ActionItem>` separately so the
/// row mapping closure stays simple.
#[derive(Debug)]
struct PostmortemRow {
    incident_id: Uuid,
    summary: Option<String>,
    root_cause: Option<String>,
    impact: Option<String>,
    action_items_json: serde_json::Value,
    author_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    published_at: Option<DateTime<Utc>>,
}

/// Map a [`PostmortemRow`] into the domain [`IncidentPostmortem`]. The
/// `action_items` JSON is deserialized via `serde_json::from_value` so a
/// corrupt payload surfaces as a `StorageError::Duckdb` rather than a panic.
fn postmortem_row_to_domain(row: PostmortemRow) -> Result<IncidentPostmortem> {
    let action_items: Vec<ActionItem> = serde_json::from_value(row.action_items_json)
        .map_err(|e| StorageError::Duckdb(format!("postmortem action_items decode: {e}")))?;
    Ok(IncidentPostmortem {
        incident_id: row.incident_id,
        summary: row.summary,
        root_cause: row.root_cause,
        impact: row.impact,
        action_items,
        author_id: row.author_id.map(UserId),
        created_at: row.created_at,
        updated_at: row.updated_at,
        published_at: row.published_at,
    })
}

/// Row helper for the `escalation_policies` listing query: the projected
/// columns plus the raw JSON `payload` (deserialized separately so we can
/// derive `step_count` from the full policy).
#[derive(Debug)]
struct EscalationPolicyRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    repeat_count: i32,
    payload: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Row helper for the `on_call_schedules` listing query.
#[derive(Debug)]
struct OnCallScheduleRow {
    id: Uuid,
    name: String,
    timezone: String,
    payload: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// On-disk shape of an on-call schedule's `payload` column. We store the
/// schedule metadata and layer stack together (the editor writes them in one
/// round-trip); overrides live in their own table and are joined at read time
/// by [`DuckdbStorage::get_on_call_schedule`].
#[derive(Debug, Serialize, Deserialize)]
struct OnCallSchedulePayload {
    schedule: OnCallSchedule,
    layers: Vec<OnCallLayer>,
}

/// `NotificationChannel` only derives `Serialize` (no `org_id` on the wire),
/// so we deserialize through this mirror struct and convert.
#[derive(Debug, Deserialize)]
struct NotificationChannelDto {
    id: Uuid,
    name: String,
    kind: statuscore::domain::ChannelKind,
    config: statuscore::domain::ChannelConfig,
    enabled: bool,
    #[serde(default)]
    disabled_reason: Option<String>,
    #[serde(default)]
    verified_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    #[serde(default)]
    write_source: WriteSource,
}

impl From<NotificationChannelDto> for NotificationChannel {
    fn from(dto: NotificationChannelDto) -> Self {
        Self {
            id: dto.id,
            name: dto.name,
            kind: dto.kind,
            config: dto.config,
            enabled: dto.enabled,
            disabled_reason: dto.disabled_reason,
            verified_at: dto.verified_at,
            created_at: dto.created_at,
            updated_at: dto.updated_at,
            write_source: dto.write_source,
        }
    }
}

fn check_status_from_str(s: &str) -> CheckStatus {
    match s {
        "up" => CheckStatus::Up,
        "down" => CheckStatus::Down,
        "degraded" => CheckStatus::Degraded,
        _ => CheckStatus::Error,
    }
}

/// Build a `NotFound` error with the conventional `"{what} {id}"` shape used
/// across all storage methods. Centralised so the message format stays
/// consistent and call sites stay short.
fn not_found(what: &str, id: impl std::fmt::Display) -> StorageError {
    StorageError::NotFound(format!("{what} {id}"))
}

/// Map a [`SubRow`] (raw column projection from the `subscribers` table) into
/// the domain [`Subscriber`]. The `config` JSON column is parsed and the
/// `channel` string is converted via [`SubscriberChannel::from_db_str`].
/// Extracted so both `list_subscribers` and `verify_subscriber` (and any
/// future reader) share one mapping path.
fn map_subscriber_row(row: SubRow) -> Result<Subscriber> {
    let config: serde_json::Value =
        serde_json::from_str(&row.config_str).map_err(|e| StorageError::Duckdb(e.to_string()))?;
    let channel = SubscriberChannel::from_db_str(&row.channel)
        .ok_or_else(|| StorageError::Duckdb(format!("unknown channel: {}", row.channel)))?;
    Ok(Subscriber {
        id: row.id,
        status_page_id: row.status_page_id,
        org_id: OrgId(row.org_id),
        channel,
        target: row.target,
        config,
        verified_at: row.verified_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

const fn rank_to_day_state(rank: i64) -> DayState {
    match rank {
        0 => DayState::NoData,
        1 => DayState::Operational,
        3 => DayState::Degraded,
        4 => DayState::MajorOutage,
        _ => DayState::NoData,
    }
}

fn delivery_row_to_domain(r: DeliveryRow) -> Result<SubscriberDelivery> {
    let channel = SubscriberChannel::from_db_str(&r.channel).ok_or_else(|| {
        StorageError::Duckdb(format!("unknown subscriber channel: {}", r.channel))
    })?;
    let reason = DeliveryReason::from_db_str(&r.reason);
    let status = DeliveryStatus::from_db_str(&r.status);
    Ok(SubscriberDelivery {
        id: r.id,
        subscriber_id: r.subscriber_id,
        status_page_id: r.status_page_id,
        channel,
        target: r.target,
        payload: r.payload,
        reason,
        status,
        attempts: r.attempts as u32,
        last_error: r.last_error,
        created_at: r.created_at,
        sent_at: r.sent_at,
        next_attempt_at: r.next_attempt_at,
    })
}

fn api_token_row_to_domain(r: ApiTokenDbRow) -> Result<ApiTokenRow> {
    Ok(ApiTokenRow {
        id: r.id,
        user_id: UserId(r.user_id),
        name: r.name,
        token_hash: r.token_hash,
        token_prefix: r.token_prefix,
        scopes: ScopeSet::from_json(&r.scopes_str),
        created_at: r.created_at,
        last_used_at: r.last_used_at,
        expires_at: r.expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use statuscore::domain::{
        ActionItem, CheckResult, CheckSpec, CheckStatus, EscalationPolicy, EscalationStep,
        EscalationTarget, EscalationTargetType, Incident, IncidentEscalationState,
        IncidentSeverity, IncidentStatusPhase, OnCallLayer, OnCallOverride, OnCallParticipant,
        OnCallSchedule, OnCallScheduleDetail, OrgId, PingCheck, PostmortemUpsert,
        PublicIncidentUpdate, PublicOrgBranding, RotationType, StatusPage, StatusPageId, Target,
        UserId, WriteSource,
    };
    use std::time::Duration;
    use uuid::Uuid;

    fn make_target(name: &str) -> Target {
        Target {
            id: Uuid::now_v7(),
            name: name.into(),
            check: CheckSpec::Ping(PingCheck {
                host: "example.com".into(),
                timeout: Duration::from_secs(3),
            }),
            interval: Duration::from_mins(1),
            enabled: true,
            tags: vec!["edge".into()],
            alerts: Default::default(),
            alert_confirmations: 2,
            notify_recovery: true,
            renotify_interval_secs: 3600,
            region_policy: Default::default(),
            group_name: Some("API".into()),
            owner_user_id: None,
            escalation_policy_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            write_source: WriteSource::Ui,
        }
    }

    fn make_result(target_id: Uuid, org_id: Uuid, ts_ms: i64) -> CheckResult {
        CheckResult {
            target_id,
            org_id: OrgId(org_id),
            timestamp: chrono::DateTime::from_timestamp(0, 0).unwrap()
                + chrono::Duration::milliseconds(ts_ms),
            status: CheckStatus::Up,
            duration_ms: 42,
            dns_ms: Some(1),
            connect_ms: Some(2),
            tls_ms: None,
            ttfb_ms: Some(3),
            response_code: Some(200),
            response_size: Some(1024),
            error: None,
        }
    }

    fn make_incident(target_id: Uuid) -> Incident {
        Incident {
            id: Uuid::now_v7(),
            target_id,
            started_at: Utc::now(),
            ended_at: None,
            status: CheckStatus::Down,
            duration_secs: None,
            check_count: 1,
            error_sample: Some("timeout".into()),
            severity: IncidentSeverity::Major,
            public_title: Some("Major outage".into()),
            public_description: None,
            created_at: Some(Utc::now()),
            updated_at: None,
            updates: Vec::new(),
            regions_down: Vec::new(),
            regions_up: Vec::new(),
        }
    }

    fn make_status_page(slug: &str, org_id: Uuid) -> StatusPage {
        StatusPage {
            id: StatusPageId(Uuid::now_v7()),
            org_id: OrgId(org_id),
            slug: slug.into(),
            name: format!("Page {slug}"),
            enabled: true,
            branding: PublicOrgBranding {
                public_display_name: Some("Display".into()),
                ..PublicOrgBranding::default()
            },
            write_source: WriteSource::Ui,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    async fn fresh() -> DuckdbStorage {
        let s = DuckdbStorage::open(":memory:").unwrap();
        s.migrate().await.unwrap();
        s
    }

    #[tokio::test]
    async fn target_crud_roundtrip() {
        let s = fresh().await;
        let t = make_target("api");
        let created = s.create_target(&t).await.unwrap();
        assert_eq!(created.id, t.id);

        let got = s.get_target(t.id).await.unwrap();
        assert_eq!(got.name, t.name);
        assert_eq!(got.tags, t.tags);
        assert_eq!(got.check.kind(), "ping");
        assert_eq!(got.group_name.as_deref(), Some("API"));

        let listed = s.list_targets().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, t.id);

        let mut updated = t.clone();
        updated.name = "api-v2".into();
        updated.enabled = false;
        let r = s.update_target(&updated).await.unwrap();
        assert_eq!(r.name, "api-v2");
        assert!(!r.enabled);
        let got2 = s.get_target(t.id).await.unwrap();
        assert_eq!(got2.name, "api-v2");
        assert!(!got2.enabled);

        s.delete_target(t.id).await.unwrap();
        let err = s.get_target(t.id).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn target_create_conflict_and_update_not_found() {
        let s = fresh().await;
        let t = make_target("api");
        s.create_target(&t).await.unwrap();
        let err = s.create_target(&t).await.unwrap_err();
        assert!(format!("{err:?}").contains("Conflict"));

        let other = make_target("other");
        let err = s.update_target(&other).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));

        let err = s.delete_target(Uuid::now_v7()).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn results_record_list_sorted_and_limited() {
        let s = fresh().await;
        let t = make_target("api");
        s.create_target(&t).await.unwrap();
        let org = Uuid::now_v7();
        for i in 0..5 {
            s.record_result(&make_result(t.id, org, i * 1000)).await.unwrap();
        }
        let listed = s.list_results(t.id, 3).await.unwrap();
        assert_eq!(listed.len(), 3);
        // DESC by timestamp — the largest ts_ms lands first.
        assert!(listed[0].timestamp > listed[1].timestamp);
        assert!(listed[1].timestamp > listed[2].timestamp);

        // Empty for an unknown target.
        let none = s.list_results(Uuid::now_v7(), 10).await.unwrap();
        assert!(none.is_empty());

        // Re-recording the same (target_id, timestamp) overwrites, not conflicts.
        let mut dup = make_result(t.id, org, 0);
        dup.duration_ms = 999;
        s.record_result(&dup).await.unwrap();
        let all = s.list_results(t.id, 100).await.unwrap();
        let first = all.iter().find(|r| r.timestamp == dup.timestamp).unwrap();
        assert_eq!(first.duration_ms, 999);
    }

    #[tokio::test]
    async fn incident_create_and_list() {
        let s = fresh().await;
        let t = make_target("api");
        s.create_target(&t).await.unwrap();
        let inc = make_incident(t.id);
        s.create_incident(&inc).await.unwrap();

        let listed = s.list_incidents().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, inc.id);
        assert_eq!(listed[0].public_title.as_deref(), Some("Major outage"));
        assert_eq!(listed[0].severity, IncidentSeverity::Major);

        let err = s.create_incident(&inc).await.unwrap_err();
        assert!(format!("{err:?}").contains("Conflict"));
    }

    #[tokio::test]
    async fn status_page_roundtrip_preserves_org_id() {
        let s = fresh().await;
        let org = Uuid::now_v7();
        let sp = make_status_page("acme", org);
        let created = s.create_status_page(&sp).await.unwrap();
        assert_eq!(created.id.0, sp.id.0);

        let got = s.get_status_page(sp.id.0).await.unwrap();
        assert_eq!(got.id.0, sp.id.0);
        assert_eq!(got.org_id.0, org); // org_id survives the round-trip
        assert_eq!(got.slug, "acme");
        assert_eq!(got.branding.public_display_name.as_deref(), Some("Display"));

        let listed = s.list_status_pages().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].org_id.0, org);

        let err = s.get_status_page(Uuid::now_v7()).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn status_page_crud_roundtrip() {
        let s = fresh().await;
        let org = Uuid::now_v7();
        let sp = make_status_page("acme", org);

        // create
        let created = s.create_status_page(&sp).await.unwrap();
        assert_eq!(created.id.0, sp.id.0);

        // create conflict (same id)
        let err = s.create_status_page(&sp).await.unwrap_err();
        assert!(format!("{err:?}").contains("Conflict"));

        // update
        let mut updated = sp.clone();
        updated.name = "Acme v2".into();
        updated.enabled = false;
        let r = s.update_status_page(&updated).await.unwrap();
        assert_eq!(r.name, "Acme v2");
        assert!(!r.enabled);
        let got = s.get_status_page(sp.id.0).await.unwrap();
        assert_eq!(got.name, "Acme v2");
        assert!(!got.enabled);

        // update not found
        let other = make_status_page("other", org);
        let err = s.update_status_page(&other).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));

        // delete
        s.delete_status_page(sp.id.0).await.unwrap();
        let err = s.get_status_page(sp.id.0).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));

        // delete not found
        let err = s.delete_status_page(sp.id.0).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    fn make_incident_update(message: &str) -> PublicIncidentUpdate {
        PublicIncidentUpdate {
            posted_at: Utc::now(),
            phase: IncidentStatusPhase::Investigating,
            message: message.into(),
        }
    }

    #[tokio::test]
    async fn incident_get_update_roundtrip() {
        let s = fresh().await;
        let t = make_target("api");
        s.create_target(&t).await.unwrap();
        let inc = make_incident(t.id);
        s.create_incident(&inc).await.unwrap();

        // get
        let got = s.get_incident(inc.id).await.unwrap();
        assert_eq!(got.id, inc.id);
        assert_eq!(got.public_title.as_deref(), Some("Major outage"));

        // get not found
        let err = s.get_incident(Uuid::now_v7()).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));

        // update
        let mut updated = inc.clone();
        updated.public_title = Some("Updated title".into());
        updated.severity = IncidentSeverity::Critical;
        let r = s.update_incident(&updated).await.unwrap();
        assert_eq!(r.public_title.as_deref(), Some("Updated title"));
        assert_eq!(r.severity, IncidentSeverity::Critical);
        let got2 = s.get_incident(inc.id).await.unwrap();
        assert_eq!(got2.public_title.as_deref(), Some("Updated title"));
        assert_eq!(got2.severity, IncidentSeverity::Critical);

        // update not found
        let other = make_incident(t.id);
        let err = s.update_incident(&other).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn add_incident_update_appends_to_vec() {
        let s = fresh().await;
        let t = make_target("api");
        s.create_target(&t).await.unwrap();
        let inc = make_incident(t.id);
        s.create_incident(&inc).await.unwrap();

        assert!(inc.updates.is_empty());

        let u1 = make_incident_update("looking into it");
        let r1 = s.add_incident_update(inc.id, &u1).await.unwrap();
        assert_eq!(r1.updates.len(), 1);
        assert_eq!(r1.updates[0].message, "looking into it");

        let u2 = make_incident_update("identified");
        let r2 = s.add_incident_update(inc.id, &u2).await.unwrap();
        assert_eq!(r2.updates.len(), 2);
        assert_eq!(r2.updates[1].message, "identified");

        // persists across reads
        let got = s.get_incident(inc.id).await.unwrap();
        assert_eq!(got.updates.len(), 2);

        // not found when incident missing
        let err = s.add_incident_update(Uuid::now_v7(), &u1).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn list_recent_results_across_targets() {
        let s = fresh().await;
        let t1 = make_target("api");
        let t2 = make_target("web");
        s.create_target(&t1).await.unwrap();
        s.create_target(&t2).await.unwrap();
        let org = Uuid::now_v7();
        // t1: ts=1000, 2000 ; t2: ts=1500
        s.record_result(&make_result(t1.id, org, 1000)).await.unwrap();
        s.record_result(&make_result(t2.id, org, 1500)).await.unwrap();
        s.record_result(&make_result(t1.id, org, 2000)).await.unwrap();

        let recent = s.list_recent_results(100).await.unwrap();
        assert_eq!(recent.len(), 3);
        // DESC by timestamp
        assert!(recent[0].timestamp > recent[1].timestamp);
        assert!(recent[1].timestamp > recent[2].timestamp);

        // limit honored
        let limited = s.list_recent_results(2).await.unwrap();
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].timestamp, recent[0].timestamp);

        // empty when nothing recorded
        let s2 = fresh().await;
        assert!(s2.list_recent_results(10).await.unwrap().is_empty());
    }

    // ── Escalation / on-call fixtures ───────────────────────────────────

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn make_escalation_policy(name: &str, repeat: i32) -> EscalationPolicy {
        EscalationPolicy {
            id: Uuid::now_v7(),
            name: name.into(),
            description: Some("test policy".into()),
            repeat_count: repeat,
            steps: vec![
                EscalationStep {
                    id: Uuid::now_v7(),
                    level: 1,
                    delay_secs: 300,
                    targets: vec![EscalationTarget {
                        id: Uuid::now_v7(),
                        target_type: EscalationTargetType::Channel,
                        user_id: None,
                        schedule_id: None,
                        channel_id: Some(Uuid::now_v7()),
                    }],
                },
                EscalationStep {
                    id: Uuid::now_v7(),
                    level: 2,
                    delay_secs: 900,
                    targets: vec![
                        EscalationTarget {
                            id: Uuid::now_v7(),
                            target_type: EscalationTargetType::User,
                            user_id: Some(Uuid::now_v7()),
                            schedule_id: None,
                            channel_id: None,
                        },
                        EscalationTarget {
                            id: Uuid::now_v7(),
                            target_type: EscalationTargetType::Channel,
                            user_id: None,
                            schedule_id: None,
                            channel_id: Some(Uuid::now_v7()),
                        },
                    ],
                },
            ],
            created_at: ts("2026-01-01T00:00:00Z"),
            updated_at: ts("2026-01-01T00:00:00Z"),
        }
    }

    fn make_on_call_schedule_detail(name: &str, tz: &str) -> OnCallScheduleDetail {
        let now = ts("2026-06-01T00:00:00Z");
        OnCallScheduleDetail {
            schedule: OnCallSchedule {
                id: Uuid::now_v7(),
                name: name.into(),
                timezone: tz.into(),
                created_at: now,
                updated_at: now,
            },
            layers: vec![OnCallLayer {
                id: Uuid::now_v7(),
                name: Some("primary".into()),
                rotation_type: RotationType::Daily,
                rotation_length_secs: 86_400,
                handoff_at: ts("2026-06-01T09:00:00Z"),
                layer_order: 0,
                created_at: now,
                participants: vec![
                    OnCallParticipant {
                        id: Uuid::now_v7(),
                        user_id: UserId(Uuid::from_u128(1)),
                        position: 0,
                    },
                    OnCallParticipant {
                        id: Uuid::now_v7(),
                        user_id: UserId(Uuid::from_u128(2)),
                        position: 1,
                    },
                ],
            }],
            overrides: Vec::new(),
        }
    }

    fn make_on_call_override(_schedule_id: Uuid, user: u128) -> OnCallOverride {
        OnCallOverride {
            id: Uuid::now_v7(),
            user_id: UserId(Uuid::from_u128(user)),
            starts_at: ts("2026-06-02T00:00:00Z"),
            ends_at: ts("2026-06-02T12:00:00Z"),
            created_by: None,
            created_at: ts("2026-06-01T00:00:00Z"),
        }
    }

    fn make_escalation_state(incident_id: Uuid, policy_id: Uuid) -> IncidentEscalationState {
        IncidentEscalationState {
            incident_id,
            policy_id,
            current_level: 0,
            current_round: 0,
            last_paged_at: ts("2026-06-01T00:00:00Z"),
            next_check_at: ts("2026-06-01T00:05:00Z"),
            acked: false,
        }
    }

    #[tokio::test]
    async fn escalation_policy_crud_roundtrip() {
        let s = fresh().await;
        let policy = make_escalation_policy("default", 1);

        // upsert (create)
        let created = s.upsert_escalation_policy(&policy).await.unwrap();
        assert_eq!(created.id, policy.id);

        // get
        let got = s.get_escalation_policy(policy.id).await.unwrap();
        assert_eq!(got.name, "default");
        assert_eq!(got.repeat_count, 1);
        assert_eq!(got.steps.len(), 2);
        assert_eq!(got.steps[0].level, 1);
        assert_eq!(got.steps[1].targets.len(), 2);
        assert_eq!(got.steps[0].targets[0].target_type, EscalationTargetType::Channel);

        // list — step_count comes from deserialising the payload
        let listed = s.list_escalation_policies().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, policy.id);
        assert_eq!(listed[0].name, "default");
        assert_eq!(listed[0].step_count, 2);
        assert_eq!(listed[0].repeat_count, 1);

        // upsert (replace) — bump repeat_count + swap step list
        let mut updated = policy.clone();
        updated.repeat_count = 3;
        updated.steps.truncate(1);
        updated.name = "default-v2".into();
        let r = s.upsert_escalation_policy(&updated).await.unwrap();
        assert_eq!(r.repeat_count, 3);
        let got2 = s.get_escalation_policy(policy.id).await.unwrap();
        assert_eq!(got2.repeat_count, 3);
        assert_eq!(got2.name, "default-v2");
        assert_eq!(got2.steps.len(), 1);
        let listed2 = s.list_escalation_policies().await.unwrap();
        assert_eq!(listed2[0].step_count, 1);
        assert_eq!(listed2[0].repeat_count, 3);

        // delete + NotFound
        s.delete_escalation_policy(policy.id).await.unwrap();
        let err = s.get_escalation_policy(policy.id).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
        let err = s.delete_escalation_policy(policy.id).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn on_call_schedule_crud_roundtrip() {
        let s = fresh().await;
        let detail = make_on_call_schedule_detail("primary", "UTC");

        // upsert (create)
        let sched = s.upsert_on_call_schedule(&detail).await.unwrap();
        assert_eq!(sched.id, detail.schedule.id);
        assert_eq!(sched.timezone, "UTC");

        // list — layer_count is derived from the payload
        let listed = s.list_on_call_schedules().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, detail.schedule.id);
        assert_eq!(listed[0].layer_count, 1);
        assert_eq!(listed[0].timezone, "UTC");

        // get detail — layers survive the round trip
        let got = s.get_on_call_schedule(detail.schedule.id).await.unwrap();
        assert_eq!(got.schedule.name, "primary");
        assert_eq!(got.layers.len(), 1);
        assert_eq!(got.layers[0].participants.len(), 2);
        assert_eq!(got.layers[0].rotation_type, RotationType::Daily);
        // No overrides yet
        assert!(got.overrides.is_empty());

        // upsert (replace) — change tz + drop layers
        let mut updated = detail.clone();
        updated.schedule.timezone = "America/New_York".into();
        updated.layers.clear();
        let r = s.upsert_on_call_schedule(&updated).await.unwrap();
        assert_eq!(r.timezone, "America/New_York");
        let got2 = s.get_on_call_schedule(detail.schedule.id).await.unwrap();
        assert_eq!(got2.schedule.timezone, "America/New_York");
        assert!(got2.layers.is_empty());
        let listed2 = s.list_on_call_schedules().await.unwrap();
        assert_eq!(listed2[0].layer_count, 0);

        // delete + NotFound
        s.delete_on_call_schedule(detail.schedule.id).await.unwrap();
        let err = s.get_on_call_schedule(detail.schedule.id).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
        let err = s.delete_on_call_schedule(detail.schedule.id).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn on_call_override_crud() {
        let s = fresh().await;
        let detail = make_on_call_schedule_detail("primary", "UTC");
        s.upsert_on_call_schedule(&detail).await.unwrap();

        // create override on the schedule
        let ov = make_on_call_override(detail.schedule.id, 9);
        let created = s.create_on_call_override(detail.schedule.id, &ov).await.unwrap();
        assert_eq!(created.id, ov.id);
        assert_eq!(created.user_id, ov.user_id);

        // conflict on duplicate id
        let err = s.create_on_call_override(detail.schedule.id, &ov).await.unwrap_err();
        assert!(format!("{err:?}").contains("Conflict"));

        // list by schedule — single row, ordered by starts_at DESC
        let listed = s.list_on_call_overrides(detail.schedule.id).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, ov.id);

        // list for an unknown schedule is empty
        let none = s.list_on_call_overrides(Uuid::now_v7()).await.unwrap();
        assert!(none.is_empty());

        // overrides show up in get_on_call_schedule too
        let got = s.get_on_call_schedule(detail.schedule.id).await.unwrap();
        assert_eq!(got.overrides.len(), 1);
        assert_eq!(got.overrides[0].id, ov.id);

        // delete + NotFound
        s.delete_on_call_override(ov.id).await.unwrap();
        assert!(s.list_on_call_overrides(detail.schedule.id).await.unwrap().is_empty());
        let err = s.delete_on_call_override(ov.id).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn escalation_state_lifecycle() {
        let s = fresh().await;
        let incident_id = Uuid::now_v7();
        let policy_id = Uuid::now_v7();

        // initially absent
        assert!(s.get_escalation_state(incident_id).await.unwrap().is_none());

        // upsert
        let mut state = make_escalation_state(incident_id, policy_id);
        s.upsert_escalation_state(&state).await.unwrap();
        let got = s.get_escalation_state(incident_id).await.unwrap().unwrap();
        assert_eq!(got.policy_id, policy_id);
        assert!(!got.acked);
        assert_eq!(got.current_level, 0);

        // re-upsert (replace) — advance level + next_check_at
        state.current_level = 1;
        state.next_check_at = ts("2026-06-01T00:10:00Z");
        s.upsert_escalation_state(&state).await.unwrap();
        let got2 = s.get_escalation_state(incident_id).await.unwrap().unwrap();
        assert_eq!(got2.current_level, 1);

        // list_due_escalation_states — only the not-yet-due and acked ones
        // are filtered out.
        // Make a second incident that is acked (should not appear in due list).
        let incident2 = Uuid::now_v7();
        let acked_state = IncidentEscalationState {
            incident_id: incident2,
            policy_id,
            current_level: 0,
            current_round: 0,
            last_paged_at: ts("2026-06-01T00:00:00Z"),
            next_check_at: ts("2026-06-01T00:05:00Z"),
            acked: true,
        };
        s.upsert_escalation_state(&acked_state).await.unwrap();

        // now = 00:06 → state due (next_check_at = 00:10? no, we updated to 00:10).
        // First state: next_check_at = 00:10, acked = false → NOT due at 00:06.
        let due_before = s.list_due_escalation_states(ts("2026-06-01T00:06:00Z")).await.unwrap();
        assert!(due_before.is_empty());

        // now = 00:11 → first state due (00:10 ≤ 00:11), acked state still filtered.
        let due = s.list_due_escalation_states(ts("2026-06-01T00:11:00Z")).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].incident_id, incident_id);

        // ack the incident — it should disappear from the due list
        s.ack_escalation_state(incident_id).await.unwrap();
        let got3 = s.get_escalation_state(incident_id).await.unwrap().unwrap();
        assert!(got3.acked);
        let due_after = s.list_due_escalation_states(ts("2026-06-01T00:11:00Z")).await.unwrap();
        assert!(due_after.is_empty());

        // ack on missing state → NotFound
        let err = s.ack_escalation_state(Uuid::now_v7()).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));

        // delete is idempotent
        s.delete_escalation_state(incident_id).await.unwrap();
        assert!(s.get_escalation_state(incident_id).await.unwrap().is_none());
        s.delete_escalation_state(incident_id).await.unwrap();
    }

    // ── Postmortems ─────────────────────────────────────────────────────

    fn make_action_items() -> Vec<ActionItem> {
        vec![
            ActionItem {
                text: "patch the cache invalidator".into(),
                owner_user_id: Some(UserId(Uuid::from_u128(7))),
                done: false,
            },
            ActionItem { text: "add a regression test".into(), owner_user_id: None, done: true },
        ]
    }

    fn make_postmortem_upsert() -> PostmortemUpsert {
        PostmortemUpsert {
            summary: Some("cache stampede took down the API".into()),
            root_cause: Some("missing TTL jitter".into()),
            impact: Some("5xx for 12 minutes".into()),
            action_items: make_action_items(),
        }
    }

    #[tokio::test]
    async fn postmortem_crud_roundtrip() {
        let s = fresh().await;
        let incident_id = Uuid::now_v7();
        let author = Uuid::from_u128(42);

        // initially absent
        assert!(s.get_postmortem(incident_id).await.unwrap().is_none());

        // upsert (create)
        let body = make_postmortem_upsert();
        let pm = s.upsert_postmortem(incident_id, Some(author), &body).await.unwrap();
        assert_eq!(pm.incident_id, incident_id);
        assert_eq!(pm.summary.as_deref(), Some("cache stampede took down the API"));
        assert_eq!(pm.root_cause.as_deref(), Some("missing TTL jitter"));
        assert_eq!(pm.impact.as_deref(), Some("5xx for 12 minutes"));
        assert_eq!(pm.action_items.len(), 2);
        assert_eq!(pm.action_items[0].text, "patch the cache invalidator");
        assert!(pm.action_items[1].done);
        assert_eq!(pm.author_id.map(|u| u.0), Some(author));
        assert!(pm.published_at.is_none());

        // get
        let got = s.get_postmortem(incident_id).await.unwrap().unwrap();
        assert_eq!(got.summary, pm.summary);
        assert_eq!(got.action_items.len(), 2);
        assert!(got.published_at.is_none());

        // publish
        let published = s.publish_postmortem(incident_id).await.unwrap();
        assert!(published.published_at.is_some());
        let got = s.get_postmortem(incident_id).await.unwrap().unwrap();
        assert!(got.published_at.is_some());

        // unpublish
        let unpublished = s.unpublish_postmortem(incident_id).await.unwrap();
        assert!(unpublished.published_at.is_none());
        let got = s.get_postmortem(incident_id).await.unwrap().unwrap();
        assert!(got.published_at.is_none());

        // publish on missing → NotFound
        let err = s.publish_postmortem(Uuid::now_v7()).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
        // unpublish on missing → NotFound
        let err = s.unpublish_postmortem(Uuid::now_v7()).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));

        // delete + absent again
        s.delete_postmortem(incident_id).await.unwrap();
        assert!(s.get_postmortem(incident_id).await.unwrap().is_none());
        // delete is idempotent
        s.delete_postmortem(incident_id).await.unwrap();
    }

    #[tokio::test]
    async fn postmortem_upsert_preserves_published_at() {
        let s = fresh().await;
        let incident_id = Uuid::now_v7();

        // create + publish
        let body = make_postmortem_upsert();
        s.upsert_postmortem(incident_id, None, &body).await.unwrap();
        let published = s.publish_postmortem(incident_id).await.unwrap();
        let original_published_at = published.published_at.expect("published_at set");
        let original_created_at = published.created_at;

        // re-upsert (edit) — published_at must be preserved, created_at too
        let mut body2 = body.clone();
        body2.summary = Some("edited summary".into());
        let edited = s.upsert_postmortem(incident_id, None, &body2).await.unwrap();
        assert_eq!(edited.summary.as_deref(), Some("edited summary"));
        assert_eq!(edited.published_at, Some(original_published_at));
        assert_eq!(edited.created_at, original_created_at);

        // get reflects the preserved published_at
        let got = s.get_postmortem(incident_id).await.unwrap().unwrap();
        assert_eq!(got.published_at, Some(original_published_at));
        assert_eq!(got.created_at, original_created_at);
        assert_eq!(got.summary.as_deref(), Some("edited summary"));
    }

    #[tokio::test]
    async fn postmortem_action_items_roundtrip_json() {
        // Action items carry an owner_user_id that must survive the JSON
        // encode/decode round-trip (the public projection strips it later).
        let s = fresh().await;
        let incident_id = Uuid::now_v7();
        let body = PostmortemUpsert {
            summary: None,
            root_cause: None,
            impact: None,
            action_items: make_action_items(),
        };
        s.upsert_postmortem(incident_id, None, &body).await.unwrap();
        let got = s.get_postmortem(incident_id).await.unwrap().unwrap();
        assert_eq!(got.action_items.len(), 2);
        assert_eq!(got.action_items[0].owner_user_id, Some(UserId(Uuid::from_u128(7))));
        assert_eq!(got.action_items[1].owner_user_id, None);
        assert!(got.action_items[1].done);
    }

    #[tokio::test]
    async fn monitor_share_crud_roundtrip() {
        let s = fresh().await;
        let target_id = Uuid::now_v7();

        // Create a share — the raw token is returned once.
        let created = s.create_monitor_share(target_id, Some("on-call rota"), None).await.unwrap();
        assert!(!created.token.is_empty(), "raw token must be non-empty");
        assert_eq!(created.share.target_id, target_id);
        assert_eq!(created.share.label.as_deref(), Some("on-call rota"));
        assert_eq!(created.share.view_count, 0);
        assert!(created.share.last_viewed_at.is_none());
        // The raw token is never stored on the persisted view.
        assert!(created.share.token.is_none());

        // List — newest-first, one entry.
        let listed = s.list_monitor_shares(target_id).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, created.share.id);
        assert_eq!(listed[0].view_count, 0);
        // Listed shares never carry the raw token.
        assert!(listed[0].token.is_none());

        // Resolve via the raw token (hashed). View count increments.
        let hash = hash_cookie_value(&created.token);
        let resolved = s.resolve_monitor_share(&hash).await.unwrap().unwrap();
        assert_eq!(resolved.target_id, target_id);
        assert_eq!(resolved.share_id, created.share.id);

        // View count + last_viewed_at updated.
        let listed = s.list_monitor_shares(target_id).await.unwrap();
        assert_eq!(listed[0].view_count, 1);
        assert!(listed[0].last_viewed_at.is_some());

        // A second resolve bumps the count again.
        let _ = s.resolve_monitor_share(&hash).await.unwrap().unwrap();
        let listed = s.list_monitor_shares(target_id).await.unwrap();
        assert_eq!(listed[0].view_count, 2);

        // Delete — idempotent.
        s.delete_monitor_share(created.share.id.0).await.unwrap();
        s.delete_monitor_share(created.share.id.0).await.unwrap();
        assert!(s.list_monitor_shares(target_id).await.unwrap().is_empty());

        // After delete, resolve returns None.
        let after = s.resolve_monitor_share(&hash).await.unwrap();
        assert!(after.is_none());
    }

    #[tokio::test]
    async fn monitor_share_expires() {
        let s = fresh().await;
        let target_id = Uuid::now_v7();
        // Mint a share that already expired.
        let past = Utc::now() - chrono::Duration::seconds(60);
        let created = s.create_monitor_share(target_id, None, Some(past)).await.unwrap();

        // Resolve must return None — expired tokens never match.
        let hash = hash_cookie_value(&created.token);
        let resolved = s.resolve_monitor_share(&hash).await.unwrap();
        assert!(resolved.is_none());

        // The row still exists (expired ≠ deleted) so it shows in the list.
        let listed = s.list_monitor_shares(target_id).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].view_count, 0, "expired resolve must not bump view_count");
    }
}
