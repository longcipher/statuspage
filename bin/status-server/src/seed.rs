//! Config-driven seed: syncs notification channels, targets, and status
//! pages from TOML config into DuckDB on startup. Idempotent — skips
//! items that already exist (matched by name / slug).
//!
//! Config format (in the TOML file pointed to by `STATUSPAGE_CONFIG_PATH`):
//!
//! ```toml
//! [[seed.notification_channels]]
//! name = "Telegram Alerts"
//!
//! [seed.notification_channels.config]
//! type = "telegram"
//! bot_token = "xxx"
//! chat_id = "-100xxx"
//!
//! [[seed.targets]]
//! name = "My Service"
//! group_name = "Production"
//! interval_secs = 30
//! alert_confirmations = 3
//! channel_names = ["Telegram Alerts"]
//!
//! [seed.targets.check]
//! type = "http"
//! url = "https://example.com/health"
//! method = "GET"
//! timeout = 5000
//! follow_redirects = true
//! max_redirects = 5
//! expected_status = { kind = "exact", value = 200 }
//! verify_tls = true
//!
//! [[seed.status_pages]]
//! name = "LongCipher Status"
//! slug = "status"
//! ```

use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use serde::Deserialize;
use statuscore::domain::alert::{AlertBinding, TargetAlerts};
use statuscore::domain::check::CheckSpec;
use statuscore::domain::org::OrgId;
use statuscore::domain::{
    ChannelConfig, NewNotificationChannel, StatusPage, StatusPageComponent, StatusPageId, Target,
    WriteSource,
};
use storage::Storage;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct SeedConfig {
    #[serde(default)]
    pub notification_channels: Vec<SeedChannelConfig>,
    #[serde(default)]
    pub targets: Vec<SeedTargetConfig>,
    #[serde(default)]
    pub status_pages: Vec<SeedStatusPageConfig>,
}

#[derive(Debug, Deserialize)]
pub struct SeedChannelConfig {
    pub name: String,
    pub config: ChannelConfig,
}

#[derive(Debug, Deserialize)]
pub struct SeedTargetConfig {
    pub name: String,
    pub check: CheckSpec,
    pub interval_secs: u64,
    #[serde(default)]
    pub group_name: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_alert_confirmations")]
    pub alert_confirmations: u32,
    #[serde(default = "default_true")]
    pub notify_recovery: bool,
    #[serde(default = "default_renotify_interval_secs")]
    pub renotify_interval_secs: u32,
    /// Notification channel names to bind. Resolved to UUIDs after channels
    /// are synced. Empty = no alerts.
    #[serde(default)]
    pub channel_names: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SeedStatusPageConfig {
    pub name: String,
    pub slug: String,
    /// Page title shown to public visitors. Defaults to `name`.
    #[serde(default)]
    pub title: Option<String>,
}

const fn default_alert_confirmations() -> u32 {
    3
}
const fn default_true() -> bool {
    true
}
const fn default_renotify_interval_secs() -> u32 {
    3600
}

/// Load seed config from the same TOML file used by `AppConfig`. Returns
/// `None` when no `[seed]` section exists.
pub fn load_seed_config() -> Option<SeedConfig> {
    let config_path = std::env::var("STATUSPAGE_CONFIG_PATH")
        .unwrap_or_else(|_| "config/default.toml".to_string());

    let builder = config::Config::builder()
        .add_source(config::File::from(std::path::PathBuf::from(&config_path)).required(false));

    let cfg = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "failed to load config for seed");
            return None;
        }
    };

    match cfg.get::<SeedConfig>("seed") {
        Ok(seed) => Some(seed),
        Err(config::ConfigError::NotFound(_)) => None,
        Err(e) => {
            tracing::warn!(error = %e, "failed to parse [seed] config; skipping");
            None
        }
    }
}

/// Sync notification channels, targets, and status pages from config into
/// storage. Idempotent: existing items (matched by name / slug) are skipped.
pub async fn sync_from_config(storage: &dyn Storage, seed: &SeedConfig) {
    // 1. Sync notification channels and build name→id map.
    let mut channel_ids: HashMap<String, Uuid> = HashMap::new();
    for ch in &seed.notification_channels {
        if let Some(existing) = find_channel_by_name(storage, &ch.name).await {
            tracing::info!(name = %ch.name, id = %existing, "notification channel exists, skipping");
            channel_ids.insert(ch.name.clone(), existing);
        } else {
            let new_ch = NewNotificationChannel {
                name: ch.name.clone(),
                config: ch.config.clone(),
                enabled: true,
            };
            match storage.create_notification_channel(&new_ch).await {
                Ok(created) => {
                    tracing::info!(name = %ch.name, id = %created.id, "created notification channel");
                    channel_ids.insert(ch.name.clone(), created.id);
                }
                Err(e) => {
                    tracing::error!(name = %ch.name, error = %e, "failed to create notification channel");
                }
            }
        }
    }

    // 2. Sync targets. Track created target ids for status page binding.
    let existing_targets = storage.list_targets().await.unwrap_or_default();
    let mut target_ids: HashMap<String, Uuid> =
        existing_targets.iter().map(|t| (t.name.clone(), t.id)).collect();

    for t in &seed.targets {
        if target_ids.contains_key(&t.name) {
            tracing::info!(name = %t.name, "target exists, skipping");
            continue;
        }

        let alerts = if t.channel_names.is_empty() {
            TargetAlerts::default()
        } else {
            let bindings: Vec<AlertBinding> = t
                .channel_names
                .iter()
                .filter_map(|name| channel_ids.get(name).map(|id| AlertBinding { channel_id: *id }))
                .collect();
            if bindings.len() != t.channel_names.len() {
                tracing::warn!(
                    target = %t.name,
                    requested = ?t.channel_names,
                    "some channel names not found; target will use available channels only"
                );
            }
            TargetAlerts(bindings)
        };

        let target = Target {
            id: Uuid::now_v7(),
            name: t.name.clone(),
            check: t.check.clone(),
            interval: Duration::from_secs(t.interval_secs),
            enabled: true,
            tags: t.tags.clone(),
            alerts,
            alert_confirmations: t.alert_confirmations,
            notify_recovery: t.notify_recovery,
            renotify_interval_secs: t.renotify_interval_secs,
            region_policy: Default::default(),
            group_name: t.group_name.clone(),
            owner_user_id: None,
            escalation_policy_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            write_source: WriteSource::Terraform,
        };

        match storage.create_target(&target).await {
            Ok(created) => {
                tracing::info!(name = %t.name, id = %created.id, check = %t.check.kind(), "created target from config");
                target_ids.insert(t.name.clone(), created.id);
            }
            Err(e) => {
                tracing::error!(name = %t.name, error = %e, "failed to create target from config");
            }
        }
    }

    // 3. Sync status pages: create page + bind all seed targets as components.
    let existing_pages = storage.list_status_pages().await.unwrap_or_default();
    let existing_slugs: HashMap<String, Uuid> =
        existing_pages.iter().map(|p| (p.slug.clone(), p.id.0)).collect();

    for sp in &seed.status_pages {
        let page_id = if let Some(&id) = existing_slugs.get(&sp.slug) {
            tracing::info!(slug = %sp.slug, id = %id, "status page exists, skipping create");
            id
        } else {
            let page = StatusPage {
                id: StatusPageId(Uuid::now_v7()),
                org_id: OrgId(Uuid::nil()),
                slug: sp.slug.clone(),
                name: sp.name.clone(),
                enabled: true,
                branding: statuscore::domain::org::PublicOrgBranding {
                    public_display_name: sp.title.clone().or_else(|| Some(sp.name.clone())),
                    public_show_powered_by: Some(false),
                    ..Default::default()
                },
                write_source: WriteSource::Terraform,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            match storage.create_status_page(&page).await {
                Ok(created) => {
                    tracing::info!(slug = %sp.slug, id = %created.id, "created status page");
                    created.id.0
                }
                Err(e) => {
                    tracing::error!(slug = %sp.slug, error = %e, "failed to create status page");
                    continue;
                }
            }
        };

        // Build seed targets grouped for component binding.
        let seed_target_map: HashMap<&str, &SeedTargetConfig> =
            seed.targets.iter().map(|t| (t.name.as_str(), t)).collect();

        for (idx, (name, &target_id)) in target_ids.iter().enumerate() {
            let group = seed_target_map
                .get(name.as_str())
                .and_then(|t| t.group_name.as_deref())
                .unwrap_or("General");

            let component = StatusPageComponent {
                target_id,
                monitor_name: name.clone(),
                public_name: None,
                public_description: None,
                public_group: Some(group.to_string()),
                sort_order: idx as i32,
            };

            if let Err(e) = storage.set_status_page_component(page_id, &component).await {
                tracing::warn!(target = %name, page = %sp.slug, error = %e, "failed to bind component");
            }
        }

        tracing::info!(
            slug = %sp.slug,
            components = target_ids.len(),
            "status page synced with all targets"
        );
    }
}

async fn find_channel_by_name(storage: &dyn Storage, name: &str) -> Option<Uuid> {
    let channels = storage.list_notification_channels().await.ok()?;
    channels.iter().find(|c| c.name == name).map(|c| c.id)
}
