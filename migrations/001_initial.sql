CREATE TABLE IF NOT EXISTS targets (
                id UUID PRIMARY KEY,
                name VARCHAR NOT NULL,
                enabled BOOLEAN NOT NULL,
                payload JSON NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL
            );

            CREATE TABLE IF NOT EXISTS check_results (
                target_id UUID NOT NULL,
                org_id UUID NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                status VARCHAR NOT NULL,
                duration_ms INTEGER NOT NULL,
                payload JSON NOT NULL,
                PRIMARY KEY (target_id, timestamp)
            );
            CREATE INDEX IF NOT EXISTS idx_check_results_target_ts
                ON check_results(target_id, timestamp DESC);

            CREATE TABLE IF NOT EXISTS incidents (
                id UUID PRIMARY KEY,
                target_id UUID NOT NULL,
                started_at TIMESTAMP NOT NULL,
                ended_at TIMESTAMP,
                severity VARCHAR NOT NULL,
                payload JSON NOT NULL,
                created_at TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_target ON incidents(target_id);
            CREATE INDEX IF NOT EXISTS idx_incidents_started ON incidents(started_at DESC);

            CREATE TABLE IF NOT EXISTS status_pages (
                id UUID PRIMARY KEY,
                org_id UUID NOT NULL,
                slug VARCHAR UNIQUE NOT NULL,
                name VARCHAR NOT NULL,
                enabled BOOLEAN NOT NULL,
                payload JSON NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL
            );

            -- Status page ↔ target binding (many-to-many with per-page curation).
            -- `payload` carries the full StatusPageComponent JSON (public_name,
            -- public_group, sort_order, etc.); `sort_order` and `target_id`
            -- are projected out so the listing query can ORDER BY without
            -- touching the JSON.
            CREATE TABLE IF NOT EXISTS status_page_components (
                status_page_id UUID NOT NULL,
                target_id UUID NOT NULL,
                sort_order INTEGER NOT NULL,
                monitor_name VARCHAR NOT NULL,
                payload JSON NOT NULL,
                PRIMARY KEY (status_page_id, target_id)
            );

            -- Heartbeat pings: one row per heartbeat target, storing the most
            -- recent inbound ping timestamp. The scheduler's heartbeat
            -- evaluator reads this to decide up/down (now - last_ping >
            -- period + grace → Down).
            CREATE TABLE IF NOT EXISTS heartbeat_pings (
                target_id UUID PRIMARY KEY,
                last_ping_at TIMESTAMP NOT NULL
            );

            -- Maintenance windows. `component_ids` is a JSON array of target
            -- UUIDs affected by the window; projected columns (starts_at,
            -- ends_at) let the active-window query filter without JSON scan.
            CREATE TABLE IF NOT EXISTS maintenance_windows (
                id UUID PRIMARY KEY,
                title VARCHAR NOT NULL,
                starts_at TIMESTAMP NOT NULL,
                ends_at TIMESTAMP NOT NULL,
                payload JSON NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_maintenance_active
                ON maintenance_windows(starts_at, ends_at);

            -- Silence rules: operator-defined windows that suppress
            -- notification delivery for matching incidents. Projected
            -- columns (target_id, channel_id, starts_at, ends_at) let the
            -- active-rule lookup index without JSON scan; the full rule
            -- (incl. `reasons` whitelist) lives in the JSON payload.
            CREATE TABLE IF NOT EXISTS silence_rules (
                id UUID PRIMARY KEY,
                title VARCHAR NOT NULL,
                target_id UUID,
                channel_id UUID,
                starts_at TIMESTAMP NOT NULL,
                ends_at TIMESTAMP NOT NULL,
                payload JSON NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_silence_active_target
                ON silence_rules(starts_at, ends_at, target_id);

            -- Public status page subscribers (double opt-in). `verified_at`
            -- is NULL until the subscriber confirms via the verify endpoint.
            CREATE TABLE IF NOT EXISTS subscribers (
                id UUID PRIMARY KEY,
                status_page_id UUID NOT NULL,
                org_id UUID NOT NULL,
                channel VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                config JSON NOT NULL,
                verified_at TIMESTAMP,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_subscribers_page
                ON subscribers(status_page_id);

            -- Reusable org-scoped variables for `{{key}}` interpolation in
            -- HTTP check headers / bodies. Plain variables store the value
            -- inline; secret variables store the value inline too (v1 is
            -- single-tenant, self-hosted — no envelope crypto yet). The
            -- `is_secret` flag drives redaction on read.
            CREATE TABLE IF NOT EXISTS variables (
                id UUID PRIMARY KEY,
                key VARCHAR NOT NULL,
                is_secret BOOLEAN NOT NULL,
                value VARCHAR NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                UNIQUE(key)
            );

            -- Notification channels (operator alerting). The full
            -- NotificationChannel (config, disabled_reason, verified_at,
            -- write_source) lives in `payload`; `name`/`kind`/`enabled`
            -- are projected out so list/filter queries avoid JSON scan.
            CREATE TABLE IF NOT EXISTS notification_channels (
                id UUID PRIMARY KEY,
                name VARCHAR NOT NULL,
                kind VARCHAR NOT NULL,
                enabled BOOLEAN NOT NULL,
                payload JSON NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL
            );

            -- Target ↔ channel many-to-many binding.
            CREATE TABLE IF NOT EXISTS target_channel_bindings (
                target_id UUID NOT NULL,
                channel_id UUID NOT NULL,
                created_at TIMESTAMP NOT NULL,
                PRIMARY KEY (target_id, channel_id)
            );
            CREATE INDEX IF NOT EXISTS idx_target_channel_bindings_channel
                ON target_channel_bindings(channel_id);

            -- Channel verification tokens. `token_hash` is sha256_hex of the
            -- raw token (the raw token goes in the email link, never stored).
            -- Atomic consumption via
            -- `UPDATE ... SET used_at = now() WHERE used_at IS NULL`.
            CREATE TABLE IF NOT EXISTS channel_verification_tokens (
                id UUID PRIMARY KEY,
                channel_id UUID NOT NULL,
                token_hash VARCHAR NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used_at TIMESTAMP,
                created_at TIMESTAMP NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_channel_verify_tokens_hash
                ON channel_verification_tokens(token_hash);

            -- Subscriber delivery dispatch log. One row per attempted
            -- notification; the dispatcher claims Pending rows, attempts
            -- delivery, and marks them Sent / Failed / DeadLetter.
            CREATE TABLE IF NOT EXISTS subscriber_deliveries (
                id UUID PRIMARY KEY,
                subscriber_id UUID NOT NULL,
                status_page_id UUID NOT NULL,
                channel VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                payload TEXT NOT NULL,
                reason VARCHAR NOT NULL,
                status VARCHAR NOT NULL,
                attempts INTEGER NOT NULL,
                last_error TEXT,
                created_at TIMESTAMP NOT NULL,
                sent_at TIMESTAMP,
                next_attempt_at TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_subscriber_deliveries_status
                ON subscriber_deliveries(status, created_at);

            -- Cached last-good RDAP state for domain-expiry checks.
            CREATE TABLE IF NOT EXISTS domain_expiry_states (
                target_id UUID PRIMARY KEY,
                domain VARCHAR NOT NULL,
                expires_at DATE,
                registrar VARCHAR,
                fetched_at TIMESTAMP NOT NULL
            );

            -- ── Auth tables ───────────────────────────────────────────────
            -- Single-tenant: no org_id columns. Soft-delete via `deleted_at`;

            -- Users. Email is normalized (trim + lowercase) on write and
            -- unique among non-deleted rows. Soft-delete tombstone in
            -- `deleted_at`; the purge job hard-deletes after the grace window.
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY,
                email VARCHAR NOT NULL,
                display_name VARCHAR,
                email_verified_at TIMESTAMP,
                last_seen_at TIMESTAMP,
                theme VARCHAR NOT NULL DEFAULT 'default',
                time_format VARCHAR NOT NULL DEFAULT 'auto',
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                deleted_at TIMESTAMP
            );
            -- DuckDB lacks partial indexes, so this is a plain UNIQUE on
            -- `email`. The app layer cooperates: on soft-delete it appends a
            -- tombstone suffix (e.g. `user@example.comdeleted_<uuid>`) so the
            -- original email stays free for re-registration while the soft-
            -- deleted row keeps a distinct value satisfying the constraint.
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email
                ON users(email);

            -- Sessions. `id_hash` = sha256_hex(cookie_value); the raw cookie
            -- never lives in the DB. Double timeout enforced in app layer.
            CREATE TABLE IF NOT EXISTS sessions (
                id_hash VARCHAR PRIMARY KEY,
                user_id UUID NOT NULL,
                created_at TIMESTAMP NOT NULL,
                last_used_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                ip_hash VARCHAR,
                user_agent_hash VARCHAR
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_user
                ON sessions(user_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires
                ON sessions(expires_at);

            -- API tokens. `token_hash` is an argon2id PHC string;
            -- `token_prefix` is a non-unique lookup index (first N chars).
            CREATE TABLE IF NOT EXISTS api_tokens (
                id UUID PRIMARY KEY,
                user_id UUID NOT NULL,
                name VARCHAR NOT NULL,
                token_hash VARCHAR NOT NULL,
                token_prefix VARCHAR NOT NULL,
                scopes JSON NOT NULL,
                created_at TIMESTAMP NOT NULL,
                last_used_at TIMESTAMP,
                expires_at TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_api_tokens_prefix
                ON api_tokens(token_prefix);
            CREATE INDEX IF NOT EXISTS idx_api_tokens_user
                ON api_tokens(user_id, created_at DESC);

            -- Magic links. `token_hash` is argon2id; `token_prefix` is the
            -- non-unique lookup index. Atomic consumption via
            -- `UPDATE ... SET used_at = now() WHERE used_at IS NULL`.
            CREATE TABLE IF NOT EXISTS magic_link_tokens (
                id UUID PRIMARY KEY,
                email VARCHAR NOT NULL,
                token_hash VARCHAR NOT NULL,
                token_prefix VARCHAR NOT NULL,
                created_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used_at TIMESTAMP,
                ip_hash VARCHAR,
                redirect_after VARCHAR
            );
            CREATE INDEX IF NOT EXISTS idx_magic_links_prefix
                ON magic_link_tokens(token_prefix);
            CREATE INDEX IF NOT EXISTS idx_magic_links_expires
                ON magic_link_tokens(expires_at);

            -- Escalation policies. The full policy (steps + targets) is
            -- serialised into `payload` as JSON; `name` is projected out for
            -- list filtering.
            CREATE TABLE IF NOT EXISTS escalation_policies (
                id UUID PRIMARY KEY,
                name VARCHAR NOT NULL,
                description VARCHAR,
                repeat_count INTEGER NOT NULL DEFAULT 0,
                payload JSON NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_escalation_policies_name
                ON escalation_policies(name);

            -- On-call schedules. The full schedule (layers + participants)
            -- is in `payload`; `name` and `timezone` projected out.
            CREATE TABLE IF NOT EXISTS on_call_schedules (
                id UUID PRIMARY KEY,
                name VARCHAR NOT NULL,
                timezone VARCHAR NOT NULL,
                payload JSON NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_on_call_schedules_name
                ON on_call_schedules(name);

            -- On-call overrides (one-off coverage swaps). Stored separately
            -- from the schedule aggregate so the calendar can manage them
            -- out of band.
            CREATE TABLE IF NOT EXISTS on_call_overrides (
                id UUID PRIMARY KEY,
                schedule_id UUID NOT NULL,
                user_id UUID NOT NULL,
                starts_at TIMESTAMP NOT NULL,
                ends_at TIMESTAMP NOT NULL,
                created_by UUID,
                created_at TIMESTAMP NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_on_call_overrides_schedule
                ON on_call_overrides(schedule_id, starts_at DESC);

            -- Incident escalation state (tracks per-incident progress through
            -- a policy's ladder so the engine knows where to resume).
            CREATE TABLE IF NOT EXISTS incident_escalation_state (
                incident_id UUID PRIMARY KEY,
                policy_id UUID NOT NULL,
                current_level INTEGER NOT NULL DEFAULT 0,
                current_round INTEGER NOT NULL DEFAULT 0,
                last_paged_at TIMESTAMP NOT NULL,
                next_check_at TIMESTAMP NOT NULL,
                acked BOOLEAN NOT NULL DEFAULT FALSE
            );
            CREATE INDEX IF NOT EXISTS idx_escalation_state_next_check
                ON incident_escalation_state(next_check_at);
            CREATE INDEX IF NOT EXISTS idx_escalation_state_policy
                ON incident_escalation_state(policy_id);

            -- Postmortems. One per incident. `action_items` is a JSON array.
            -- `summary` / `root_cause` / `impact` are nullable to match the
            -- domain type (`Option<String>`); `published_at` is NULL until
            -- the operator publishes.
            CREATE TABLE IF NOT EXISTS incident_postmortems (
                incident_id UUID PRIMARY KEY,
                summary TEXT,
                root_cause TEXT,
                impact TEXT,
                action_items JSON NOT NULL DEFAULT '[]',
                author_id UUID,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                published_at TIMESTAMP
            );

            -- Monitor share links. `token_hash` is sha256_hex(raw_token); the
            -- raw token is never stored. `view_count` increments on each
            -- resolve. Single-tenant: no `org_id` column — the resolve path
            -- threads `OrgId(Uuid::nil())` for downstream tenant scoping.
            CREATE TABLE IF NOT EXISTS monitor_shares (
                id UUID PRIMARY KEY,
                target_id UUID NOT NULL,
                label VARCHAR,
                token_hash VARCHAR NOT NULL UNIQUE,
                created_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP,
                view_count BIGINT NOT NULL DEFAULT 0,
                last_viewed_at TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_monitor_shares_target
                ON monitor_shares(target_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_monitor_shares_hash
                ON monitor_shares(token_hash);

            -- Per-status-page named assets (logo, future: favicon, og:image,
            -- custom css, ...). One row per (page, slot). `data` is the raw
            -- file bytes (BLOB); `hash` is sha256_hex(data) — used as a
            -- cache-buster on the public logo URL. Replacing a slot reuses
            -- `created_at` and bumps `updated_at` (see `upload_page_asset`).
            CREATE TABLE IF NOT EXISTS page_assets (
                status_page_id UUID NOT NULL,
                slot VARCHAR NOT NULL,
                content_type VARCHAR NOT NULL,
                data BLOB NOT NULL,
                hash VARCHAR NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                PRIMARY KEY (status_page_id, slot)
            );
