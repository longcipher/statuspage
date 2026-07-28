# StatusPage — Production Deployment

This directory contains the production deployment assets for StatusPage:
**rpxy reverse proxy** (TLS termination, HTTP/2 + HTTP/3) in front of
the `status-server` Rust binary, which embeds DuckDB for all storage.

No external databases are required — DuckDB runs in-process inside the
`status-server` binary, persisting to a single file under `/opt/statuspage/`.

## What this gives you

| Concern | How it's handled |
|---|---|
| TLS certificates | Automatic via Let's Encrypt TLS-ALPN-01 ACME |
| HTTP/2 + HTTP/3 | Enabled by default in rpxy |
| Public health probes | `/healthz` and `/readyz` exposed without auth |
| Metrics blocking | `/metrics` returned 404 by the backend (configure in your app) |
| Security headers | Handled by `status-server` (HSTS, X-Frame-Options, etc.) |
| Access logging | Via rpxy access log, rotated automatically |
| Database | DuckDB embedded in the server — no external DB, no DB ports |
| Health checking | Active HTTP health check on upstream `/healthz` |
| Process supervision | systemd restarts both rpxy and status-server on crash |

## Prerequisites

- A Linux host (any cloud, any VPS, your own metal)
- Public IP with **ports 80 and 443 open**
- Rust 1.75+ (for building), or a pre-built `status-server` binary
- rpxy binary ([build from source](https://github.com/junkurihara/rust-rpxy) or use [prebuilt packages](https://rpxy.gamerboy59.dev))
- systemd (every modern Linux distro ships it)
- DNS A/AAAA record pointing your domain to this host

## Files

| File | Purpose |
|---|---|
| `config.toml` | rpxy reverse proxy config (TLS + routing + health checks) |
| `statuspage.service` | systemd unit file for the `status-server` binary |
| `rpxy.service` | systemd unit file for the rpxy reverse proxy |
| `README.md` | This file |

## First-time setup

### 1. Build the binary and frontend

On a build host (or the target host) with Rust 1.75+ and the `wasm32` target installed:

```bash
just fe-build
cargo build -p status-server --release
```

### 2. Install rpxy

Option A — build from source:

```bash
git clone https://github.com/junkurihara/rust-rpxy
cd rust-rpxy
git submodule update --init
cargo build --release
sudo cp target/release/rpxy /usr/local/bin/
```

Option B — use prebuilt packages (Linux RPM/DEB):

See <https://rpxy.gamerboy59.dev> for prebuilt packages.

Option C — Docker:

```bash
docker pull jqtype/rpxy
```

### 3. Install onto the host

```bash
sudo cp target/release/status-server /usr/local/bin/
sudo mkdir -p /opt/statuspage
sudo cp config/default.toml /opt/statuspage/
sudo cp -r target/site /opt/statuspage/
sudo cp deployment/config.toml /opt/statuspage/
sudo cp deployment/statuspage.service /etc/systemd/system/
sudo cp deployment/rpxy.service /etc/systemd/system/
```

Edit `/opt/statuspage/config.toml` — replace the placeholders:

- `STATUSPAGE_DOMAIN_PLACEHOLDER` → your domain (e.g. `status.example.com`)
- `ACME_EMAIL_PLACEHOLDER` → your email for Let's Encrypt notifications

Edit `/opt/statuspage/default.toml` to set your KEK, OAuth
credentials, and any other site-specific values. Secrets are better
supplied via environment variables in a systemd drop-in
(`systemctl edit statuspage` → add `[Service]` `Environment=` lines).

### 4. Create system users

```bash
sudo useradd -r -s /sbin/nologin statuspage
sudo useradd -r -s /sbin/nologin rpxy
sudo chown -R statuspage:statuspage /opt/statuspage
```

### 5. Start the stack

```bash
# Create log directory for rpxy
sudo mkdir -p /var/log/rpxy
sudo chown rpxy:rpxy /var/log/rpxy

# Enable + start the services
sudo systemctl daemon-reload
sudo systemctl enable --now statuspage
sudo systemctl enable --now rpxy
```

Visit `https://<your-domain>`. On first start rpxy will issue the TLS
certificate via ACME (typically within 30-60 seconds).

## How rpxy compares to Caddy

| Feature | Caddy | rpxy |
|---|---|---|
| TLS certificates | HTTP-01 ACME | TLS-ALPN-01 ACME |
| HTTP/3 | Via QUIC module | Via Quinn (default) |
| Config format | Caddyfile | TOML |
| Rate limiting | Via caddy-ratelimit plugin | Not built-in (use backend or firewall) |
| Security headers | Built-in header directive | Backend handles |
| Compression | Built-in encode directive | Backend handles |
| Health checks | reverse_proxy health_uri | Active health_check (TCP/HTTP) |
| Binary size | ~50 MB | ~10 MB |
| Written in | Go | Rust |

## Backups

StatusPage stores all data in a single DuckDB file at
`/opt/statuspage/statuspage.db` (path set by `storage.duckdb_path`).
Back it up with either of these approaches:

### Simple file copy (offline or snapshot)

```bash
# Stop the server so no writes are in flight, copy, restart.
sudo systemctl stop statuspage
sudo cp /opt/statuspage/statuspage.db ./statuspage-$(date +%Y%m%d).db
sudo systemctl start statuspage
```

### DuckDB EXPORT DATABASE (online, consistent)

```bash
# If duckdb CLI is available on the host:
duckdb /opt/statuspage/statuspage.db "EXPORT DATABASE 'backup_dir'"
```

### ACME certificate data

ACME certs re-issue automatically, but backing up the registry
avoids hitting Let's Encrypt rate limits on a full rebuild:

```bash
sudo tar czf acme-$(date +%Y%m%d).tar.gz -C /opt/statuspage acme_registry
```

## Upgrading

```bash
# Build the new binary on a build host
cargo build -p status-server --release

# Copy it to the target, then restart
sudo cp target/release/status-server /usr/local/bin/
sudo systemctl restart statuspage
```

rpxy's active health check (every 10s) pulls the upstream out of
rotation while it's down and back in once it recovers. For
zero-downtime upgrades, run two `status-server` replicas behind rpxy's
load balancer.

## Troubleshooting

**Certificate fails to provision**

- DNS not propagated? `dig +short status.example.com`
- Ports 80/443 blocked? Test from another host: `curl -v http://status.example.com`
- Hit Let's Encrypt rate limit? Uncomment the `dir_url` staging line in `config.toml`

**rpxy can't reach status-server**
```bash
sudo systemctl status statuspage
curl -fsS http://127.0.0.1:8081/healthz
```

**Check logs**
```bash
sudo journalctl -u statuspage -f          # server logs (journald)
sudo journalctl -u rpxy -f                # reverse proxy logs (journald)
sudo journalctl -u statuspage --since "1 hour ago"
sudo journalctl -u rpxy --since "1 hour ago"
```

**rpxy config hot-reload**

rpxy watches `config.toml` for changes and applies them without restart:

```bash
# After editing /opt/statuspage/config.toml, changes take effect immediately
sudo systemctl status rpxy   # confirm it's running
```
