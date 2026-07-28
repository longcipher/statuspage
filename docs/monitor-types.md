# Monitor types

Eight kinds of check are defined, each answering a different question. Picking the right one matters more than tuning it afterwards: a monitor that watches the wrong layer either misses the outage or pages you for something that was never broken.

StatusPage is a single-process deployment with no agent runtime, so only **four kinds run in-process** — `http`, `tcp`, `ping`, `heartbeat`. The other four (`dns`, `tls_cert`, `domain_expiry`, `flow`) are agent-only: their specs are accepted and stored, but every scheduled tick records `CheckStatus::Error` with `check kind '<k>' is not supported on the control plane; it requires an agent`. They are documented below for forward compatibility; until an agent runtime exists, prefer the four in-process kinds.

The exact payload for each is in [REST API](api.md#check-specs). This page is about which to reach for.

## Choosing

| You want to know | Use | In-process? |
|---|---|---|
| Is my site or API answering correctly | HTTP | yes |
| Is this port open at all | TCP | yes |
| Is this host reachable on the network | Ping | yes |
| Did my cron job or worker run | Heartbeat | yes |
| Is my certificate about to expire | TLS certificate | no (agent-only) |
| Is my domain about to expire | Domain expiry | no (agent-only) |
| Does this hostname still resolve where it should | DNS | no (agent-only) |
| Can a real user still log in | Flow | no (agent-only) |

Most installs run mostly HTTP monitors and a heartbeat per scheduled job; the agent-only kinds are defined for when an agent runtime is added.

## HTTP

The default. Requests a URL and decides up or down from the response.

Beyond status codes you can require a substring in the body, send custom headers, pick the method, post a body, and control redirect following. Expected status can be an exact code, a range, or a set, so an endpoint that legitimately answers 204 or 301 does not need a workaround.

Two behaviours worth knowing, because they prevent false pages:

- A `429` or `503` is recorded as **degraded**, not down. The upstream is answering and asking you to back off, which is not an outage. If you genuinely expect those codes, list them in the expected status and they count as up.
- Checks against the same host and port are throttled (default 2 in-flight), so a burst of monitors against one upstream cannot look like a probe. An over-cap tick is dropped rather than recorded, so it never counts as a failure and never alerts.

Point it at a real health endpoint rather than the homepage where you can. A homepage can render fine while the database behind it is gone.

Credentials do not belong in this form. Reference a secret variable from a header instead, see [Variables](api.md#variables).

## TCP

Opens a connection to a host and port and reports whether it was accepted. No protocol knowledge, no payload.

Right for databases, message brokers, SMTP, SSH, and anything else that speaks a protocol you cannot easily assert on. Wrong as a substitute for HTTP: a listening port proves the process is alive, not that it is serving correct responses.

## Ping

One ICMP echo, timed. Answers reachability and round-trip latency only.

Useful for routers, gateways, and hosts that expose nothing else. Silence for the whole timeout is down, since ICMP has no way to refuse. Plenty of networks and cloud providers drop ICMP entirely, so confirm the target answers a ping at all before relying on it.

Self-hosting note: the probe opens an unprivileged `SOCK_DGRAM` ICMP socket, so on Linux the process needs `net.ipv4.ping_group_range` to cover its GID (configure via sysctl, including under systemd) or `CAP_NET_RAW`; without either, ping checks report `error`.

## Heartbeat

The direction is reversed. Instead of us probing you, your system calls a URL we give you, and we alert when the call stops arriving.

This is how you monitor things that have no endpoint to poll: nightly backups, cron jobs, queue workers, data pipelines. Creating one mints a ping URL; call it at the end of each successful run, typically by appending `curl -fsS $URL` to the job.

You set a **period** (how often you expect the ping) and a **grace** (how late it may be before it counts as failed). A job that runs hourly with a ten-minute grace alerts eleven minutes after a missed run. A fresh or re-enabled monitor gets a full period plus grace before it can go down, so creating one at an awkward moment does not page you immediately.

Pick grace with your deployment in mind. A ping sent while the control plane is unreachable is lost, so on a single-node self-host keep grace comfortably above your restart window.

Heartbeats are passive: the scheduler evaluates `last_ping_at` in storage rather than probing the network, so `POST /targets/test` and `POST /targets/{id}/check-now` do not apply to them (`NOT_TESTABLE`) — there is nothing on our side to probe.

## TLS certificate

Connects, reads the certificate, and reports how many days remain.

Two thresholds: a **warn** count that marks the monitor degraded, and a **critical** count that marks it down. The form starts at 30 and 7 days. Keep the warn threshold above your renewal automation's window, so a failed renewal surfaces while there is still time to fix it by hand.

Certificates move slowly, so the minimum interval is one hour. Checking more often tells you nothing new.

**Agent-only.** This kind is accepted and stored but is not executed in-process; every tick records `CheckStatus::Error` with `check kind 'tls_cert' is not supported on the control plane; it requires an agent`.

## Domain expiry

Asks the registry how long is left on the domain registration itself, through RDAP.

Different failure from TLS and often worse: an expired certificate breaks HTTPS, an expired domain hands your name back to the market. Same warn and critical day thresholds, same hourly floor. Worth one per domain you own, set to warn generously, since registrar transfers and renewal disputes take weeks rather than minutes.

**Agent-only.** Stored but not executed in-process; every tick records `CheckStatus::Error`. Also rejected by `POST /targets/test` with `NOT_TESTABLE` (needs cached RDAP state).

## DNS

Resolves a name and checks the answer.

Pick a record type (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`, `PTR`, `CAA`, `SRV`), optionally a specific resolver to query, and optionally a substring the answer must contain.

That last option is the point of the check. Without it, any answer at all counts as up, so you learn only that the name still resolves. With it, you learn that it resolves **to the right place** — which is what catches a hijacked record, a bad registrar change, or a regional misroute that a plain HTTP check from one location would sail straight past.

An empty answer, including NXDOMAIN, is down. So is a mismatch when you have set an expected substring, and so is a resolver that fails outright. Querying a specific resolver is how you verify propagation: point one monitor at your authoritative server and another at a public resolver, and a gap between them is a propagation problem.

**Agent-only.** Stored but not executed in-process; every tick records `CheckStatus::Error`.

## Flow

Drives a real headless browser through a scripted sequence, so it verifies that a user can still log in rather than that the login endpoint returns 200.

Steps run in order: navigate, fill a field, click, wait for a selector, assert text, assert URL. At least one assertion is required, so a broken login fails instead of quietly passing. Up to 30 steps, with a whole-run budget and a per-step selector timeout.

This is the check that catches what nothing else does: an expired OAuth secret, a broken JavaScript bundle, a session cookie that stopped being set. It is also the heaviest, so the minimum interval is five minutes.

Use a dedicated low-privilege account, never a real or admin login. Put the password in a secret variable and reference it as `{{key}}` in the fill step, so the stored config holds the reference rather than the credential. See [Variables](api.md#variables).

**Agent-only.** Stored but not executed in-process; every tick records `CheckStatus::Error`. A flow needs a headless browser engine, which this deployment does not ship.

## Intervals

Every kind has a floor enforced by `min_interval_secs_for_kind`. The effective minimum is that floor.

| Kind | Floor |
|---|---|
| HTTP, TCP, Ping, DNS | 10 seconds |
| Heartbeat | 60 seconds (evaluation cadence) |
| Flow | 5 minutes |
| TLS certificate, domain expiry | 1 hour |

Faster is not better. Interval decides how quickly you detect an outage, but the consecutive-failure setting (`alert_confirmations` on the target) decides how quickly you are told about one, and that is usually where the real tuning is. See [REST API → Alert config](api.md#alert-config).
