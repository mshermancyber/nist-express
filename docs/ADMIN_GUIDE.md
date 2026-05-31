# NIST Express — Administrator Guide

For platform admins (the people who own the running service). Pairs
with [`INSTALL.md`](INSTALL.md) and [`NETWORK.md`](NETWORK.md).

---

## 1 · First-run bootstrap

The first time the platform starts, **no users exist** and the
platform is in **open mode** — anonymous requests are treated as
admin. A yellow banner makes this obvious.

To close the hatch:

1. Open `https://<host>/login.html`.
2. Click **Provision the first admin**.
3. Provide a username, display name, and a password meeting the
   policy (`≥ 12 chars`, `≥ 2 character classes`, not in the breach
   list).
4. Optionally pre-grant the four approver roles to the admin so they
   can immediately sign ARB approvals during initial pilots.

After the first user exists, open mode is off — every subsequent
operation requires a session cookie + CSRF token, or a Bearer API key.

---

## 2 · Users and roles

### Roles

| Role | What it grants |
|---|---|
| `admin` | Everything. Provision users, configure webhooks, view audit log. |
| `architect` | Create / edit assessments; upload IaC / SBOM / cloud snapshots. |
| `analyst` | Same as architect + audit log read access. |
| `product-owner` | Create / edit assessments; request approvals. |
| `approver-security` | Sign as Security on an approval request. |
| `approver-risk` | Sign as Risk. |
| `approver-architecture` | Sign as Architecture. |
| `approver-compliance` | Sign as Compliance. |

A user can hold multiple roles. Approvers can hold the matching
`architect`/`product-owner` role too — separation of duties is enforced
by the approval-flow design (only the approver-* roles can sign the
matching lane).

### User Administration UI

Admins land on a dedicated console at **`https://<host>:8080/users.html`**
(also linked in the sidebar when signed in as admin):

- Metrics tiles: Total / Active / Disabled / Admins / MFA-enrolled /
  Soft-deleted.
- Filterable user grid with username, display name, email, roles,
  status badges, last-login, and inline actions.
- "Add user" dialog collects the full profile (firstName, lastName,
  email, department, jobTitle, phone, timezone), one or more roles,
  an initial password (policy: ≥ 12 chars AND all four character
  classes), and an optional **Require password change on first
  login** checkbox.
- Per-row actions: **Edit**, **Enable / Disable**, **Force pwd reset**,
  and **Delete** (soft by default; **Shift+Click** to escalate to
  irreversible hard delete).

Sensitive operations re-prompt for the admin's password (and TOTP if
enrolled). The page issues sudo in-place when the API returns
`403 sudo:false` so you only re-authenticate when you need to.

### Provision a user (API equivalent)

```bash
# As admin, with cookies/CSRF or API key
curl -X POST https://<host>:8080/api/auth/users \
  -H 'authorization: Bearer arb_...' \
  -H 'content-type: application/json' \
  -d '{
    "username": "asmith",
    "displayName": "A. Smith",
    "email": "asmith@example.com",
    "firstName": "A.",
    "lastName": "Smith",
    "department": "Engineering",
    "jobTitle": "Solutions Architect",
    "password": "<≥12 chars, all 4 classes>",
    "roles": ["architect"]
  }'
```

### List users

```bash
GET /api/auth/users      # admin only — passwords never returned
```

### Edit profile

```bash
# Whitelisted fields only; username/passwordHash/id are not mutable here
PATCH /api/auth/users/:id   # admin + sudo
```

### Disable / Enable

```bash
POST /api/auth/users/:id/disable   # admin + sudo. Body: { reason?: string ≤500 }
POST /api/auth/users/:id/enable    # admin + sudo
```

A disabled user cannot authenticate; existing session cookies become
useless on their next request (the auth lookup returns nothing).

### Force password change

```bash
POST /api/auth/users/:id/force-password-change   # admin + sudo
```

The login response surfaces `forcePasswordChange: true`; the user
must call `POST /api/auth/change-password` with their old and new
password before any other action will succeed.

### Delete

```bash
DELETE /api/auth/users/:id              # admin + sudo. Soft delete — reversible.
DELETE /api/auth/users/:id?hard=1       # admin + sudo. Irreversible erasure.
```

Both refuse to delete the actor or the last active admin. A
soft-deleted row is hidden from all auth lookups but preserved for
the audit trail; `?hard=1` can target a previously soft-deleted row.

---

## 3 · TOTP 2FA

Each user enrols TOTP for themselves:

```bash
# Already authenticated as the target user
curl -X POST https://<host>/api/auth/totp/enroll
# → { "secret": "PLZQ44TO7...", "otpauth": "otpauth://totp/..." }

# Confirm a code from the authenticator app
curl -X POST https://<host>/api/auth/totp/verify \
  -H 'content-type: application/json' -d '{"code":"123456"}'
```

After verification, every subsequent login requires `{ username,
password, totp }`.

To disable (lost device etc.):
```bash
curl -X POST https://<host>/api/auth/totp/disable     # self
```

Admins can also revoke another user's TOTP secret by editing the
`.data/user-security.json` file (set `totpEnabled: false`).

---

## 4 · API keys (CI integration)

Each user can issue named API keys for non-interactive workflows.

```bash
curl -X POST https://<host>/api/auth/api-keys \
  -H 'content-type: application/json' \
  -d '{"name":"ci-pipeline"}'
# Response includes "key": "arb_…" — store this in your secrets manager NOW.
# It cannot be retrieved later.
```

Use the key by adding `Authorization: Bearer arb_…` to requests.
Bearer authentication bypasses CSRF (the cookie isn't involved).

Revoke:
```bash
GET    /api/auth/api-keys          # list
DELETE /api/auth/api-keys/:id      # revoke
```

---

## 5 · Login throttling

In-process sliding-window counters lock out after:
- **5 failed attempts per username per 15 min** → 5-minute cooldown.
- **30 failed attempts per IP per 15 min** → 5-minute cooldown.

A successful login resets the per-user counter. To free a locked
account immediately, restart the server (counters are in-memory).

For multi-node deployments, plumb the counter into Redis (TODO).

---

## 6 · Approval workflow

The approval request captures the SHA-256 of the package the user is
signing. If anyone regenerates the package after a request is open,
the hash changes and `POST /api/approval/:id/sign` returns 409:

```
"package was regenerated since request — re-issue the approval request"
```

Workflow:
1. **Owner requests** approval (`POST /api/approval/:id/request`).
2. Each **approver-*** role signs with `decision: approve|reject` and
   an optional `comment`.
3. When all required roles have **approved**, status flips to
   `approved`. Any **reject** flips it to `rejected`.
4. Owner may **cancel** an open request.

PDF + HTML exports render the signature block automatically.

---

## 7 · Webhooks

`POST /api/webhooks` registers an outbound webhook. Each subscription
has:
- A name
- A target URL (subject to the SSRF guard — see § 12)
- One or more events (`package.generated`, `approval.requested`,
  `approval.signed`, `residual.critical`, `comment.created`,
  `risk.expiring`)
- An adapter (`generic`, `slack`, `teams`)
- An HMAC secret generated server-side; first 4 chars shown on list

Delivery:
- 8-second timeout
- HMAC SHA-256 in `x-nistexpress-signature: sha256=<hex>`
- Event in `x-nistexpress-event`
- Body matches the adapter shape (Slack Incoming Webhook / Teams
  MessageCard / generic envelope)

`POST /api/webhooks/:id/test` sends a fake `package.generated` event
for verification.

---

## 8 · Ticketing (Jira / ServiceNow)

Set the relevant env vars (see Install Guide § 5) and the
`POST /api/risks/:assessmentId/:riskId/ticket` route will reach the
configured backend. Without env vars, the route returns a mock ticket
id so downstream UI flows can be tested without external dependencies.

Both backends use **Basic auth** over HTTPS. Jira Cloud accepts an API
token; ServiceNow accepts an account password (rotate it with the
underlying account).

---

## 9 · Audit log

- File: `.data/audit.jsonl`
- Format: append-only JSONL
- **Integrity:** every entry carries `_chain.prev` (previous HMAC) and
  `_chain.mac` (HMAC of prev + entry-body), keyed by a derivative of
  the session secret. The current chain head is in `.data/audit-head`.

### Verify
```bash
curl -s -H 'authorization: Bearer arb_...' \
  https://<host>/api/audit/verify
# → { "ok": true, "entries": 1234 }
# or { "ok": false, "entries": 1234, "firstBadIndex": 882 } when tampered
```

### Read
```bash
GET /api/audit?limit=200      # admin / analyst only
```

### Operational notes
- Rotation: there's no built-in rotation. For long-running deployments,
  ship the file to a SIEM (Loki, OpenSearch, CloudWatch) via a
  sidecar (`tail -F`) and truncate periodically with a controlled
  process.
- Tampering: any modification to an existing line invalidates every
  subsequent MAC. `/api/audit/verify` returns the first bad index.

---

## 10 · Backups

State lives entirely under `/app/.data` inside the container. Take
a snapshot with vanilla `tar` against the named volume:

```bash
# stop, snapshot, restart
COMPOSE='docker compose -f deploy/docker-compose.yml'
$COMPOSE stop
docker run --rm \
  -v nist-express_app-data:/data \
  -v /var/backups/nist-express:/backup \
  alpine sh -c "tar -czf /backup/nist-express-\$(date -u +%Y%m%dT%H%M%SZ).tar.gz -C /data . \
                && sha256sum /backup/nist-express-*.tar.gz | tail -1 > /backup/nist-express-*.tar.gz.sha256"
$COMPOSE start
```

Schedule with cron, a systemd timer, or your backup tooling of
choice. Backups cover `.data/` (assessments, packages, package
history, users, audit log, webhooks, comments, acceptances, IaC /
SBOM / cloud blobs, TLS PEM pair). Keep at least seven rolling
copies and verify the sha256 sidecar before relying on a restore.

For bare-metal (Ubuntu / systemd) installs, the equivalent is:

```bash
sudo systemctl stop nist-express
sudo tar -czf "/var/backups/nist-express-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" \
  -C /opt/nist-express .data
sudo systemctl start nist-express
```

To restore the container:

```bash
COMPOSE='docker compose -f deploy/docker-compose.yml'
$COMPOSE down            # stop + remove containers (volume KEPT)
docker volume rm nist-express_app-data
docker volume create nist-express_app-data
docker run --rm \
  -v nist-express_app-data:/data \
  -v /var/backups/nist-express:/backup \
  alpine tar -xzf /backup/nist-express-<ts>.tar.gz -C /data
$COMPOSE up -d
```

Restore the bare-metal install the same way you snapshotted it,
extracting back to `/opt/nist-express/.data` and `chown`'ing to the
service user.

---

## 11 · Migrations

On startup the server runs ordered migrations from
`src/store/migrations.ts`; applied IDs are recorded in
`.data/migrations.json`. Migrations are forward-only; if you need to
roll back, restore a backup taken **before** the migration ran.

---

## 12 · Network egress (SSRF guard)

All outbound HTTP calls go through `safeFetch()`, which:
- refuses non-`http(s)` schemes
- resolves the target hostname and **rejects any IP in private,
  loopback, link-local, or cloud-metadata ranges** (RFC 1918,
  127/8, ::1/128, 169.254/16, fe80::/10, 169.254.169.254/32,
  RFC 6598 CGNAT)
- enforces a per-call timeout

To allow specific internal targets (e.g. a Slack-compatible internal
chat), set:
```
OUTBOUND_ALLOW_HOSTS=chat.internal,hooks.lan
```

---

## 13 · Session-secret rotation

```bash
# Generate a new active key; older keys remain accepted for
# in-flight sessions until they expire (session TTL is 5 minutes
# with sliding refresh on activity).
curl -X POST -H 'authorization: Bearer arb_admin_...' \
  https://<host>/api/auth/rotate-secret    # admin + sudo
```

The function is exported as `rotateSessionSecret()` from
`src/auth/auth.ts`. The file `.data/session-secret` holds up to 3
recent keys (newest first). Restart is **not** required.

---

## 14 · Observability

- **`GET /metrics`** — Prometheus format. Counters:
  `arb_http_requests_total`, `arb_packages_generated_total`,
  `arb_ai_calls_total`, `arb_jobs_run_total`. Histogram:
  `arb_http_request_duration_seconds`.
- **stdout** — structured JSON access log per request (rid, method,
  path, status, ms).
- **OpenTelemetry** — set `OTEL_EXPORTER_OTLP_ENDPOINT` to ship spans
  over OTLP/HTTP.

### Alert ideas
- `rate(arb_http_requests_total{status="5xx"}[5m]) > 0`
- Audit-log verify (`/api/audit/verify`) returning `ok: false` →
  page on-call immediately.
- Failed AI calls (`arb_ai_calls_total{outcome="fail"}`) over a
  threshold.

---

## 15 · Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| 403 `csrf token missing or mismatch` on state-changing API calls | Missing `x-csrf-token` header | The bundled frontend handles this. For external clients, GET `/api/csrf` first and echo the token. |
| 401 `TOTP required` | User has TOTP enabled | Re-submit with `{ "totp": "123456" }` field. |
| 429 `too many failed attempts` | Login throttling | Wait `cooldownSeconds`, or restart. |
| 409 on `/api/approval/:id/sign` | Package was regenerated after request | Re-issue the approval request. |
| Webhook deliveries fail with `private / metadata / loopback` | Target is on a private IP | Add the host to `OUTBOUND_ALLOW_HOSTS`. |
| Server refuses to start: `PORT … outside allowed range` | The platform pins to `80/443/8080/8443` | Pick another port in the band. |

Logs live under `.run/server.log` for the local lifecycle scripts, and
in stdout for Docker / Kubernetes / ECS.

---

## 16 · Self-attestation

The platform reports on its **own** ASVS posture at:

```
GET /api/asvs-self
```

Use this in your internal vendor-risk review to demonstrate that the
tool you're using for security architecture review meets OWASP ASVS
L1+L2 itself. Section breakdown is in `src/engine/asvs.ts` —
PASS / PARTIAL / GAP for each control.

---

## 17 · Hardening checklist before exposing to the internet

- [ ] Terminate TLS at a reverse proxy (ALB, nginx, Cloudflare).
- [ ] Set `TRUST_PROXY=1`.
- [ ] Provision the first admin and disable open mode by adding a
      user.
- [ ] Enable TOTP for every admin account.
- [ ] Configure `OUTBOUND_ALLOW_HOSTS` if your webhooks need internal
      targets.
- [ ] Rotate the session secret (`rotateSessionSecret()`).
- [ ] Set up scheduled backups (see § 10 — cron + `docker volume`-aware `tar`, or systemd timer for bare metal).
- [ ] Ship the audit log to a SIEM.
- [ ] Restrict `/metrics` and `/api/asvs-self` if not for the public.
- [ ] Apply `iptables` / Security Group rules per `NETWORK.md`.
