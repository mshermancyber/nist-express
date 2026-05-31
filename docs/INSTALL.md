# NIST Express — Installation Guide

Audience: site reliability engineers, platform engineers, security
engineers installing the platform for an organisation.

> **Just want it running?** Docker compose is the fastest path
> (next section). The container terminates TLS itself; on first boot
> the entrypoint generates a self-signed cert (CN=`nist.local`, SANs
> for `localhost`, `127.0.0.1`). After it boots, open
> **`https://<host>:8080/login.html`**, accept the self-signed cert
> in your browser once, and bootstrap the first admin. Replace
> `/app/.data/cert.pem` + `key.pem` with your own PEM pair for
> production. There is no plain-HTTP fallback.

This guide covers four installation paths:

1. [Docker / docker-compose](#1-docker--docker-compose) **← recommended**
2. [Ubuntu (bare metal, with systemd)](#2-ubuntu-bare-metal-with-systemd)
3. [Kubernetes (Helm)](#3-kubernetes-helm)
4. [AWS ECS (Terraform module)](#4-aws-ecs-terraform-module)

Plus configuration ([§ 5](#5-configuration)), Postgres opt-in ([§ 6](#6-postgres-backend-optional)),
AI provider setup ([§ 7](#7-ai-augmentation)), verification
([§ 8](#8-post-install-verification)), and uninstall ([§ 9](#9-uninstall)).

---

## 1 · Docker / docker-compose

### Prerequisites

- Docker Engine ≥ 24 + `docker compose` v2 (Docker Desktop on
  macOS / Windows is fine).

### Build the image

```bash
tar -xzf nist-express-1.1.0.tar.gz -C nist-express
cd nist-express
docker build -t nist-express:1.1.0 -f deploy/Dockerfile .
```

### Run a single container

```bash
docker run -d --name nist-express \
  -p 8080:8080 \
  -v nist-data:/app/.data \
  -e AI_BASE_URL=https://api.openai.com/v1 \
  -e AI_API_KEY=sk-... \
  nist-express:1.1.0
```

### Or docker-compose (preferred)

```bash
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml logs -f
```

The image:

- runs as a **non-root** user (`node`, UID 1000)
- has a `HEALTHCHECK` against `/readyz` over HTTPS
- exposes only port `8080`
- uses `npm ci --omit=dev` to ship only runtime deps
- bind-mounts `/app/.data` as the persistent volume

Uncomment the `db:` service block in `deploy/docker-compose.yml` to
enable Postgres persistence (see [§ 6](#6-postgres-backend-optional)).

---

## 2 · Ubuntu (bare metal, with systemd)

Tested on Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. Should work on any
Debian-family distro with the equivalent apt packages.

### 2a · Install Node.js 22 (NodeSource)

```bash
# system tooling
sudo apt-get update
sudo apt-get install -y curl ca-certificates gnupg openssl

# NodeSource repo (official)
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs

# verify
node --version    # → v22.x
npm  --version
```

If you prefer to install Node without adding the NodeSource repo,
use `nvm` instead:

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
exec "$SHELL"
nvm install 22
nvm alias default 22
```

### 2b · Create a service user and target directory

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin nistexp
sudo mkdir -p /opt/nist-express /etc/nist-express
sudo chown nistexp:nistexp /opt/nist-express
```

### 2c · Extract the release into `/opt/nist-express`

```bash
sudo -u nistexp tar -xzf nist-express-1.1.0.tar.gz -C /opt/nist-express --strip-components=0
cd /opt/nist-express
sudo -u nistexp npm ci --omit=dev
sudo -u nistexp npm run build
```

`npm ci --omit=dev` skips devDependencies (jest, ts-node-dev, types).
The build step compiles TypeScript into `dist/`.

### 2d · Configure environment

```bash
sudo tee /etc/nist-express/env >/dev/null <<'ENV'
PORT=8080
NODE_ENV=production
LOG_LEVEL=info
# Optional integrations:
# AI_BASE_URL=https://api.openai.com/v1
# AI_API_KEY=sk-...
# AI_MODEL=gpt-4o-mini
# SCIM_TOKEN=...
# DATABASE_URL=postgres://nistexp:pw@localhost:5432/nistexp
ENV
sudo chmod 600 /etc/nist-express/env
sudo chown nistexp:nistexp /etc/nist-express/env
```

### 2e · Allow binding to port 80 / 443 (only if you need them)

The release allows the four standard service ports
**`80, 443, 8080, 8443`**. Binding 80 or 443 normally requires root.
Grant the Node binary the capability instead:

```bash
sudo setcap 'cap_net_bind_service=+ep' "$(which node)"
```

(Repeat after any Node upgrade — capabilities don't follow binary
replacements.)

For non-privileged operation, leave `PORT=8080` and front the app
with a reverse proxy that listens on 443 and forwards to 8080.

### 2f · systemd unit

```bash
sudo tee /etc/systemd/system/nist-express.service >/dev/null <<'UNIT'
[Unit]
Description=NIST Express — Architecture Review Board platform
Documentation=https://github.com/<your-org>/nist-express
After=network-online.target
Wants=network-online.target

[Service]
User=nistexp
Group=nistexp
WorkingDirectory=/opt/nist-express
EnvironmentFile=/etc/nist-express/env
ExecStart=/usr/bin/node /opt/nist-express/dist/server.js
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/nist-express/.data /opt/nist-express/.run
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now nist-express
sudo systemctl status nist-express --no-pager
```

### 2g · Backup and restore

The release does not bundle a wrapper script. Use vanilla `tar`:

```bash
# stop the service, snapshot the state directory, restart
sudo systemctl stop nist-express
sudo tar -czf "/var/backups/nist-express-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" \
  -C /opt/nist-express .data
sudo systemctl start nist-express

# restore
sudo systemctl stop nist-express
sudo rm -rf /opt/nist-express/.data
sudo tar -xzf /var/backups/nist-express-<timestamp>.tar.gz -C /opt/nist-express
sudo chown -R nistexp:nistexp /opt/nist-express/.data
sudo systemctl start nist-express
```

Keep at least seven rolling snapshots (`logrotate(8)` or a small
cron job). The `.data/` directory is the only state that matters:
SQLite (if Postgres isn't used), `users.json`, the audit chain, the
TLS PEM pair, throttle counters.

### 2h · Updates

```bash
sudo systemctl stop nist-express
sudo -u nistexp tar -xzf nist-express-1.1.1.tar.gz -C /opt/nist-express
cd /opt/nist-express
sudo -u nistexp npm ci --omit=dev
sudo -u nistexp npm run build
sudo systemctl start nist-express
```

---

## 3 · Kubernetes (Helm)

```bash
helm install nist-express deploy/helm \
  --namespace nist-express --create-namespace \
  --set image.repository=ghcr.io/your-org/nist-express \
  --set image.tag=1.1.0 \
  --set env.AI_BASE_URL=https://api.openai.com/v1 \
  --set env.AI_API_KEY=sk-... \
  --set persistence.size=20Gi
```

Defaults in `deploy/helm/values.yaml`:

- 1 replica (single-writer adapter; scale to ≥ 2 only with Postgres)
- `runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities.drop: ALL`
- ClusterIP service on port 80 → container 8080
- Optional Ingress (set `ingress.enabled=true`)

The chart creates a PVC for `.data/` so persistence survives pod
recreates.

---

## 4 · AWS ECS (Terraform module)

```hcl
module "nist_express" {
  source            = "./deploy/terraform"
  region            = "us-east-1"
  name              = "nist-express"
  image             = "<account>.dkr.ecr.us-east-1.amazonaws.com/nist-express:1.1.0"
  vpc_id            = aws_vpc.main.id
  subnet_ids        = aws_subnet.private[*].id
  public_subnet_ids = aws_subnet.public[*].id
  ai_base_url       = "https://api.openai.com/v1"
  ai_api_key        = var.openai_api_key
  database_url      = "postgres://nistexp:pw@<rds-endpoint>:5432/nistexp"
}

output "nist_express_url" { value = module.nist_express.alb_dns_name }
```

The module creates:

- An ECS cluster, task definition (FARGATE, 0.5 vCPU / 1 GB)
- IAM execution role + CloudWatch log group
- ALB on port 443 → target group on 8080
- Security groups (ALB-only ingress to the task)

Provide an ACM cert ARN to the module to terminate TLS at the ALB.
The app itself still terminates TLS internally; the ALB connects to
the backend over HTTPS as well (cert validation disabled for the
self-signed loop).

---

## 5 · Configuration

All configuration is via environment variables. Persistent state
lives under `.data/`. The TLS PEM pair (`cert.pem`, `key.pem`) lives
there too — mount it as a volume / PVC.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Listening port. Must be in `{80, 443, 8080, 8443}`. |
| `NODE_ENV` | `production` | Set to `production` in deployment. |
| `LOG_LEVEL` | `off` | `off` / `error` / `warn` / `info` / `debug` / `trace`. **Default OFF in production.** |
| `LOG_FILE` | _(unset)_ | Append-only file mirror for log output. |
| `TRUST_PROXY` | _(unset)_ | Set to non-empty to honour `X-Forwarded-For` (only behind a trusted reverse proxy). |
| `PER_USER_RATE_LIMIT` | `600` | Requests per user per minute. |
| `OUTBOUND_ALLOW_HOSTS` | _(unset)_ | Comma-list of hostnames that bypass the SSRF guard. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | _(unset)_ | OTLP/HTTP traces endpoint. |
| `OTEL_SERVICE_NAME` | `nist-express` | OTel service name. |
| `DATABASE_URL` | _(unset)_ | If set, Postgres persistence is used. See § 6. |
| `REDIS_URL` | _(unset)_ | When set + `ioredis` installed, throttle counters move to Redis for multi-node. |
| `KEY_ENCRYPTION_KEY` | _(derived)_ | Base64 32-byte KEK for AES-256-GCM at-rest field encryption. Auto-derived from session secret if unset. |
| `SCIM_TOKEN` | _(unset)_ | Bearer token for SCIM 2.0 endpoint. SCIM disabled when unset. |
| `FORCE_FIPS` | _(unset)_ | `1` to call `crypto.setFips(true)` at startup (requires FIPS-enabled Node). |
| `AI_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible endpoint. |
| `AI_API_KEY` | _(unset)_ | Bearer token. Optional for localhost endpoints. |
| `AI_MODEL` | `gpt-4o-mini` | Model identifier valid at `AI_BASE_URL`. |
| `AI_TIMEOUT_MS` | `30000` | Per-AI-request timeout. |
| `PY_AI_URL` | _(unset)_ | When set, AI calls route through the Python sidecar. |
| `JIRA_BASE_URL`, `JIRA_USER`, `JIRA_TOKEN`, `JIRA_PROJECT_KEY` | — | Jira ticketing. |
| `SERVICENOW_BASE_URL`, `SERVICENOW_USER`, `SERVICENOW_PASSWORD`, `SERVICENOW_TABLE` | — | ServiceNow ticketing. |
| `NOTIFY_MAX_LINES` | `10000` | Notifications log rotation threshold. |

### Reverse-proxy guidance

When behind nginx / ALB / Cloudflare, set:

- `X-Forwarded-Proto: https`
- `X-Forwarded-For: <client-ip>`
- `TRUST_PROXY=1` on the server (so `req.ip` resolves correctly)
- The proxy must talk **HTTPS** to the backend — the app has no
  HTTP listener and will refuse cleartext at the TLS layer.

---

## 6 · Postgres backend (optional)

By default state is stored as JSON files under `.data/` (FS adapter).
For multi-node deployments or operational tidiness:

```bash
export DATABASE_URL='postgres://nistexp:pw@db.internal:5432/nistexp'
sudo systemctl restart nist-express
```

On first connection the adapter creates two tables idempotently:

- `arb_assessments(id, updated_at, body)`
- `arb_packages(assessment_id, version, generated_at, package_hash, body)`

The other stores (users, audit log, webhooks, comments, tickets) still
write to disk — these are smaller and rarely benefit from a DB.

> Encryption at rest: rely on the underlying disk (EBS/PD/Azure Disk)
> or Postgres TDE. The platform encrypts specific fields (TOTP
> secrets, webhook secrets) with the field-level KEK; everything else
> trusts the volume.

---

## 7 · AI augmentation

The chat-with-package and executive-narrative features use any
OpenAI-compatible endpoint:

```bash
# OpenAI
export AI_BASE_URL=https://api.openai.com/v1
export AI_MODEL=gpt-4o-mini
export AI_API_KEY=sk-...

# Anthropic (OpenAI-compat endpoint)
export AI_BASE_URL=https://api.anthropic.com/v1
export AI_MODEL=claude-sonnet-4-6
export AI_API_KEY=sk-ant-...

# Ollama (local)
export AI_BASE_URL=http://localhost:11434/v1
export AI_MODEL=llama3.1:8b
# AI_API_KEY not required for localhost

# Azure OpenAI (via a gateway like LiteLLM)
export AI_BASE_URL=https://litellm.yourorg.com/v1
export AI_MODEL=azure/gpt-4o
export AI_API_KEY=sk-litellm-...
```

The deterministic engine outputs are always emitted; AI only enriches
narrative + clarification questions. If AI is unreachable or the
deterministic fallback is preferred, leave `AI_API_KEY` unset.

---

## 8 · Post-install verification

The container terminates TLS itself with a self-signed cert on first
boot, so `curl` needs `-k` (or `--cacert /app/.data/cert.pem`):

```bash
# Liveness
curl -sk https://<host>:8080/healthz

# Readiness
curl -sk https://<host>:8080/readyz

# AI reachability (optional)
curl -sk https://<host>:8080/api/generate/ai-status

# Metrics (Prometheus exposition)
curl -sk https://<host>:8080/metrics | head
```

### Smoke-test the engine with the bundled examples

Five sample assessments ship under `examples/`. After the first
admin is provisioned, sign in and click **Load JSON** in the wizard
to import one:

```text
examples/01-public-fintech-pci.json
examples/02-hipaa-patient-portal.json
examples/03-internal-hr-platform.json
examples/04-marketing-static-site.json
examples/05-fedramp-gov-analytics.json
```

Generate the package and confirm the PDF / HTML / OSCAL / CSV
exports render. These are also useful as regression fixtures if you
fork the engine.

### Audit log integrity

```bash
# log in first; below assumes a cookie jar at /tmp/cookies
curl -sk -b /tmp/cookies https://<host>:8080/api/audit/verify
# → { "ok": true, "entries": N }
```

If the response shows `ok: false`, the log has been tampered with
(or the session secret was rotated mid-chain — see the Admin Guide
§ Rotation).

---

## 9 · Uninstall

Container:

```bash
docker compose -f deploy/docker-compose.yml down -v
docker image rm nist-express:1.1.0
```

Ubuntu / systemd:

```bash
sudo systemctl disable --now nist-express
sudo rm /etc/systemd/system/nist-express.service
sudo systemctl daemon-reload
sudo userdel --remove nistexp
sudo rm -rf /opt/nist-express /etc/nist-express
```

Persistent state lives under `.data/`. Snapshot it first with `tar`
(see § 2h) if you might want to restore later.
