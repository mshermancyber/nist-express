# NIST Express — Enterprise Security Architecture Assessment Platform

A production-grade web application that lets business users and security teams
collaboratively describe a new AWS-based solution and automatically generate
Architecture Review Board (ARB) artifacts: categorization, architecture &
security diagrams, STRIDE + operational threat models, NIST 800-53 Rev 5 SSP,
auditable-events catalog, recovery assessment, CIS v8 mapping, AWS
Well-Architected scoring, compliance crosswalks (SOC2 / ISO / PCI / HIPAA /
FedRAMP / GDPR / CCPA), residual-risk register, evidence requests, and the
executive summary.

The generation engine is deterministic and traceable — every recommendation
cites the business / security / compliance / risk decision that motivated it.
When configured, an OpenAI-compatible LLM (OpenAI, Anthropic, Ollama, or any
other gateway speaking `/v1/chat/completions`) enriches the executive
narrative and proposes additional clarification questions.

## Run

The fastest path is Docker compose. See
[`docs/INSTALL.md`](./docs/INSTALL.md) for Ubuntu (bare metal /
systemd), Helm, and Terraform.

```bash
tar -xzf nist-express-1.1.0.tar.gz -C nist-express
cd nist-express
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml logs -f
```

After the container is healthy, open
**`https://<host>:8080/login.html`**, accept the self-signed cert
once (the entrypoint generates it on first boot at
`/app/.data/cert.pem` + `key.pem`), and bootstrap the first admin.
Mount your own PEM at the same paths to override. Plain HTTP is
refused at the TLS layer — there is no fallback.

Admins can manage users at `/users.html` after signing in: metrics
tiles, sortable / paginated user grid, add / edit / enable / disable /
force-password-reset, soft-delete (Shift+Click for irreversible hard
delete), plus a Security panel showing current lockouts, recent
failed logins, password events, and admin actions.

### Bare metal (Ubuntu / Debian)

```bash
# install Node 22 (NodeSource)
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs

# build and run
tar -xzf nist-express-1.1.0.tar.gz -C nist-express
cd nist-express
npm ci --omit=dev
npm run build
PORT=8080 node dist/server.js
```

The server binds to one of the allowed ports `{80, 443, 8080, 8443}`
and refuses any other value. See
[`docs/INSTALL.md § 2`](./docs/INSTALL.md#2-ubuntu-bare-metal-with-systemd)
for a complete Ubuntu setup with a dedicated service user, systemd
unit, UFW rules, capability grant for ports 80/443, and a tar-based
backup convention.

## Containers

Everything ships as containers under `deploy/` — a multi-stage
Node image for the app, a Python image for the AI sidecar, plus
opt-in Postgres and Ollama services. The compose file uses
profiles so the stack scales from "just the app" to "everything":

```bash
docker compose -f deploy/docker-compose.yml up -d                  # app only
docker compose -f deploy/docker-compose.yml --profile db up -d     # app + Postgres
docker compose -f deploy/docker-compose.yml --profile ai up -d     # app + Python AI sidecar + Ollama
docker compose -f deploy/docker-compose.yml --profile full up -d   # all of the above
docker compose -f deploy/docker-compose.yml logs -f                # follow logs
docker compose -f deploy/docker-compose.yml down                   # stop + remove
docker compose -f deploy/docker-compose.yml down -v                # also remove the data volume
```

The app container is non-root, read-only-rootfs, `tini` PID-1, with
a `/readyz` healthcheck over HTTPS. State (session secrets, audit
chain, package history, TLS PEM pair) persists in a named volume.
See [`deploy/docker-compose.yml`](./deploy/docker-compose.yml) for
the full stack definition.

## Backups

State lives entirely under `/app/.data` inside the container (mapped
to a named volume by compose). Snapshot it with vanilla `tar`:

```bash
docker compose -f deploy/docker-compose.yml stop
docker run --rm -v nist-express_app-data:/data -v "$PWD":/backup alpine \
  tar -czf "/backup/nist-express-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" -C /data .
docker compose -f deploy/docker-compose.yml start
```

Keep at least seven rolling snapshots (`logrotate`, a small cron
job, or your backup tooling of choice).

## AI augmentation (optional)

The platform speaks the OpenAI chat-completions wire format, so any
compatible backend works. Set:

| Variable        | Default                          | Purpose |
|-----------------|----------------------------------|---------|
| `AI_BASE_URL`   | `https://api.openai.com/v1`      | Override to point at Anthropic, Ollama, or any OpenAI-compatible gateway |
| `AI_API_KEY`    | _(unset)_                        | Bearer token. Not required for localhost backends (e.g. Ollama) |
| `AI_MODEL`      | `gpt-4o-mini`                    | Any model valid at `AI_BASE_URL` |
| `AI_TIMEOUT_MS` | `30000`                          | Per-request timeout in ms |

Examples:

```bash
# OpenAI
AI_BASE_URL=https://api.openai.com/v1 AI_API_KEY=sk-... AI_MODEL=gpt-4o-mini npm start

# Anthropic via OpenAI-compatible endpoint
AI_BASE_URL=https://api.anthropic.com/v1 AI_API_KEY=sk-ant-... AI_MODEL=claude-opus-4-7 npm start

# Local Ollama
AI_BASE_URL=http://localhost:11434/v1 AI_MODEL=llama3.1:8b npm start
```

The deterministic engine outputs are always present; the LLM only enriches
the executive narrative and proposes additional clarification questions. If
the AI call fails or the timeout fires, the platform falls back to the
deterministic outputs.

## Latest round of additions (M25–M44)

- **SBOM ingestion** — CycloneDX 1.4+ and SPDX 2.x JSON; VEX statements; intersected against a curated CISA KEV list. Upload at `POST /api/sbom/:id/upload`.
- **Per-control comments + watchers + inbox** — threaded discussion on SSP controls, residual risks, threats; auto-watch on comment; notifications inbox.
- **FAIR risk quantification + Monte Carlo** — Loss Event Frequency × Vulnerability × Loss Magnitude bands, 5 000-iteration simulation, ALE p10/p50/p90/mean per risk, portfolio rollup.
- **More compliance frameworks** — NIST CSF 2.0, NIST AI RMF, EU AI Act, HITRUST CSF, DORA, FFIEC, IRS Pub 1075 — all crosswalked to the SSP.
- **Pre-built templates** — 5 archetypes (SaaS, internal microservice, data warehouse, AI-enabled, mobile backend); `GET /api/templates`, `POST /api/templates/:id/instantiate`.
- **Side-by-side diff view** at `/diff.html?id=X&from=A&to=B` + `…diff.csv`.
- **Webhooks** with Slack and Teams adapters; HMAC-signed delivery; `POST /api/webhooks`, `POST /api/webhooks/:id/test`.
- **Jira + ServiceNow ticketing** for residual risks; mocked when no env credentials.
- **Risk acceptance with expiration**; portfolio dashboard shows expiring acceptances.
- **TOTP 2FA** (RFC 6238, no external dep) + **API keys** (Bearer auth bypasses CSRF for CI integration).
- **Live cloud reconciliation** — accepts JSON snapshots from AWS Config / AWS Security Hub / Azure Resource Graph / GCP Cloud Asset Inventory; cross-references actual deployed resources against the described architecture.
- **Postgres backend** opt-in via `DATABASE_URL` (same `StoreAdapter` interface).
- **Background job queue** — persistent single-process worker for generation, webhooks, AI calls.
- **AI chat-with-the-package** — `POST /api/chat/:id`; deterministic FAQ fallback when AI is not configured.
- **Attack trees + Cyber Kill Chain** mapping per HIGH/CRITICAL residual risk.
- **Docker + docker-compose + Helm chart + Terraform module** under `deploy/`.
- **Prometheus `/metrics`** endpoint + structured JSON logs + optional OTLP traces (set `OTEL_EXPORTER_OTLP_ENDPOINT`).
- **Backup / restore** scripts + idempotent migration framework on startup.
- **CSRF (double-submit token)** on state-changing routes; per-user rate limiter on top of per-IP; session-secret rotation with multi-key verification.
- **OWASP ASVS self-attestation** at `GET /api/asvs-self` — the platform reports on its own posture.

## What's new in this version

Every assessment now produces, in addition to the original artifacts:

- **Per-flow STRIDE findings** (DFD-driven) alongside the per-component model.
- **MITRE ATT&CK mapping** for every STRIDE finding (tactic + technique).
- **CAPEC attack-pattern references** keyed to component layer and STRIDE category.
- **LINDDUN privacy threat model** (7 categories) — emitted only when personal data is in scope.
- **DPIA** structured per GDPR Article 35 — emitted when GDPR/CCPA is selected or PHI/PCI/PII is processed.
- **Cost estimate** with a per-service breakdown and a T-shirt tier (XS → XL).
- **OSCAL v1.1.2 SSP** export (FedRAMP-compatible structural subset).
- **CSV exports** for SSP, evidence requests, residual-risk register, audit events, STRIDE, cost, and compliance.
- **Server-side PDF** rendered with pdfkit (16-page report with signature block).
- **Diff between regenerations** — categories, posture, controls, components, threat scores, compliance coverage.
- **Versioned package history** (every generation is kept under `.data/package-history/`).
- **Multi-cloud architectures** — Azure and GCP renderings emitted when `hosting.model` is Azure or GCP.
- **IaC reconciliation** — attach a Terraform plan JSON, CloudFormation YAML/JSON, or CDK synth output and the engine cross-checks the deployed resources against the described components.
- **Auth + RBAC + audit log** — local users (bcrypt) with admin / architect / analyst / product-owner and the four approver roles. Audit log writes for every mutation.
- **Approval workflow** — Security / Risk / Architecture / Compliance signatures bound to the SHA-256 of the package they signed. Regenerating the package invalidates open approvals.

## What gets generated

For every assessment the engine produces a typed `ArbPackage` containing:

- **FIPS 199 categorization** (high-water mark of CIA across matched NIST
  800-60 information types) with full rationale
- **Data classification** (Public / Internal / Confidential / Restricted)
  with handling, retention, disposition
- **Architecture** — component graph across nine layers (edge / identity /
  app / data / integration / logging / monitoring / backup / admin), each
  with trust zone, encryption posture, sensitive-data flag, and rationale
- **Mermaid diagrams** — architecture, security overlay (trust boundaries
  + encryption zones + tamper-sensitive sources), and DFD
- **STRIDE threat model** per component with attack paths, likelihood,
  impact, inherent/residual risk, and control mitigations
- **Operational threat model** — SPOFs, misconfig, capacity, backup,
  monitoring gaps, vendor dependency, identity ops, DR
- **System Security Plan (NIST 800-53 Rev 5)** with tailored
  implementation statements, evidence references, control inheritance
  (Customer / AWS / Hybrid / Common), CIS v8 mappings, assessment guidance
- **Auditable events catalog** (event, source, CIA, retention, alerting,
  severity, control references)
- **Recovery assessment** — Tier 1-4 classification, multi-AZ/region,
  backup strategy, restore-test cadence, failover approach, gaps
- **Compliance crosswalk** — SOC2 / ISO 27001 / PCI DSS / HIPAA / FedRAMP /
  GDPR / CCPA with Full / Partial / Gap coverage
- **AWS Well-Architected scoring** — Security, Reliability, Operational
  Excellence pillars (0-100) with findings and recommendations
- **Evidence requests** — per-control artifact, collection method,
  responsible party, acceptance criteria
- **Residual risk register**
- **Security assumptions & constraints**
- **Executive summary** with risk posture, go/no-go advice, conditions
- **Clarification questions** when assessor judgment is required

## Export

Every package can be downloaded as:

- JSON (`/api/export/:id.json`)
- Markdown (`/api/export/:id.md`)
- Self-contained HTML (`/api/export/:id.html`) — opens with Mermaid
  diagrams rendered client-side; print-to-PDF from the browser

## Save / load assessment input as JSON

The wizard has three buttons next to "Save draft" for working with
JSON files directly:

| Button         | What it does |
|----------------|---|
| ⬇ Download JSON | Saves the current wizard state to `assessment-<slug>.json` on the user's disk. |
| ⬆ Load JSON     | Uploads a JSON file (server validates with zod and creates a new draft). |
| + New           | Clears the form. |

The matching API: `POST /api/assessments/import` accepts the same
JSON shape (or an exported package — `id`, `createdAt`, `updatedAt`,
`status` are stripped server-side and regenerated). Reimporting an
exported file always creates a fresh assessment.

## 5 worked examples

`examples/` ships five JSON inputs that exercise different parts of the
engine, from low-impact to FedRAMP:

| # | File | Purpose |
|---|------|---------|
| 1 | `01-public-fintech-pci.json`       | Public consumer payments, PCI + PII, multi-region, RTO 15m / RPO 0 |
| 2 | `02-hipaa-patient-portal.json`     | HIPAA patient portal, PHI, customer + employee users |
| 3 | `03-internal-hr-platform.json`     | Internal HR app, PII only, single-region, SOC2 only |
| 4 | `04-marketing-static-site.json`    | Low-impact public marketing site, no sensitive data |
| 5 | `05-fedramp-gov-analytics.json`    | FedRAMP / CUI / Export Controlled, multi-region, partner ETL |

Sign in to a running server, then either click **⬆ Load JSON** in
the wizard and pick one of the five files, or POST them through the
import API:

```bash
for f in examples/*.json; do
  curl -sk -b cookies.txt -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $(jq -r .token <(curl -sk -b cookies.txt -c cookies.txt https://<host>:8080/api/csrf))" \
    --data @"$f" https://<host>:8080/api/assessments/import
done
```

Output (typical, after engine calibration):

```
#    Application                           Category   SSP    STRD   Cmpl   Posture    Recommendation
1    Consumer Payments Hub                 High       43     63     14     Elevated   Proceed With Conditions
2    MyCare Patient Portal                 High       43     61     14     Elevated   Proceed With Conditions
3    PeopleOps HR Platform                 Moderate   43     58     8      Moderate   Proceed With Conditions
4    Acme Marketing Website                Moderate   43     57     1      Low        Proceed
5    FedAnalytics Mission Platform         High       43     60     12     Elevated   Proceed With Conditions
```

Per-case Markdown, HTML, and full package JSON are written to
`.run/examples/`. Open the HTML files in a browser for the
Mermaid-rendered architecture, security overlay, and DFD.

## API

### Auth & users
| Method | Path | Purpose |
|--------|------|---------|
| POST   | `/api/auth/login` | Sign in (cookie-based) |
| POST   | `/api/auth/logout` | Clear session cookie |
| GET    | `/api/auth/me` | Current session (or `openMode: true`) |
| POST   | `/api/auth/users` | Provision a user (open mode → anyone; closed mode → admin only) |
| GET    | `/api/auth/users` | List users (admin) |
| GET    | `/api/audit` | Audit log (admin / analyst) |

### Assessments
| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/healthz` | Liveness |
| GET    | `/api/assessments` | List |
| POST   | `/api/assessments` | Create (zod-validated) |
| POST   | `/api/assessments/import` | Import a JSON file as a new draft |
| GET    | `/api/assessments/:id` | Fetch |
| PUT    | `/api/assessments/:id` | Update |
| DELETE | `/api/assessments/:id` | Delete |

### Generation & versions
| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/api/generate/ai-status` | Whether AI augmentation is configured |
| POST   | `/api/generate/:id` | Generate the ARB package (bumps version) |
| GET    | `/api/generate/:id` | Latest generated package |
| GET    | `/api/generate/:id/versions` | List historical versions |
| GET    | `/api/generate/:id/v/:n` | Fetch a specific version |
| GET    | `/api/generate/:id/diff/:from/:to` | Diff between two versions |

### Exports
| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/api/export/:id.json` | Full ArbPackage JSON |
| GET    | `/api/export/:id.md` | Markdown |
| GET    | `/api/export/:id.html` | Self-contained HTML (Mermaid renders client-side) |
| GET    | `/api/export/:id.pdf` | PDF (pdfkit) |
| GET    | `/api/export/:id.oscal.json` | NIST OSCAL v1.1.2 SSP |
| GET    | `/api/export/:id.{ssp,evidence,residual-risk,audit-events,stride,cost,compliance}.csv` | CSV slices |

### IaC reconciliation
| Method | Path | Purpose |
|--------|------|---------|
| POST   | `/api/iac/:id/upload` | Multipart upload of Terraform plan JSON, CFN YAML/JSON, or CDK synth |
| DELETE | `/api/iac/:id` | Remove an attached IaC file |

### Approval workflow
| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/api/approval/:id` | Current approval state |
| POST   | `/api/approval/:id/request` | Open a request (owner) |
| POST   | `/api/approval/:id/sign` | Sign as Security / Risk / Architecture / Compliance |
| POST   | `/api/approval/:id/cancel` | Cancel an open request |

## Architecture of this app

```
src/
  server.ts                Express bootstrap (helmet, rate-limit, CSP, range-checked port)
  types/assessment.ts      Single source of truth for the Assessment + ArbPackage shapes
  data/
    nistControls.ts        Curated NIST 800-53 Rev 5 catalog (all 18 families)
    cisControls.ts         CIS Controls v8 (all 18 controls + key safeguards)
    awsServices.ts         AWS service catalog with layer + inherited controls
    informationTypes.ts    NIST 800-60 representative information types
  engine/
    categorization.ts      FIPS 199 high-water mark + 800-60 mapping
    dataClassification.ts  Public/Internal/Confidential/Restricted
    architecture.ts        AWS reference architecture builder
    diagrams.ts            Mermaid renderers (architecture, overlay, DFD)
    threatModel.ts         STRIDE per component
    operationalThreats.ts  SPOF / misconfig / capacity / backup / monitoring / vendor / identity / DR
    ssp.ts                 Control selection + tailored implementation statements
    auditEvents.ts         Logging recommendations
    recovery.ts            RTO/RPO + availability tier
    compliance.ts          Cross-framework mapping
    wellArchitected.ts     Pillar scoring (Security / Reliability / OpEx)
    evidence.ts            Per-control evidence requests
    residualRisk.ts        Risk register aggregation
    assumptions.ts         Security assumptions & basis
    executiveSummary.ts    Posture, top risks, go/no-go
    validation.ts          Pre-generation validator + clarification questions
    ai.ts                  Vendor-neutral OpenAI-compatible client + fallback helpers
    package.ts             Orchestrator
  routes/
    assessments.ts         zod-validated CRUD
    generate.ts            Generate & fetch packages
    export.ts              JSON / Markdown / HTML
  store/assessmentStore.ts In-memory cache + JSON persistence under .data/
  export/
    html.ts                Self-contained HTML export
    markdown.ts            Markdown export

public/
  index.html / app.js      Wizard
  view.html / view.js      Package viewer (renders Mermaid client-side)
  dashboard.html / dashboard.js  Portfolio dashboard
  styles.css               Dark-mode enterprise design system
```

## Test

```bash
npm test
```

## Security posture of this app

- Helmet, strict CSP, no `x-powered-by`
- Rate limiting (`240 req/min`)
- 512 KB JSON body limit
- zod-validated input on every mutation route
- Output escaping in the Markdown and HTML exporters
- Mermaid identifiers sanitised in the diagram generator
- No telemetry, no third-party calls outside the configured AI gateway
