# NIST Express — User Guide

This guide is written for the people who will *use* the platform on a
weekly basis: Product Owners, Security Analysts, Security Architects,
Risk Officers, and Compliance reviewers. For installation and
administration, see [`INSTALL.md`](INSTALL.md) and
[`ADMIN_GUIDE.md`](ADMIN_GUIDE.md).

---

## 1 · Concepts in one page

The platform turns a guided **Assessment** (~ 8 sections of plain
questions) into a structured **ARB Package** containing:

| Artifact | Used by |
|---|---|
| FIPS 199 categorization + data classification | Risk, Compliance |
| Architecture + security overlay + data-flow diagrams | Architecture, Security |
| STRIDE per-component + per-flow + LINDDUN | Security, Privacy |
| Attack trees + MITRE ATT&CK + CAPEC + Cyber Kill Chain | SecOps |
| NIST 800-53 Rev 5 SSP (186 controls across 20 families) | Compliance, ATO |
| OSCAL v1.1.2 export | FedRAMP / agency pipelines |
| Compliance crosswalk (NIST CSF, SOC2, ISO, PCI, HIPAA, HITRUST, FedRAMP, GDPR, CCPA, DORA, FFIEC, IRS 1075, EU AI Act, NIST AI RMF) | Compliance |
| Auditable events catalogue | SecOps |
| Recovery (RTO/RPO/tier) + Operational threats | Reliability, SRE |
| AWS Well-Architected scoring | Architecture |
| FAIR Monte Carlo (per-risk + portfolio ALE) | Risk, Finance |
| Residual Risk Register + Cost Estimate | Risk, PO |
| Evidence Request List | Auditor |
| Executive Summary + ARB Recommendation | Sponsor |
| DPIA (GDPR Art. 35) | Privacy |
| Side-by-side diff vs prior version | All |
| SBOM analysis (CycloneDX/SPDX + CISA KEV) | Security / Supply Chain |
| IaC reconciliation + Live cloud reconciliation | Architecture |

Everything is regenerated deterministically from the inputs, so editing
the wizard and pressing **Generate** again produces a new versioned
package + a diff against the previous one.

---

## 2 · Sign in

Open **`https://<host>:8080/login.html`**. The server terminates TLS
directly; on first visit your browser will prompt you to trust the
self-signed cert that the container generated on first boot. Replace
it with a real PEM at `/app/.data/cert.pem` + `key.pem` to avoid the
prompt on subsequent visits.

- **First-time bootstrap.** When no users exist, anyone can provision
  the initial admin from the login page. After that login is required.
- **TOTP.** Once an admin enables TOTP for their account (under
  *Session* → *Sign in to your account* → /api/auth/totp/enroll via the
  admin REST), the login dialog asks for a 6-digit code in addition to
  the password. The same TOTP code cannot be re-used within the
  ~90-second drift window.
- **Force password change.** If the admin flagged your account, the
  login response carries `forcePasswordChange: true`; the UI redirects
  you to a change-password prompt and refuses any other navigation
  until you set a new password.
- **5-minute idle timeout.** Sessions expire after 5 minutes of
  inactivity. Any authenticated request resets the clock — you only
  get kicked out if you truly walk away.
- **API keys.** For CI integrations (e.g. a pipeline that posts to
  `/api/generate/:id` after each deploy), issue a personal API key
  under `POST /api/auth/api-keys`. The raw key is returned **once** —
  store it in your secrets manager.

### Change your password
Self-service from anywhere you're signed in:
```bash
POST /api/auth/change-password
{ "currentPassword": "...", "newPassword": "..." }
```
The new password must be ≥ 12 chars AND contain all four character
classes (upper, lower, digit, special). Five wrong attempts in an
hour lock further attempts until the window clears.

---

## 3 · Create an assessment

There are three ways to start:

### a) Start from a template
On the **New Assessment** screen, choose **Start from template** (or
`POST /api/templates/:id/instantiate`). Templates ship for:

- Standard SaaS Application
- Internal Microservice
- Data Warehouse / Analytics
- AI-Enabled Product (EU AI Act + NIST AI RMF pre-populated)
- Mobile App Backend

### b) Import JSON
Click **⬆ Load JSON** to upload an assessment JSON file. The server
strips any `id`/`createdAt`/`updatedAt` and creates a fresh draft.

### c) Fill in the wizard
The wizard has 8 sections. Plain-English questions; checkboxes for
multi-choice; everything saves to the server when you click **Save
draft**.

> **Tip.** Use **⬇ Download JSON** to keep a local backup before
> sharing the link with someone else.

The 8 sections:

1. **Business overview** — name, problem solved, user types,
   user-interaction prose.
2. **Data classification** — categories (customer/financial/etc.),
   confidentiality flag, sensitive tags (PII/PCI/PHI/Export-Controlled).
3. **Business impact** — worst-case narratives for confidentiality /
   integrity / availability. *The engine reads these and tightens
   the FIPS 199 high-water mark.*
4. **Recovery** — RTO and RPO.
5. **User population** — count band + expected growth.
6. **Integrations** — for each: source, destination, protocol, auth.
7. **Compliance** — pick every framework in scope (16 supported).
8. **Hosting** — AWS / Azure / GCP / Hybrid / On-Prem. *The
   architecture is rendered for the selected cloud.*

A "**+ Advanced**" pane lets technical users override AWS region,
multi-region, MFA enforcement, logging retention, and explicit
include/exclude control IDs.

### Optional attachments

- **IaC reconciliation** — drop a Terraform plan JSON, CloudFormation
  template, or CDK synth output. The next generation compares the
  *deployed* architecture to the *described* one.
- **SBOM** — upload a CycloneDX or SPDX JSON. Vulnerabilities are
  intersected with CISA KEV.
- **Cloud snapshot** — upload an AWS Config / Security Hub / Azure
  Resource Graph / GCP Cloud Asset Inventory JSON for live
  reconciliation.

---

## 4 · Generate the package

Click **Generate ARB Package**. The platform performs:

1. Validation (refuses to fabricate; emits clarification questions).
2. FIPS 199 + 800-60 categorization.
3. Architecture build (cloud-specific) + 3 Mermaid diagrams.
4. STRIDE per-component + per-flow + Operational threats.
5. NIST 800-53 SSP (186 controls, baseline-tailored).
6. Auditable events catalogue + Recovery assessment + WAF scoring.
7. Compliance crosswalk + Evidence requests + Residual risk register.
8. FAIR Monte Carlo (5 000 iterations) + Cost estimate + OSCAL.
9. SBOM / IaC / cloud reconciliation if attached.
10. MITRE ATT&CK + CAPEC + Attack trees + Kill chain mappings.
11. Diff vs. previous version.

Generation typically completes in < 1 second.

---

## 5 · Read and act on the package

The viewer (`/view.html?id=…`) has a 26-section table of contents on
the left and the rendered artifacts on the right. Sections relevant
to each role:

| Role | Sections to focus on |
|---|---|
| **Product Owner** | Executive Summary · Cost Estimate · Diff · ARB Recommendation |
| **Security Architect** | Architecture · Security Overlay · DFD · STRIDE · MITRE · Attack Trees |
| **Security Analyst** | STRIDE per Flow · Operational Threats · Evidence Requests · Audit Events |
| **Compliance / Assessor** | SSP · Compliance Mapping · Evidence Requests · OSCAL export |
| **Risk Officer** | Residual Risk Register · FAIR · Risk Acceptances |
| **Privacy** | LINDDUN · DPIA · Data Classification |
| **SRE** | Recovery · Operational Threats · IaC Reconciliation |

### Comments
Click the bubble icon next to any SSP control, residual risk, or threat
to start a thread. Adding a comment auto-watches that target; other
watchers are notified in their inbox (`/api/comments/inbox`).

### Approvals
The Owner clicks **Request Approval** on the package — this captures
the package's SHA-256 hash and creates an open request for the four
approver roles (Security / Risk / Architecture / Compliance). Each
approver signs or rejects. If you regenerate the package after a
request is open, the hash changes and existing approvals are
invalidated until you re-request.

### Risk treatment
On the residual-risk register:
- **Accept** — records the user, an expiry, and a rationale.
- **Mitigate** — open a Jira or ServiceNow ticket
  (`POST /api/risks/:id/:risk/ticket`).

### Asking questions
Use **Chat with the Package** (`POST /api/chat/:id`) to ask plain
questions. With AI configured you get a free-form answer grounded in
the package data; without AI you get a deterministic FAQ for the most
common questions.

---

## 6 · Export

From the viewer's toolbar:

| Format | Use |
|---|---|
| **PDF** | Signed-by-printer-friendly multi-page report (16+ pages, signature block) |
| **HTML** | Self-contained; Mermaid renders client-side |
| **MD** | Source-of-truth Markdown |
| **JSON** | Full ArbPackage |
| **OSCAL** | NIST OSCAL v1.1.2 SSP (FedRAMP profile import) |
| **CSV: ssp / evidence / residual-risk / audit-events / stride / cost / compliance / diff / fair / sbom** | For Excel, BI tools, GRC |

---

## 7 · Compare versions

Open `/diff.html?id=<id>&from=<v>&to=<v>` for the side-by-side view.
The viewer shows the **Changes Since Last Version** card on every
package automatically.

---

## 8 · Common workflows

### Run an ARB
1. Owner instantiates a template, fills in any gaps, generates the package.
2. Owner shares the URL with the four approvers.
3. Each approver reviews their lane, comments on SSP controls or
   residual risks if needed, and signs.
4. The PDF or HTML export becomes the ARB record.

### Delete a saved assessment
The sidebar list of saved assessments now shows a small `×` button next
to each row. Click it, confirm, and the draft + its generated package
are removed from the server. Server-side authorization is enforced —
you can only delete assessments you own (or, for admins, any
assessment).

### Periodic re-assessment
1. Open the saved assessment; adjust whatever changed (RTO, user
   count, integrations, compliance scope).
2. Generate. The viewer's **Diff** section highlights everything that
   shifted (posture, controls added/removed, components moved, cost
   delta, compliance coverage delta).
3. If posture worsened, open new Jira/ServiceNow tickets directly
   from the residual register.

### Continuous control validation
1. Attach a freshly-pulled AWS Config snapshot (or Security Hub
   findings) to the assessment.
2. Regenerate. The **Cloud Reconciliation** section flags described
   components missing in the live environment and live security
   findings that aren't mitigated by the SSP.

---

## 9 · Glossary

- **FIPS 199** — federal standard for security categorization
  (Low / Moderate / High across CIA).
- **OSCAL** — NIST's machine-readable format for SSPs and assessments.
- **STRIDE** — Spoofing, Tampering, Repudiation, Information
  Disclosure, Denial of Service, Elevation of Privilege.
- **LINDDUN** — Privacy threat-modelling counterpart of STRIDE.
- **FAIR** — Factor Analysis of Information Risk — quantifies risk in
  $/year.
- **CISA KEV** — CISA Known Exploited Vulnerabilities catalogue.
- **SBOM** — Software Bill of Materials (CycloneDX or SPDX).
- **VEX** — Vulnerability Exploitability Exchange — "we're not
  affected because X" statements.
- **DPIA** — GDPR Article 35 Data Protection Impact Assessment.
- **Open mode** — first-run state, before any user is provisioned;
  every request becomes anonymous admin.

---

## 10 · Where to get help

- API surface: see the README's `API` section.
- Administrator concerns: see `ADMIN_GUIDE.md`.
- Network exposure: see `NETWORK.md`.
- Vulnerability disclosure: open a confidential ticket with the
  CISO Office (the operator's process).
