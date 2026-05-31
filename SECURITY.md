# Security Policy

## Supported versions

The most recent tagged release on `main` is the only version that
receives security fixes. Older tags are archived and will not be
patched.

| Version | Supported |
| --- | --- |
| latest `main` | ✅ |
| previous tags | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security reports.**

Use **GitHub's "Report a vulnerability" workflow** under the
repository's *Security* tab. That keeps disclosure private until a
fix is available.

We aim to:

- acknowledge a report within **3 business days**,
- publish a fix or a documented mitigation within **30 days** of
  acknowledgement for high-severity findings,
- credit reporters who request attribution after the fix ships.

## What is in scope

Issues affecting NIST Express itself — the server, the deterministic
generation engine, the auth / session / RBAC layer, the SCIM endpoint,
the audit-chain, the upload paths, the AI-augmentation glue.

## What is out of scope

- Findings that require already-compromised hosts or stolen
  credentials.
- Denial-of-service via resource exhaustion when the platform is
  deployed without the recommended reverse-proxy rate-limits.
- Vulnerabilities in third-party dependencies — please report those
  upstream first; we will fast-track an upgrade once a fix exists.
- Configuration choices made by the operator (e.g. supplying a weak
  TLS cert via `/app/.data/cert.pem`, disabling `cap_drop`).

## Hardening defaults this project ships with

- **TLS terminated in-process** on the published port. The container
  generates a self-signed cert on first boot and refuses plain-HTTP
  connections — there is no `ALLOW_HTTP` env escape. Loopback peers
  (the docker healthcheck) are exempt at the application layer only.
- **HMAC-SHA256 signed session and sudo cookies**, `HttpOnly`,
  `SameSite=Strict`, `Secure` unconditional. Sudo signs with a
  dedicated key (`/app/.data/sudo-secret`) so a session-secret
  rotation does not silently revoke active elevations.
- **5-minute idle session timeout** with sliding refresh: an active
  user is not kicked out mid-form, but true inactivity expires.
- **bcrypt** for password hashing. Password policy requires ≥ 12
  characters AND all four character classes (upper, lower, digit,
  special) plus a curated breach deny-list.
- **TOTP** RFC 6238 second-factor available per-user, with **per-user
  replay protection**: a successfully-validated code's step is
  recorded, and the same code cannot be re-consumed within the drift
  window.
- **Per-username and per-IP login throttling** with cooldown;
  counters persist to disk so a restart cannot escape an active
  lockout. **Per-user change-password rate limit** (5 fails per hour)
  caps stolen-session brute force.
- **CSRF double-submit token** on every state-changing route,
  `Secure` for off-loopback hosts.
- **Static-page auth gate** (`requirePageAuth`) — anonymous HTML
  navigation is 302-redirected to `/login.html`; path is canonicalised
  (null byte stripped, `..` collapsed, lowercased) before matching.
- **SSRF defence** (`engine/safeFetch.ts`): RFC 1918 / loopback / link
  local / CGNAT / cloud-metadata blocklist, including the IPv4-mapped
  IPv6 (`::ffff:127.0.0.1`) and `0.0.0.0/8` edge cases; redirect chain
  is followed manually with every hop re-validated, max 5 hops.
- **Audit chain** — HMAC-SHA256 hash-linked JSONL with a dedicated
  key (rotation-independent from session). Field-level before/after
  values captured on user PATCH (`<unset>` sentinel disambiguates
  cleared vs untouched); `notes` content redacted to length only.
- **Soft delete by default** on `DELETE /api/auth/users/:id`. The row
  is preserved with a `deletedAt` tombstone and the user is hidden
  from auth lookups; `?hard=1` performs irreversible erasure. Both
  refuse to delete the actor or the last active admin.
- Helmet defaults: CSP, frame-ancestors `'none'`, COOP/CORP same-origin.
- File-upload size + count limits, slowloris deadline, multer error
  handler that returns clean 413/400.
- SCIM endpoints behind a separate `SCIM_TOKEN`. SCIM filter charset
  is locked to the create-side username validator so a client cannot
  search for usernames the API would refuse to create.
