# Changelog

All notable changes to NIST Express are documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to semantic versioning.

## [1.1.0] — 2026-05-31

### Added
- **In-process TLS termination.** The container now listens on
  `https://0.0.0.0:8080` directly (release default; the installed tree used 13042). `deploy/docker-entrypoint.sh`
  auto-generates a self-signed cert on first boot (CN=`nist.local`,
  365-day validity, SANs `DNS:localhost,DNS:nist.local,IP:127.0.0.1`)
  at `/app/.data/cert.pem` + `key.pem`. Mount your own cert at the
  same paths to override. The entrypoint uses `flock` and atomic
  temp+rename so simultaneous container starts cannot race.
- **Static-page auth gate** (`src/middleware/requirePageAuth.ts`).
  Anonymous HTML page requests are 302-redirected to `/login.html`;
  static assets and health/metrics pass through. The path is
  canonicalised (null bytes stripped, `..` collapsed, trailing slash
  dropped, lowercased) before the passthrough check.
- **Mobile / device-class infrastructure.** New `src/middleware/deviceDetect.ts`
  emits `X-Device-Class: ios|android|desktop`. New `public/device.js`
  sets `data-device` on `<html>` before first paint. Tablets resolve
  to `desktop`. New CSS adds `env(safe-area-inset-*)` paddings on iOS
  at ≤768px and a `@media (hover: none)` guard against stuck-hover on
  touch devices.
- **5-minute idle session timeout with sliding refresh.** `withSession`
  re-issues the cookie when more than half the TTL has elapsed; true
  inactivity expires the session at 5 minutes.
- **Admin User Administration UI at `/users.html`.** Filterable user
  grid with metrics tiles (Total / Active / Disabled / Admins / MFA /
  Soft-deleted), add-user dialog, inline edit, enable / disable /
  force-password-change / delete actions. Re-prompts for sudo
  in-place when the server replies `403 sudo:false`.
- **Extended `User` profile fields.** Optional `email`, `firstName`,
  `lastName`, `department`, `jobTitle`, `phone`, `timezone`, `notes`;
  lifecycle fields `updatedAt`, `lastLoginAt`, `forcePasswordChange`,
  `deletedAt`. All editable via `PATCH /api/auth/users/:id` (zod
  `.strict()` schema — username / passwordHash / id / createdAt are
  not mutable through this surface).
- **Soft delete users.** `DELETE /api/auth/users/:id` soft-deletes by
  default (sets `deletedAt`, marks disabled, preserves the row for
  audit). `?hard=1` performs irreversible erasure and can target
  previously soft-deleted rows. Both refuse to delete the actor or
  the last active admin.
- **Force password change.** `POST /api/auth/users/:id/force-password-change`
  flags a user; login response reports `forcePasswordChange: true`;
  new `POST /api/auth/change-password` accepts current+new password,
  clears the flag, and is rate-limited at 5 fails per user per hour.
- **Delete saved assessments** is surfaced in the sidebar as a `×`
  button per row with confirm-then-delete. Backend `canAccessAssessment`
  authz check is unchanged.
- Project branding rename to **NIST Express** across HTML, README, and
  documentation. Logo + favicon shipped at `public/logo.jpg`, displayed
  on the login screen and in the sidebar of every signed-in page.
- `SECURITY.md` — responsible disclosure policy.

### Changed
- Helmet CSP `upgrade-insecure-requests` is now gated on
  `REQUIRE_HTTPS=1`. Previously emitted unconditionally, which caused
  browsers on plain-HTTP deployments to silently upgrade follow-up
  navigations to HTTPS and fail to reach the server.
- Session and sudo cookies are now `Secure` unconditionally (the
  container terminates TLS itself).
- **HTTPS is mandatory.** `src/auth/requireHttps.ts` was previously
  opt-in via `REQUIRE_HTTPS=1`; it is now always-on, with the only
  exemption being loopback TCP peers (so `docker exec curl` and the
  internal healthcheck still work). The `ALLOW_HTTP` env var is
  removed; there is no escape hatch.
- **Session TTL** dropped from 8 hours to **5 minutes** with sliding
  refresh on activity. Operator policy.
- **Password policy** upgraded from "≥ 12 chars, ≥ 2 character
  classes" to **all four classes required** (upper, lower, digit,
  special), plus the curated breach deny-list.
- **TOTP replay protection.** New `verifyTotpAndConsume(userId, ...)`
  records the last-accepted step per user and rejects re-use within
  the ~90-second drift window. Login and sudo gates use it;
  enrollment (one-time secret confirmation) keeps plain `verifyTotp`.
- **Sudo HMAC secret** moved from the shared `session-secret` file to
  a dedicated `.data/sudo-secret`. Rotating the session secret no
  longer silently invalidates active sudo elevations. Exclusive-create
  on first generation; refuses to sign with a malformed key.
- **CSRF cookie** now sets `Secure` for any non-loopback Host; missing
  or malformed Host header defaults to `Secure` (fail closed).
- **Login throttle counters** persist to `.data/login-throttle.json`
  via atomic temp+rename, so a restart cannot be used to escape an
  active cooldown.

### Fixed
- SCIM `GET /v2/Users` rejects `startIndex < 1` and unbounded `count`,
  caps `count` at 200 (RFC 7644 §3.4.2.4).
- SCIM `POST/PUT /v2/Users` enforces the same username regex as local
  auth (back-door closure).
- Notification log rotation no longer drops entries written between
  the snapshot read and the rename.
- Login throttling no longer bypasses per-IP counting when the IP is
  blank or unresolved.
- Background job worker `setInterval` now `unref`s, allowing clean
  shutdown.
- Sudo and session token verification check `typeof exp === 'number'`
  before age comparison.
- Multer upload errors return clean 413 / 400 instead of leaking a
  500 stack trace.
- **Express body-parser errors return 400, not 500.** Malformed JSON
  (e.g. NUL bytes, truncated payloads) used to surface through the
  global error handler as a 500, which polluted SLO dashboards with
  what are actually client errors. The handler now detects
  `SyntaxError` decorated with a `body` field (express.json's signal)
  and returns 400, and respects body-parser's `status` field for the
  413 / 414 path. Server-side faults still log at `error`; client
  faults now log at `warn`.
- `process.unhandledRejection` and `uncaughtException` log with
  context and trigger graceful shutdown.

### Security
- **IDOR closures.** `GET /api/risks/tickets` and `/api/risks/acceptances`
  are now `requireRole('admin')`; `GET /:assessmentId/:riskId/ticket`
  and `POST /:assessmentId/:riskId/release` gain `requireAccess`;
  `DELETE /api/comments/:id` checks author OR admin AND requireAccess
  on the parent assessment.
- **Missing `requireSudo`** added to `POST /api/auth/users/:id/enable`
  (the symmetric `/disable` already had it).
- **SSRF blocklist** in `engine/safeFetch.ts` now covers `0.0.0.0/8`
  and normalises IPv4-mapped IPv6 (`::ffff:a.b.c.d` in both dotted
  and hex forms) before the CIDR check. The fetch loop is rewritten
  to use `redirect: 'manual'`; every redirect hop's `Location` is
  re-validated through `validateHost`, capped at 5 hops.
- `engine/ai.ts` and `obs/otel.ts` no longer call `fetch` directly —
  both route through `safeFetch` with `allowPrivate: true` so the
  protocol allowlist and redirect re-validation still apply.
- **YAML safety**: `engine/iac.ts` parses CloudFormation YAML with
  `yaml.JSON_SCHEMA`, blocking `!!js/function` and other unsafe
  constructors.
- **SBOM / IaC document size caps** (50 MB each) prevent
  unbounded-input DoS through `JSON.parse`.
- **KEK file** creation uses `{ flag: 'wx' }` exclusive-create,
  eliminating the TOCTOU between exists + write.
- **SCIM filter** is capped at 200 chars; the captured username is
  validated against the same regex the create endpoint enforces, so
  filter / create can never disagree on what's permissible.
- **`requirePageAuth`** canonicalises the path (null-byte strip,
  `..` collapse, trailing-slash drop, lowercasing) before matching
  against the passthrough set, defeating gate bypass via funny
  encoding.
- **Per-user-and-IP rate limiter** in `auth/perUserLimit.ts` does a
  bounded probabilistic sweep so stale buckets cannot accumulate
  indefinitely from scraper traffic.
- **`change-password` rate limit** (5 fails per user per hour) caps
  stolen-session brute-force attempts.
- **PATCH `/users/:id` audit** captures field-level before/after with
  a `<unset>` sentinel so reviewers can distinguish "cleared" from
  "untouched"; `notes` content is redacted to `<N chars>`.
- **`/users/:id/disable` audit** logs only `reasonLength` and an
  80-char preview, not the raw reason.
- Removed unused `uuid@9` dependency in favour of
  `crypto.randomUUID()` (eliminates CVE noise).
