# NIST Express v1.1.0 — release build

Packaged release built from the installed container tree on
2026-05-31 (UTC). See `CHANGELOG.md` for the full list of changes
since v1.0.0.

## What's different from the installed tree

| Aspect | Installed tree | This release |
| --- | --- | --- |
| Default port | 13042 | 8080 |
| Allowed ports | 13042 only | 80, 443, 8080, 8443 |
| Identifiable info | dev-only fixtures permitted | scrubbed |
| Operator tooling | `scripts/`, `CLAUDE.md` checked in | not included |
| Runtime state | persisted in Docker volume | none — bootstrap on first run |
| Body-parser errors | global 500 | 400 for `SyntaxError` (release-only) |

## Headline features new in 1.1.0

- **In-process TLS termination** on the published port with
  auto-generated self-signed cert on first boot. No plain-HTTP
  fallback. Mount your own PEM at `/app/.data/cert.pem` + `key.pem`
  to override.
- **5-minute idle session timeout** with sliding refresh on activity.
- **Admin user-management UI at `/users.html`** with metrics,
  sortable / paginated grid, soft-delete, force-password-reset, and a
  security panel (current lockouts, recent failed logins, recent
  password resets, recent admin actions).
- **Soft-delete users** by default; hard-delete with `?hard=1` after
  sudo re-auth. Both refuse to delete the actor or the last active
  admin.
- **Password policy upgraded** to require all four character classes
  (upper, lower, digit, special) plus a curated breach deny-list.
- **TOTP replay protection** (per-user accepted-step tracking).
- **SSRF blocklist** in `safeFetch` now covers `0.0.0.0/8` and
  IPv4-mapped IPv6 (`::ffff:127.0.0.1`); every redirect hop is
  re-validated, max 5 hops.
- **Audit-log hardening**: hostile bytes in `username` / `ip` /
  per-record fields land as `<malformed:N>` sentinels rather than raw
  payloads. PATCH endpoints capture before/after per touched field.
- **Body-parser 500 → 400 fix** (release-tree only — see CHANGELOG).

## Running

Container (recommended):

```
docker compose -f deploy/docker-compose.yml up -d --build
```

Bare metal:

```
npm ci
npm run build
PORT=8080 npm start
```

For privileged ports (80 / 443) either grant
`CAP_NET_BIND_SERVICE` (`setcap 'cap_net_bind_service=+ep' "$(which node)"`)
or place the app behind a reverse proxy that handles TLS termination
and forwards to 8080.

## Sample assessments

Five ready-to-import JSON fixtures ship under `examples/`. From
the running app, click *Load JSON* on the wizard page and pick one
to seed a draft.

## Provenance

Built from the installed tree at `/data/nistexpdocker`. The installed
tree's port configuration and the running container were not
modified during this build. Identifiable info was scrubbed: real
hostnames, real customer / employer / agency references, and any IP
addresses other than `127.0.0.1`, `0.0.0.0`, or RFC-5737
documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`). The `logo.jpg` and any public GitHub URLs are
preserved.
