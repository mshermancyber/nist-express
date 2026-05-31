# Logging guide

The platform ships with **six** logging levels and is **OFF by default
in production** so no logs are emitted unless the operator opts in.
Use `LOG_LEVEL` to choose.

## Levels

| Level | What it includes | When to use |
|---|---|---|
| `off` | nothing | **Production default.** Quiet ops. |
| `error` | operational failures + 500-level responses | Always at least this in prod ops. |
| `warn` | degradation, retries, soft errors, throttle hits | Recommended during incident response. |
| `info` | startup, lifecycle, request summaries (rid + ms) | Day-to-day operations. |
| `debug` | per-component decisions, branch outcomes, engine timing | When investigating a specific feature. |
| `trace` | **highly verbose** — every store call, every AI prompt, full request bodies | Reproducing a hard bug in pre-prod. |

## Format

One JSON line per event. Fields are at least:

```
ts    ISO 8601 timestamp
level error|warn|info|debug|trace
msg   short message
```

Plus any structured fields supplied by the caller (e.g.
`rid`, `module`, `assessmentId`, `tokens`, `outcome`, etc.).

Secrets (`password`, `passwordHash`, `secret`, `apiKey`, `token`,
`authorization`, `cookie`, `totpSecret`, `kek`, …) are **redacted
recursively** before output. Strings longer than 4 096 chars are
truncated.

## Configure

`LOG_LEVEL` is read at startup. Set it through whatever the
deployment uses for env vars:

```bash
# Docker compose
LOG_LEVEL=debug docker compose -f deploy/docker-compose.yml up -d

# docker run
docker run -e LOG_LEVEL=trace -e LOG_FILE=/app/.data/server.jsonl ... nist-express:1.1.0

# Ubuntu / systemd
sudo sed -i 's/^LOG_LEVEL=.*/LOG_LEVEL=debug/' /etc/nist-express/env
sudo systemctl restart nist-express

# Bare metal, one-shot
LOG_LEVEL=trace LOG_FILE=/var/log/nist-express.jsonl node dist/server.js
```

`LOG_FILE` writes a copy in addition to stdout/stderr — useful when
you also want to ship to a SIEM but want stdout for Docker.

## Per-module child loggers

Modules call `loggerFor('engine.package')` to bind a `module` field
to every event. This makes per-module filtering trivial:

```bash
docker compose -f deploy/docker-compose.yml logs -f \
  | jq -c 'select(.module == "engine.package")'
```

## Runtime introspection

`GET /api/logging` (admin / analyst) reports the currently configured
level + the available levels:

```json
{ "configured": "info", "available": ["off","error","warn","info","debug","trace"] }
```

The level is set at process start; changing it requires a restart.
