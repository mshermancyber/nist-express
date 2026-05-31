# HTTPS-Only Container — Implementation Prompt

A reusable prompt + checklist for implementing the same HTTPS posture
we shipped in nist-express on any other containerised web app.

Hand this whole file to Claude in the target repo as the brief.

---

## Goal

Make the application **terminate TLS itself inside the container**
on a single published port, with a **self-signed cert generated on
first boot** (replaceable by mounting your own PEM). Plain HTTP is
**not accepted** at the listener layer. Operator gets HTTPS out of
the box; nothing else has to be configured for it to work.

## When to use this pattern

**Good fit:**
- A single-container app where you control both the container and
  the published port.
- Internal / LAN / VPN / single-tenant deployments where browser
  cert warnings on first boot are tolerable.
- Apps the operator runs on a host or small cluster — not behind a
  managed LB that already terminates TLS.

**Bad fit (use a reverse proxy / LB instead):**
- Public-internet deployments behind ALB / Cloudflare / CloudFront —
  let them terminate with a real cert; the app stays HTTP-internal.
- Multi-container apps where one container is already an nginx /
  Envoy / Traefik front door — terminate there, not in the app.
- Stacks that need ALPN / HTTP/2 multiplexing optimisations beyond
  what the language's stdlib server gives you.

## Architecture decisions to confirm with the operator first

Answer these before writing code. The defaults in parentheses are
what we picked for nist-express.

1. **Single port or HTTP+HTTPS pair?**
   Single port HTTPS-only (no HTTP listener) vs. two ports with HTTP
   redirecting to HTTPS. Single is simpler and matches
   "do not allow http anymore" policies; pair is friendlier for
   accidental `http://...` URLs. *Default: single port, HTTPS-only.*

2. **Should we keep an env-driven escape hatch (`ALLOW_HTTP=1`)?**
   Useful during initial cert setup; risky long-term because it
   means a misconfigured env can silently downgrade. *Default: no
   escape; the only bypass is loopback TCP peers for healthchecks.*

3. **Where do the cert/key files live?**
   A writable volume that persists across container restarts and
   that the cert-generation step can write to. *Default:
   `/app/.data/cert.pem` + `key.pem` on a bind-mounted volume.*

4. **Cert SANs?**
   The cert is only valid for hostnames listed in its SubjectAltName
   extension. Browsers will throw a warning for any other hostname
   *even if TLS itself succeeds*. Include every hostname users will
   actually type. *Default for dev: `DNS:localhost, DNS:<app>.local,
   IP:127.0.0.1`. For prod, document how to add the real hostname
   to the entrypoint or supply a real cert.*

5. **Is there a reverse proxy / LB in front?**
   If yes, the app still terminates TLS internally, and the
   proxy must talk HTTPS to the backend (or you accept double-encrypt
   cost). The proxy must forward `X-Forwarded-Proto: https` and
   `X-Forwarded-For` — and the app must trust those headers
   (e.g. Express `app.set('trust proxy', 1)`). *Default: no proxy
   assumed; design works behind one if the operator opts in.*

6. **What happens to inactive sessions?**
   Independent of TLS, but often bundled. Decide on idle-timeout
   policy now — see "Production hardening" below.

## Implementation steps

These steps are framework-agnostic with **Node/Express** specifics
inline. For other stacks (Python/FastAPI, Go, Rust, Java) substitute
the equivalent — flagged at each step where it matters.

### Step 1 — Backup the current state

Whatever the project's backup convention is — run it. We're about
to change the listener, the entrypoint, and the Dockerfile in one
batch; you want to be able to roll back to plain HTTP.

### Step 2 — Audit the current network surface

Find every place the current port + protocol is referenced. Don't
trust greps to find them all; check these in order:

- The app's listener call (`app.listen` / `uvicorn.run` /
  `http.ListenAndServe` / Spring Boot config).
- The Dockerfile (`EXPOSE`, `HEALTHCHECK`).
- The compose file (`ports:`, `healthcheck:` — this **overrides**
  the Dockerfile `HEALTHCHECK`; don't miss it).
- Helm / k8s manifests (`livenessProbe`, `readinessProbe`,
  `service.targetPort`, `containerPort`).
- Terraform / CDK if there's any infrastructure-as-code.
- Helper scripts (`scripts/up.sh`, `scripts/start.sh`, smoke tests).
- Docs (README, INSTALL, NETWORK).
- Settings / permission lists (`.claude/settings.local.json`) — these
  may have curl commands the user pre-approved; flag them but don't
  edit them silently.

Make a list. You'll touch each one.

### Step 3 — Install openssl in the runtime image

The runtime stage of the Dockerfile needs `openssl` for first-boot
cert generation:

```dockerfile
# Alpine:
RUN apk add --no-cache openssl

# Debian/Ubuntu slim:
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
```

If the operator already uses a non-self-signed cert path (mount from
secrets manager), the entrypoint must still degrade gracefully —
but openssl is still the right tool to have available for emergency
regeneration.

### Step 4 — Write the entrypoint

Generate cert/key on first boot if absent. Atomic temp+rename so a
concurrent crash never leaves a half-written cert. `flock` on a
per-CERT-dir lockfile so two containers starting against a shared
volume (k8s rolling deploy, blue-green) can't race the generation.

Save as `deploy/docker-entrypoint.sh` (or wherever the project's
deploy files live). **Don't** use bash-isms; alpine ships busybox sh.

```sh
#!/bin/sh
set -eu

# Whitelist CERT_DIR so a hostile env can't redirect cert writes
# elsewhere or smuggle shell metacharacters.
CERT_DIR="${CERT_DIR:-/app/.data}"
case "$CERT_DIR" in
    /app/.data|/etc/<app>/certs) ;;
    *) echo "[tls] refusing unrecognised CERT_DIR: $CERT_DIR" >&2; exit 1 ;;
esac
CERT="$CERT_DIR/cert.pem"
KEY="$CERT_DIR/key.pem"

mkdir -p "$CERT_DIR"
LOCK="$CERT_DIR/.tls.lock"
( touch "$LOCK" 2>/dev/null || true )

generate_cert() {
    if [ -s "$CERT" ] && [ -s "$KEY" ]; then
        echo "[tls] Using existing cert at $CERT."
        return
    fi
    echo "[tls] No cert found — generating self-signed (365d valid)."
    TMPCERT="$CERT_DIR/.cert.pem.$$"
    TMPKEY="$CERT_DIR/.key.pem.$$"
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -subj "/CN=<app>.local" \
        -addext "subjectAltName=DNS:localhost,DNS:<app>.local,IP:127.0.0.1" \
        -keyout "$TMPKEY" -out "$TMPCERT" 2>/dev/null
    chmod 600 "$TMPKEY"
    chmod 644 "$TMPCERT"
    mv "$TMPCERT" "$CERT"
    mv "$TMPKEY"  "$KEY"
    echo "[tls] Self-signed cert ready. Replace $CERT / $KEY for production."
}

(
    if command -v flock >/dev/null 2>&1; then
        flock -x 200
    fi
    generate_cert
) 200>"$LOCK"

exec "$@"
```

Replace `<app>` with the project's short name. Adjust `-days` if a
shorter or longer validity is preferred.

### Step 5 — Wire the entrypoint into the Dockerfile

```dockerfile
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# If you already use tini for PID 1:
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
# If not:
# ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

CMD ["node", "dist/server.js"]   # or whatever the runtime command is
```

### Step 6 — Switch the app's listener to HTTPS

**Node / Express:**

```ts
import https from 'https';
import fs from 'fs';
import path from 'path';

const certDir = process.env.CERT_DIR ?? '/app/.data';
const tlsOptions = {
  cert: fs.readFileSync(path.join(certDir, 'cert.pem')),
  key:  fs.readFileSync(path.join(certDir, 'key.pem'))
};
const server = https.createServer(tlsOptions, app).listen(PORT, () => {
  logger.info('listening', { port: PORT, tls: true });
});
```

**Python / FastAPI** (`uvicorn.run`):

```python
uvicorn.run(
    "app.main:app",
    host="0.0.0.0",
    port=PORT,
    ssl_certfile="/app/.data/cert.pem",
    ssl_keyfile="/app/.data/key.pem",
)
```

**Go / net/http**:

```go
log.Fatal(server.ListenAndServeTLS("/app/.data/cert.pem", "/app/.data/key.pem"))
```

**Java / Spring Boot** (`application.yml`):

```yaml
server:
  port: 13042
  ssl:
    enabled: true
    key-store: /app/.data/keystore.p12
    key-store-type: PKCS12
    key-store-password: ${KEYSTORE_PASSWORD}
```

(Spring wants a keystore, not raw PEM — adjust the entrypoint to
produce a `.p12` via `openssl pkcs12 -export …`.)

**Crash on missing cert is the correct behaviour.** Don't wrap the
file read in a try/catch that falls back to HTTP — the operator must
notice if the cert is gone.

### Step 7 — Remove any HTTP listener

Search for and delete every `app.listen(plainHttp)`, `http.Server`,
`uvicorn.run(..., ssl_certfile=None)` etc. There should be **one**
listener and it should be HTTPS. Plain HTTP requests will get
"connection refused" from outside the container.

### Step 8 — Update the healthcheck (in BOTH places)

The Dockerfile `HEALTHCHECK` and the compose `healthcheck:` stanza
are independent — compose **overrides** the Dockerfile. Update both:

**Dockerfile:**

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
  CMD wget --no-check-certificate -qO- "https://127.0.0.1:${PORT}/readyz" || exit 1
```

**docker-compose.yml:**

```yaml
healthcheck:
  test: ["CMD", "wget", "--no-check-certificate", "-qO-", "https://127.0.0.1:13042/readyz"]
  interval: 30s
  timeout: 5s
  start_period: 10s
  retries: 5
```

(Use `curl -k` if the base image has curl but not wget.)

**Important:** If your app has middleware that refuses non-loopback
HTTP, the healthcheck on `127.0.0.1` must be exempt — see Step 9.

### Step 9 — Keep the application-layer HTTPS gate as defence in depth

Even with TLS terminated in-process, keep (or add) an HTTPS-enforcing
middleware. It's a no-op for in-process TLS (every connection is
already `req.secure: true`), but it remains a safety net if someone
ever reintroduces an HTTP listener or fronts the container with a
reverse proxy. Two requirements that bit us:

- **Loopback exemption must check the TCP peer, not the Host
  header.** A request that arrives through a reverse proxy with
  `Host: localhost` is NOT loopback — its TCP connection traversed
  the network. Use `req.socket.remoteAddress` (Node) /
  `request.client.host` (FastAPI/Starlette) / `RemoteAddr` (Go).
  Only `127.0.0.1` and `::1` peers count as loopback.

- **Open-redirect defence.** If you redirect HTTP→HTTPS, the
  redirect target host must come from an env-configured canonical
  hostname (`CANONICAL_HOST`) OR an inbound `Host` header that
  appears in an allow-list (`ALLOWED_HOSTS`, comma-separated). With
  neither set, return **421 Misdirected Request** rather than
  constructing a redirect you can't vouch for.

Reference implementation (Node/Express): see
`/data/nistexpdocker/src/auth/requireHttps.ts`.

### Step 10 — Update env wiring in compose

Add the new env vars to the backend service block:

```yaml
environment:
  PORT: "13042"
  # No ALLOW_HTTP. There is no escape.
  ALLOWED_HOSTS: "${ALLOWED_HOSTS:-localhost,127.0.0.1}"
  TRUST_PROXY: "${TRUST_PROXY:-1}"
```

`TRUST_PROXY` matters only if a reverse proxy is in front, but
setting it to 1 by default is safe because the only consumer is
`req.secure` (which the HTTPS listener already makes true).

### Step 11 — Verify

Rebuild and recreate the container (NOT just `up -d` — the entrypoint
and CMD changes may not trigger recreation without `--force-recreate`
or removing the container first):

```bash
docker compose up -d --build --force-recreate
```

Then:

```bash
# Container should be healthy
docker inspect <container> --format '{{.State.Health.Status}}'

# HTTPS works
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost:13042/readyz

# HTTP refused (TLS handshake fails on the client side)
curl -s -o /dev/null --connect-timeout 3 -w "%{http_code}\n" http://localhost:13042/

# Cert is what you expect
docker exec <container> openssl x509 -in /app/.data/cert.pem \
  -noout -subject -ext subjectAltName
```

### Step 12 — Update docs

Anywhere docs say `http://<host>:<port>`, flip to `https://`. Note
the self-signed cert and the `--no-check-certificate` / `-k` flags.
Note that the operator can drop their own PEM at `cert.pem` / `key.pem`
to override.

## Gotchas we hit — don't repeat them

These cost us real cycles. Front-load them into your plan.

1. **Compose healthcheck overrides Dockerfile HEALTHCHECK.**
   We rebuilt the image with the new HTTPS healthcheck in the
   Dockerfile and the container stayed "starting" forever, because
   `docker-compose.yml` had its own `healthcheck: http://...` block.

2. **Loopback exemption on Host header is a bypass.**
   First cut of `_is_loopback` used `request.url.hostname` (Host
   header), which made every browser request from
   `https://localhost:port` exempt from the HTTPS gate. Behind nginx,
   *every* request had `Host: localhost` even when arriving over the
   network. Use TCP peer (`request.client.host` /
   `req.socket.remoteAddress`), not the Host header.

3. **The compose `up -d --build` may NOT recreate the container.**
   If only the entrypoint or the cmd changed (image label same),
   compose may keep the existing container running. Use
   `--force-recreate` or `docker compose down` first.

4. **`fs.readFileSync` of cert/key fails loudly if missing — that's
   correct.** Don't add a try/catch that falls back to HTTP. The
   operator must notice a missing cert.

5. **Cert SANs must include the actual hostname the user will type.**
   We initially shipped SANs for `localhost, 127.0.0.1, nist.local`.
   The operator tried `https://192.0.2.10:13042` and got "cert is
   not valid for this name" (handshake succeeded, but the browser
   warned and refused to remember the trust). Document how to add a
   SAN or supply a real cert. Consider an env var that templates SANs
   into the openssl invocation.

6. **The Express `secure` cookie flag needs to actually be set.**
   Once TLS is in-process, `req.secure` is always true, but cookies
   you set via `res.cookie({ secure: process.env.REQUIRE_HTTPS === '1' })`
   will still be missing `Secure` if you didn't set that env. Just
   set `secure: true` unconditionally — you've committed to TLS.

7. **`new URL()` normalises octal/decimal/hex IPv4** to canonical
   dotted form. So `http://0177.0.0.1`, `http://2130706433`, and
   `http://0x7f000001` all collapse to `127.0.0.1` before your code
   sees the hostname. Don't waste time "defending" against these
   forms in your hostname validators.

8. **Audit findings claiming "X-Forwarded-Proto bypass" once you're
   HTTPS-only** are dead code. There is no HTTP listener for a
   client to send `X-F-P: https` over. Don't add complex defences
   for a path that doesn't exist.

## Production-hardening checklist (do these next, not now)

The minimum-viable implementation above gets you to "browser
accepts the cert and the connection is encrypted." For production,
also consider:

- **HSTS header** on every response (`Strict-Transport-Security:
  max-age=31536000; includeSubDomains; preload`) — most frameworks'
  security middleware (helmet, Spring Security, Starlette) emit this
  automatically once TLS is detected.
- **TLS version + cipher policy.** Disable TLS 1.0/1.1, prefer
  AEAD ciphers (the Mozilla "intermediate" list is the easy default).
- **Real cert from Let's Encrypt / cloud KMS.** Document how to drop
  the PEM pair into the volume. Consider an init container that
  fetches from a secret store.
- **Cert renewal.** A 365-day self-signed cert quietly expires.
  Either rotate via the entrypoint on each restart, ship with a
  rotation cronjob, or push the operator toward a real CA.
- **Mutual TLS (mTLS)** for inter-service traffic if applicable —
  the entrypoint pattern extends naturally to client certs too.
- **OCSP stapling / CT logs** — only relevant once you're on a real
  cert chain.

## Reference implementation

This pattern is live in nist-express:

- Entrypoint: `deploy/docker-entrypoint.sh`
- Dockerfile changes: `deploy/Dockerfile` (search "openssl" and
  "HEALTHCHECK")
- Listener: `src/server.ts` (search "https.createServer")
- Defence-in-depth middleware: `src/auth/requireHttps.ts`
- Compose env + healthcheck: `deploy/docker-compose.yml`

Read those files together with this prompt for a complete picture.
