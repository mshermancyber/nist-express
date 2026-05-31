# NIST Express — Network Port & Protocol Guide

Every port the platform uses, in which direction, and to whom. Pair
this with `iptables-open.sh` (or the equivalent Security Group / NSG /
firewall rule in your environment).

---

## 1 · TL;DR

| Direction | Port | Protocol | Purpose | Required? |
|---|---|---|---|---|
| **Inbound** | **8080** | TCP / HTTP (or HTTPS via reverse proxy) | Web UI + REST API | **Yes (required)** |
| Outbound | 53 | UDP/TCP | DNS resolution | Yes (most networks) |
| Outbound | 443 | TCP / HTTPS | AI provider, webhooks, Jira, ServiceNow, Mermaid CDN | Optional, per-feature |
| Outbound | 5432 | TCP / Postgres | DB persistence | Only if `DATABASE_URL` is set |
| Outbound | 4317 / 4318 | TCP / OTLP (gRPC / HTTP) | OpenTelemetry traces | Only if `OTEL_EXPORTER_OTLP_ENDPOINT` is set |
| Outbound | 80 | TCP | None used directly; some webhook endpoints may redirect 80→443 | Discouraged |
| Outbound | 11434 | TCP / HTTP | Ollama (if AI_BASE_URL points there) | Only with local Ollama |

The platform itself listens on **a single TCP port** in the band
`80, 443, 8080, 8443` (default `8080`). Ports outside that range are
refused at startup.

---

## 2 · Inbound

### 8080/tcp — the only inbound port
- Speaks plain HTTP/1.1 (or HTTP/2 if the reverse proxy upgrades).
- Carries the web UI, the REST API, the metrics endpoint, and the
  health check.
- All authentication, CSRF, rate-limiting, and per-user limiting are
  handled in-process.
- Should be **fronted by a TLS terminator** in production (ALB,
  nginx, Caddy, Cloudflare).

#### Who should be allowed in?
| Audience | Source | Recommended firewall rule |
|---|---|---|
| End users (browsers) | Corporate VPN or office CIDRs | Allow from corp CIDRs only |
| CI pipelines (using API keys) | CI runner subnets / GitHub Actions egress IPs | Allow specific CIDRs |
| Liveness checks | ALB / health-checker subnet | Allow from LB SG |
| Metrics scrape | Prometheus | Allow from monitoring subnet |
| Public internet | _(typically no)_ | Block by default |

If a host firewall is in effect on your deployment box, open the
listener port (8080 by default) to the source subnets that need it.
Most cloud images and stock Ubuntu installs ship with no host
firewall enabled, in which case nothing additional is required.

---

## 3 · Outbound

The platform makes outbound calls in **only** these situations:

### a) AI augmentation
- When: `AI_API_KEY` is set OR `AI_BASE_URL` resolves to localhost.
- Destination: whatever `AI_BASE_URL` resolves to (OpenAI, Anthropic
  OpenAI-compat endpoint, LiteLLM gateway, Azure OpenAI gateway,
  Ollama).
- Port: 443 (OpenAI / Anthropic), 11434 (Ollama default), or whatever
  your gateway uses.
- Frequency: once per `POST /api/generate/:id` and once per
  `POST /api/chat/:id`.

### b) Webhooks
- When: an admin has registered a webhook AND an event fires
  (`package.generated`, `approval.signed`, etc.).
- Destination: the URL configured per-subscription.
- Port: 443 (Slack / Teams / generic).
- SSRF guard: refuses private / link-local / metadata / loopback
  destinations unless the host is on `OUTBOUND_ALLOW_HOSTS`.

### c) Jira / ServiceNow
- When: a user creates a residual-risk ticket and the env vars are
  set.
- Destination: `JIRA_BASE_URL` / `SERVICENOW_BASE_URL`.
- Port: 443.

### d) Postgres
- When: `DATABASE_URL` is set.
- Destination: the DB host:port (default 5432).
- Port: 5432.

### e) OpenTelemetry traces
- When: `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
- Destination: typically a collector in your monitoring VPC.
- Port: 4317 (gRPC) or 4318 (HTTP).

### f) Mermaid CDN
- When: a browser opens the HTML viewer.
- This is **from the browser**, not from the server, but it does mean
  client machines need outbound 443 to `cdn.jsdelivr.net` to render
  diagrams. If your client network blocks the CDN, you can self-host
  the Mermaid file — drop it under `public/lib/mermaid.esm.min.mjs`
  and edit the import in `public/view.html`.

---

## 4 · Suggested AWS Security Group

```hcl
# Inbound: only the ALB SG can reach the ECS task on 8080
resource "aws_security_group" "task" {
  name   = "arb-task"
  vpc_id = var.vpc_id
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    # AI provider + webhooks + Jira + ServiceNow + Postgres + OTel
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.rds.id]
  }
  egress {
    from_port = 53
    to_port   = 53
    protocol  = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

---

## 5 · Suggested Kubernetes NetworkPolicy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: arb-default
  namespace: arb
spec:
  podSelector: { matchLabels: { app: nist-express } }
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - namespaceSelector: { matchLabels: { name: ingress-nginx } }
      ports:
        - port: 8080
          protocol: TCP
  egress:
    - to:
        - namespaceSelector: { matchLabels: { name: kube-system } }
      ports: [{ port: 53, protocol: UDP }]
    - to:
        # The CIDR for your internet egress — narrow to the AI / SaaS targets you actually use
        - ipBlock: { cidr: 0.0.0.0/0, except: ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"] }
      ports:
        - { port: 443, protocol: TCP }
    - to:
        - podSelector: { matchLabels: { app: postgres } }
      ports: [{ port: 5432, protocol: TCP }]
```

---

## 6 · TLS termination

**The application terminates TLS itself on 8080.** Plain HTTP is
not accepted at the listener layer. On first boot, the entrypoint
generates a self-signed cert at `/app/.data/cert.pem` + `key.pem`
(CN=`nist.local`, SANs for `localhost` and `127.0.0.1`); to use a
real cert, drop your PEM pair into the same paths.

You can still front the container with a reverse proxy / load
balancer for hostname routing, WAF, or to re-terminate TLS with a
publicly-trusted cert. In that case the upstream proxy should:
- Set `X-Forwarded-Proto: https`,
- Set `X-Forwarded-For` with the real client IP,
- Be configured to talk to the backend over HTTPS (the backend will
  refuse HTTP).

Set `TRUST_PROXY=1` so the in-app rate-limiter sees the real client
IP. Loopback peers inside the container (the docker healthcheck) are
exempt from the HTTPS enforcement layer so health probes keep working.

The HSTS header is emitted by helmet (`max-age=31536000;
includeSubDomains; preload`) and will fire on every response since
the backend connection is always TLS-terminated.

---

## 7 · ICMP / management

The application doesn't initiate or accept ICMP. For health checks
prefer the HTTP `/healthz` endpoint over ICMP echo — it confirms the
app is actually responding, not just that the kernel is up.

---

## 8 · Default-deny rule of thumb

If you're not sure whether to open a port, leave it closed:

- Block all inbound except 8080 (and 22 if you need ad-hoc SSH).
- Egress to internal only by default; allow specific HTTPS
  destinations as features (AI / webhooks / ticketing) are
  configured.

The platform is designed to fail-closed: a feature that can't reach
its destination logs an error and the rest of the application keeps
working.
