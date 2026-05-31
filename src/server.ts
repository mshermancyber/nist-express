import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import compression from 'compression';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import path from 'path';
import https from 'https';
import fs from 'fs';
import { assessmentsRouter } from './routes/assessments';
import { generateRouter } from './routes/generate';
import { exportRouter } from './routes/export';
import { authRouter, withSession } from './auth/auth';
import { userAuthRouter } from './auth/userAuth';
import { approvalRouter } from './routes/approval';
import { auditRouter } from './routes/audit';
import { iacRouter } from './routes/iac';
import { sbomRouter } from './routes/sbom';
import { cloudRouter } from './routes/cloud';
import { commentRouter } from './routes/comments';
import { templatesRouter } from './routes/templates';
import { webhookRouter } from './routes/webhooks';
import { riskRouter } from './routes/risks';
import { chatRouter } from './routes/chat';
import { jobsRouter } from './routes/jobs';
import { asvsRouter } from './routes/asvs';
import { fedrampRouter } from './routes/fedramp';
import { scimRouter } from './routes/scim';
import { loggingRouter } from './routes/logging';
import { passwordResetRouter } from './routes/passwordReset';
import { dsarRouter } from './routes/dsar';
import { selfSbomRouter } from './routes/selfSbom';
import { openapiRouter } from './routes/openapi';
import { tryEnableFips } from './engine/fips';
import { requireHttps } from './auth/requireHttps';
import { sudoRouter } from './auth/sudo';
import { csrfMiddleware, csrfRouter } from './auth/csrf';
import { perUserLimiter } from './auth/perUserLimit';
import { deviceDetect } from './middleware/deviceDetect';
import { requirePageAuth } from './middleware/requirePageAuth';
import { runMigrations } from './store/migrations';
import { logger } from './obs/logger';
import { httpDuration, httpRequests, render as renderMetrics, packagesGenerated } from './obs/metrics';
import { startSpan, endSpan, newRequestId } from './obs/otel';
import { startWorker, register } from './jobs/queue';

const PORT = Number(process.env.PORT ?? 8080);
// Release builds restrict to standard service ports. Operators
// choosing 80/443 must grant CAP_NET_BIND_SERVICE or run behind a
// reverse proxy that handles privileged binding.
const ALLOWED_PORTS = new Set([80, 443, 8080, 8443]);
if (!ALLOWED_PORTS.has(PORT)) {
  throw new Error(`PORT ${PORT} is outside allowed release ports {80, 443, 8080, 8443}`);
}

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', Boolean(process.env.TRUST_PROXY));
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        fontSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        // Only emit upgrade-insecure-requests when the operator has
        // actually committed to HTTPS. Sending it on plain-HTTP
        // deployments causes browsers to silently upgrade follow-up
        // same-origin navigations (window.location.href = '/x') to
        // https://, which then fail because the server isn't on 443
        // — making login appear broken even though the POST succeeded.
        // helmet ships upgradeInsecureRequests in its DEFAULT directive
        // set, so omitting the key leaves it on. Use `null` to actively
        // suppress it on HTTP deployments.
        upgradeInsecureRequests: process.env.REQUIRE_HTTPS === '1' ? [] : null
      }
    },
    crossOriginEmbedderPolicy: false,
    hsts: { maxAge: 31_536_000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
  })
);
app.use(compression());
app.use(cors({ origin: false }));
app.use(cookieParser());
app.use(express.json({ limit: '5mb' }));
app.use(rateLimit({ windowMs: 60_000, max: 240, standardHeaders: true, legacyHeaders: false }));

// Request id + JSON access log + Prom histogram + OTel span
app.use((req, res, next) => {
  const rid = newRequestId();
  (req as Request & { rid?: string }).rid = rid;
  const span = startSpan('http.request', { 'http.method': req.method, 'http.route': req.path });
  const start = Date.now();
  res.on('finish', () => {
    const ms = (Date.now() - start) / 1000;
    httpRequests.inc({ method: req.method, route: req.path.split('/').slice(0, 3).join('/'), status: String(res.statusCode) });
    httpDuration.observe(ms, { method: req.method });
    logger.info('http', { rid, method: req.method, path: req.path, status: res.statusCode, ms: Math.round(ms * 1000) });
    void endSpan(span, { 'http.status_code': res.statusCode });
  });
  next();
});

app.use(requireHttps);
app.use(withSession);
app.use(perUserLimiter);
app.use(csrfMiddleware);

// /livez: process is up. /healthz preserved as alias.
// /readyz: ready to accept traffic — 503 during startup or drain.
let isReady = false;
let isDraining = false;
app.get('/healthz', (_req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));
app.get('/livez', (_req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));
app.get('/readyz', (_req, res) => {
  if (isDraining) { res.status(503).json({ status: 'draining' }); return; }
  if (!isReady) { res.status(503).json({ status: 'starting' }); return; }
  res.json({ status: 'ready' });
});
app.get('/metrics', (_req, res) => { res.setHeader('Content-Type', 'text/plain; version=0.0.4'); res.send(renderMetrics()); });

app.use('/api/csrf', csrfRouter);
app.use('/api/auth', authRouter);
app.use('/api/auth', userAuthRouter);
app.use('/api/auth', sudoRouter);
app.use('/api/assessments', assessmentsRouter);
app.use('/api/generate', generateRouter);
app.use('/api/export', exportRouter);
app.use('/api/approval', approvalRouter);
app.use('/api/audit', auditRouter);
app.use('/api/iac', iacRouter);
app.use('/api/sbom', sbomRouter);
app.use('/api/cloud', cloudRouter);
app.use('/api/comments', commentRouter);
app.use('/api/templates', templatesRouter);
app.use('/api/webhooks', webhookRouter);
app.use('/api/risks', riskRouter);
app.use('/api/chat', chatRouter);
app.use('/api/jobs', jobsRouter);
app.use('/api/asvs-self', asvsRouter);
app.use('/api/sbom-self', selfSbomRouter);
app.use('/api/users', passwordResetRouter);
app.use('/api/auth/users', passwordResetRouter);
app.use('/api/dsar', dsarRouter);
app.use('/api', openapiRouter);
app.use('/api/fedramp', fedrampRouter);
app.use('/api/logging', loggingRouter);
app.use('/scim', scimRouter);

app.use(deviceDetect);
app.use(requirePageAuth);
app.use(express.static(path.join(__dirname, '..', 'public')));

// Global error handler. `express.json()` throws SyntaxError on
// malformed bodies and decorates the error with `body` / `status`
// fields — these are client errors (HTTP 4xx), not server faults, so
// surface them as 400 rather than letting them masquerade as 500s and
// pollute SLO dashboards / pager noise. The `status` field on
// body-parser errors covers `entity.too.large` (413) etc. as well.
app.use((err: Error & { status?: number; statusCode?: number; type?: string; body?: unknown }, _req: Request, res: Response, _next: NextFunction) => {
  const message = err instanceof Error ? err.message : 'Internal error';
  const explicitStatus = err.status ?? err.statusCode;
  const isBodyParserClientError = err instanceof SyntaxError && 'body' in err;
  const status = isBodyParserClientError ? 400
    : (typeof explicitStatus === 'number' && explicitStatus >= 400 && explicitStatus < 500) ? explicitStatus
    : 500;
  if (status >= 500) logger.error('unhandled', { message });
  else logger.warn('client_error', { message, status });
  res.status(status).json({ error: message });
});

// Job-queue handlers — wired here so the server is the only worker.
register('webhook.deliver', async (job) => {
  const { fanOut } = await import('./engine/webhooks');
  const { event, data } = job.payload as { event: 'package.generated'; data: Record<string, unknown> };
  await fanOut(event, data);
  return { ok: true };
});

(async () => {
  tryEnableFips();
  await runMigrations();
  startWorker();
  // TLS termination on the single published port. Cert/key are
  // generated by deploy/docker-entrypoint.sh on first boot if absent;
  // operators drop their own cert.pem + key.pem into /app/.data to
  // override. Plain HTTP listeners are intentionally absent — the
  // explicit operator policy is "do not allow http anymore."
  const certDir = process.env.CERT_DIR ?? '/app/.data';
  const certPath = path.join(certDir, 'cert.pem');
  const keyPath = path.join(certDir, 'key.pem');
  const tlsOptions = {
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath)
  };
  const server = https.createServer(tlsOptions, app).listen(PORT, () => {
    logger.info('listening', { port: PORT, tls: true });
    isReady = true;
    // eslint-disable-next-line no-console
    console.log(`NIST Express listening on https://0.0.0.0:${PORT}`);
  });
  // Graceful shutdown — SIGTERM (k8s, ECS) and SIGINT (Ctrl-C) start
  // draining: readiness flips to draining (503 on /readyz so the LB
  // sheds traffic), then we close the server with a 10s timeout for
  // in-flight requests, then exit.
  function shutdown(signal: string): void {
    if (isDraining) return;
    isDraining = true;
    isReady = false;
    logger.info('shutdown.start', { signal });
    const killer = setTimeout(() => {
      logger.warn('shutdown.timeout', { signal });
      process.exit(1);
    }, 10_000).unref();
    server.close(err => {
      clearTimeout(killer);
      if (err) { logger.error('shutdown.close.fail', { err: err.message }); process.exit(1); return; }
      logger.info('shutdown.done', { signal });
      process.exit(0);
    });
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  // Log unhandled async failures with context, then begin draining.
  // We intentionally do NOT swallow — the process still exits via
  // shutdown() so a supervisor can restart us in a known-good state.
  process.on('unhandledRejection', (reason) => {
    logger.error('unhandledRejection', { reason: reason instanceof Error ? reason.message : String(reason) });
    shutdown('unhandledRejection');
  });
  process.on('uncaughtException', (err) => {
    logger.error('uncaughtException', { err: err.message, stack: err.stack });
    shutdown('uncaughtException');
  });
})().catch(err => { logger.error('startup', { err: (err as Error).message }); process.exit(1); });
// keep tree-shaking happy
void packagesGenerated;
