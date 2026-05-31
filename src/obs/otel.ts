// OpenTelemetry hook. We deliberately avoid pulling in the official
// OTel SDK as a hard dep — when OTEL_EXPORTER_OTLP_ENDPOINT is set we
// emit minimal OTLP/HTTP spans over fetch with a synthetic request id.
// For production scale, drop in @opentelemetry/sdk-node.

import { randomBytes } from 'crypto';
import { safeFetch } from '../engine/safeFetch';

const ENDPOINT = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
const SERVICE = process.env.OTEL_SERVICE_NAME ?? 'nist-express';
const ENABLED = !!ENDPOINT;

interface Span {
  traceId: string;
  spanId: string;
  name: string;
  start: number;
  attrs: Record<string, string | number | boolean>;
}

export function newRequestId(): string { return randomBytes(8).toString('hex'); }

export function startSpan(name: string, attrs: Record<string, string | number | boolean> = {}): Span {
  return { traceId: randomBytes(16).toString('hex'), spanId: randomBytes(8).toString('hex'), name, start: Date.now(), attrs };
}

export async function endSpan(span: Span, extraAttrs: Record<string, string | number | boolean> = {}): Promise<void> {
  if (!ENABLED) return;
  const end = Date.now();
  const body = {
    resourceSpans: [{
      resource: { attributes: [{ key: 'service.name', value: { stringValue: SERVICE } }] },
      scopeSpans: [{
        scope: { name: 'nist-express' },
        spans: [{
          traceId: span.traceId,
          spanId: span.spanId,
          name: span.name,
          kind: 1,
          startTimeUnixNano: String(span.start * 1_000_000),
          endTimeUnixNano: String(end * 1_000_000),
          attributes: Object.entries({ ...span.attrs, ...extraAttrs }).map(([k, v]) => ({
            key: k,
            value: typeof v === 'number' ? { intValue: String(v) } : typeof v === 'boolean' ? { boolValue: v } : { stringValue: String(v) }
          }))
        }]
      }]
    }]
  };
  try {
    // allowPrivate: OTLP collector is almost always on a private
    // address (sidecar / DaemonSet / docker network). safeFetch
    // still enforces protocol allowlist + redirect re-validation.
    await safeFetch(`${ENDPOINT!.replace(/\/+$/, '')}/v1/traces`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      allowPrivate: true,
      timeoutMs: 5_000
    });
  } catch { /* never block on telemetry */ }
}

export const otelEnabled = ENABLED;
