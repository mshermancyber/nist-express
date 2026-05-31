// Minimal Prometheus-style metrics in pure Node. Exposes counters,
// gauges, and histograms. No external dependency — sufficient for
// a single-node ARB platform; replace with prom-client if you need
// labels with high cardinality.

type LabelValues = Record<string, string>;
function key(name: string, labels?: LabelValues): string {
  if (!labels) return name;
  const ks = Object.keys(labels).sort();
  return name + (ks.length ? '{' + ks.map(k => `${k}="${String(labels[k]).replace(/"/g, '\\"')}"`).join(',') + '}' : '');
}

const counters = new Map<string, { name: string; help: string; labels?: LabelValues; value: number }>();
const gauges = new Map<string, { name: string; help: string; labels?: LabelValues; value: number }>();
const histograms = new Map<string, { name: string; help: string; labels?: LabelValues; buckets: number[]; counts: number[]; sum: number; count: number }>();

const DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

export function counter(name: string, help: string) {
  return {
    inc(labels?: LabelValues, by = 1) {
      const k = key(name, labels);
      const cur = counters.get(k) ?? { name, help, labels, value: 0 };
      cur.value += by;
      counters.set(k, cur);
    }
  };
}
export function gauge(name: string, help: string) {
  return {
    set(value: number, labels?: LabelValues) {
      counters; // keep
      const k = key(name, labels);
      gauges.set(k, { name, help, labels, value });
    }
  };
}
export function histogram(name: string, help: string, buckets: number[] = DEFAULT_BUCKETS) {
  return {
    observe(value: number, labels?: LabelValues) {
      const k = key(name, labels);
      let h = histograms.get(k);
      if (!h) { h = { name, help, labels, buckets, counts: new Array(buckets.length).fill(0), sum: 0, count: 0 }; histograms.set(k, h); }
      for (let i = 0; i < buckets.length; i++) if (value <= buckets[i]!) h.counts[i]! += 1;
      h.sum += value;
      h.count += 1;
    }
  };
}

export function render(): string {
  const lines: string[] = [];
  const seenHelp = new Set<string>();
  for (const m of counters.values()) {
    if (!seenHelp.has(m.name)) { lines.push(`# HELP ${m.name} ${m.help}`); lines.push(`# TYPE ${m.name} counter`); seenHelp.add(m.name); }
    lines.push(`${key(m.name, m.labels)} ${m.value}`);
  }
  for (const m of gauges.values()) {
    if (!seenHelp.has(m.name)) { lines.push(`# HELP ${m.name} ${m.help}`); lines.push(`# TYPE ${m.name} gauge`); seenHelp.add(m.name); }
    lines.push(`${key(m.name, m.labels)} ${m.value}`);
  }
  for (const h of histograms.values()) {
    if (!seenHelp.has(h.name)) { lines.push(`# HELP ${h.name} ${h.help}`); lines.push(`# TYPE ${h.name} histogram`); seenHelp.add(h.name); }
    for (let i = 0; i < h.buckets.length; i++) {
      lines.push(`${key(h.name + '_bucket', { ...(h.labels || {}), le: String(h.buckets[i]) })} ${h.counts[i]}`);
    }
    lines.push(`${key(h.name + '_bucket', { ...(h.labels || {}), le: '+Inf' })} ${h.count}`);
    lines.push(`${key(h.name + '_sum', h.labels)} ${h.sum}`);
    lines.push(`${key(h.name + '_count', h.labels)} ${h.count}`);
  }
  return lines.join('\n') + '\n';
}

// ---- Built-in instrumentation ----
export const httpRequests = counter('arb_http_requests_total', 'HTTP requests by route and status');
export const httpDuration = histogram('arb_http_request_duration_seconds', 'HTTP request duration');
export const packagesGenerated = counter('arb_packages_generated_total', 'Packages generated');
export const aiCalls = counter('arb_ai_calls_total', 'AI augmentation calls (by outcome)');
export const jobsRun = counter('arb_jobs_run_total', 'Background jobs run');
