// safeFetch — fetch wrapper that
//   (a) enforces a timeout via AbortController, and
//   (b) blocks SSRF to private / link-local / metadata IPs unless the
//       target is explicitly allow-listed via env.
//
// DNS rebind protection: we resolve the hostname once, then enforce
// the IP family of the request to the resolved address (preventing
// last-millisecond DNS rebinding to a private IP). The first match
// wins; if you need a stricter resolver, replace with pinned addrs.

import { lookup } from 'dns/promises';
import net from 'net';

const PRIVATE_CIDRS = [
  // RFC 1918
  '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
  // "This host on this network" — Linux connect(0.0.0.0) lands on loopback.
  '0.0.0.0/8',
  // Loopback
  '127.0.0.0/8', '::1/128',
  // Link-local
  '169.254.0.0/16', 'fe80::/10',
  // Cloud metadata
  '169.254.169.254/32',
  // CGNAT (RFC 6598)
  '100.64.0.0/10'
];

// IPv4-mapped IPv6 (::ffff:a.b.c.d) collapses to the embedded IPv4
// address at the kernel layer — `connect("::ffff:127.0.0.1")` opens
// a loopback socket. Normalise to the IPv4 form so the CIDR check
// above sees the actual destination.
function normalizeIp(ip: string): string {
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (m) return m[1]!;
  // Some resolvers / stacks emit ::ffff:7f00:1-style (hex) forms.
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ip);
  if (hex) {
    const hi = parseInt(hex[1]!, 16);
    const lo = parseInt(hex[2]!, 16);
    return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
  }
  return ip;
}

function ipToBigInt(ip: string): bigint {
  if (net.isIPv4(ip)) {
    return ip.split('.').reduce((acc, p) => (acc << 8n) | BigInt(Number(p)), 0n);
  }
  // Minimal IPv6 → 128-bit BigInt
  const parts = ip.split('::');
  const head = parts[0]!.split(':').filter(Boolean);
  const tail = parts[1] ? parts[1].split(':').filter(Boolean) : [];
  const need = 8 - head.length - tail.length;
  const full = [...head, ...new Array(Math.max(0, need)).fill('0'), ...tail].slice(0, 8);
  let n = 0n;
  for (const h of full) n = (n << 16n) | BigInt(parseInt(h || '0', 16));
  return n;
}
function cidrMatch(ip: string, cidr: string): boolean {
  const [base, mask] = cidr.split('/');
  const m = Number(mask);
  const ipFam = net.isIP(ip);
  const baseFam = net.isIP(base!);
  if (ipFam !== baseFam) return false;
  const bits = ipFam === 4 ? 32 : 128;
  const shift = BigInt(bits - m);
  const ipN = ipToBigInt(ip);
  const baseN = ipToBigInt(base!);
  return (ipN >> shift) === (baseN >> shift);
}

function isBlocked(ip: string): boolean {
  const norm = normalizeIp(ip);
  return PRIVATE_CIDRS.some(c => cidrMatch(norm, c));
}

function allowlist(): string[] {
  return (process.env.OUTBOUND_ALLOW_HOSTS ?? '').split(',').map(s => s.trim()).filter(Boolean);
}

export interface SafeFetchOptions extends RequestInit {
  timeoutMs?: number;
  /** Allow the request even if the resolved IP is private. Only used by tests / explicit local integrations. */
  allowPrivate?: boolean;
}

const MAX_REDIRECTS = 5;

async function validateHost(hostname: string, allowPrivate: boolean): Promise<void> {
  const allow = allowlist();
  if (allow.includes(hostname)) return;
  if (allowPrivate) return;
  let resolved: string;
  if (net.isIP(hostname)) {
    resolved = hostname;
  } else {
    try { resolved = (await lookup(hostname)).address; } catch { throw new Error('safeFetch: DNS resolution failed'); }
  }
  if (isBlocked(resolved)) {
    throw new Error(`safeFetch: refused — ${resolved} is on a private / metadata / loopback range`);
  }
}

export async function safeFetch(input: string, opts: SafeFetchOptions = {}): Promise<Response> {
  let currentUrl = input;
  // Manual redirect handling: every hop is re-validated against the
  // blocklist. Node fetch follows redirects transparently by default,
  // which lets an attacker's external host 302 us to http://127.0.0.1/.
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const url = new URL(currentUrl);
    if (!['http:', 'https:'].includes(url.protocol)) {
      throw new Error(`safeFetch: unsupported scheme ${url.protocol}`);
    }
    await validateHost(url.hostname, !!opts.allowPrivate);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 10_000);
    let res: Response;
    try {
      res = await fetch(currentUrl, { ...opts, signal: controller.signal, redirect: 'manual' });
    } finally {
      clearTimeout(timer);
    }
    // 3xx with Location → re-resolve and loop. Anything else returns.
    if (res.status >= 300 && res.status < 400 && res.headers.has('location')) {
      if (hop === MAX_REDIRECTS) {
        throw new Error('safeFetch: too many redirects');
      }
      currentUrl = new URL(res.headers.get('location')!, currentUrl).toString();
      continue;
    }
    return res;
  }
  throw new Error('safeFetch: redirect loop guard exhausted');
}
