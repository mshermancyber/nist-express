// Structured logger with 6 levels and per-module scoping.
//
// Levels (lowest → highest verbosity):
//   off    no output — default in production
//   error  operational failures
//   warn   degradation, retries, soft errors
//   info   startup, request summaries, lifecycle
//   debug  per-component decisions, branch outcomes
//   trace  highly verbose — every store call, every AI prompt, full request bodies
//
// Configure with LOG_LEVEL=off|error|warn|info|debug|trace.
// Send a copy to a file with LOG_FILE=/path/to/file (append mode).
//
// Each event is one JSON line. Sensitive field names
// (password, passwordHash, secret, apiKey, token, authorization,
// cookie, totpSecret, kek, …) are redacted recursively.

import fs from 'fs';

export type Level = 'off' | 'error' | 'warn' | 'info' | 'debug' | 'trace';
const LEVELS: Record<Level, number> = { off: 0, error: 10, warn: 20, info: 30, debug: 40, trace: 50 };

function parseLevel(s: string | undefined): Level {
  const v = (s ?? 'off').toLowerCase();
  return (v in LEVELS) ? v as Level : 'off';
}

const MIN_LEVEL: Level = parseLevel(process.env.LOG_LEVEL);
const LOG_FILE = process.env.LOG_FILE;

const SECRET_KEYS = new Set([
  'password', 'passwordhash', 'secret', 'apikey', 'api_key', 'token',
  'authorization', 'cookie', 'totpsecret', 'totp_secret', 'kek',
  'session-secret', 'session_secret', 'key_encryption_key', 'scim_token',
  'jira_token', 'servicenow_password', 'ai_api_key'
]);

function redact(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return value;
  if (depth > 6) return '[depth]';
  if (typeof value === 'string') {
    return value.length > 4096 ? value.slice(0, 4096) + '…[truncated]' : value;
  }
  if (typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.slice(0, 100).map(v => redact(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (SECRET_KEYS.has(k.toLowerCase())) { out[k] = '[redacted]'; continue; }
    out[k] = redact(v, depth + 1);
  }
  return out;
}

function emit(line: string, level: Level): void {
  const target = level === 'error' ? process.stderr : process.stdout;
  target.write(line + '\n');
  if (LOG_FILE) {
    try { fs.appendFileSync(LOG_FILE, line + '\n'); } catch { /* never block on log file */ }
  }
}

function fmt(level: Level, msg: string, module: string | undefined, fields: Record<string, unknown>): string {
  const payload: Record<string, unknown> = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...(module ? { module } : {}),
    ...(redact(fields) as Record<string, unknown>)
  };
  return JSON.stringify(payload);
}

export interface Logger {
  error(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  info(msg: string, fields?: Record<string, unknown>): void;
  debug(msg: string, fields?: Record<string, unknown>): void;
  trace(msg: string, fields?: Record<string, unknown>): void;
  child(extra: Record<string, unknown>): Logger;
  isEnabled(level: Level): boolean;
}

function build(module: string | undefined, bound: Record<string, unknown> = {}): Logger {
  const enabled = (lvl: Level): boolean => LEVELS[lvl] <= LEVELS[MIN_LEVEL];
  function log(level: Level, msg: string, fields?: Record<string, unknown>): void {
    if (!enabled(level)) return;
    emit(fmt(level, msg, module, { ...bound, ...(fields ?? {}) }), level);
  }
  return {
    error: (m, f) => log('error', m, f),
    warn:  (m, f) => log('warn', m, f),
    info:  (m, f) => log('info', m, f),
    debug: (m, f) => log('debug', m, f),
    trace: (m, f) => log('trace', m, f),
    child: (extra) => build(module, { ...bound, ...extra }),
    isEnabled: enabled
  };
}

export const logger: Logger = build(undefined);

export function loggerFor(module: string): Logger {
  return build(module);
}

export function currentLevel(): Level { return MIN_LEVEL; }
export function levelInfo(): { configured: Level; available: Level[] } {
  return { configured: MIN_LEVEL, available: Object.keys(LEVELS) as Level[] };
}
