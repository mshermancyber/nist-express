// SCIM 2.0 (RFC 7643/7644) provisioning. Implements the User and
// Group resource endpoints sufficient for Okta / Entra ID upstream
// provisioning. Authentication is via Bearer token configured in
// SCIM_TOKEN env var (separate from the user API keys so provisioning
// auth can be rotated independently).
//
// Mapping:
//   SCIM Group displayName  →  internal role list
//   SCIM User externalId    →  internal username
//   SCIM User active=false  →  disabled (M62)

import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { randomUUID as uuid } from 'crypto';
import { rawUsers, getUserById, getUserByUsername, saveUser, deleteUser } from '../store/userStore';
import { appendAudit } from '../store/auditStore';
import { User, UserRole } from '../types/assessment';

export const scimRouter = Router();

const SCIM_TOKEN = process.env.SCIM_TOKEN ?? '';

function bearerToken(req: Request): string | null {
  const a = (req.headers.authorization || '').trim();
  if (!a.toLowerCase().startsWith('bearer ')) return null;
  return a.slice(7).trim();
}

function scimAuth(req: Request, res: Response, next: NextFunction): void {
  if (!SCIM_TOKEN) { res.status(503).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], detail: 'SCIM_TOKEN not configured', status: '503' }); return; }
  const t = bearerToken(req);
  if (!t || t.length !== SCIM_TOKEN.length || !crypto.timingSafeEqual(Buffer.from(t), Buffer.from(SCIM_TOKEN))) {
    res.status(401).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], detail: 'unauthorized', status: '401' });
    return;
  }
  next();
}

// SCIM responses must always advertise the schema list.
function userToScim(u: User): Record<string, unknown> {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id: u.id,
    userName: u.username,
    externalId: u.username,
    displayName: u.displayName,
    name: { formatted: u.displayName },
    emails: [{ primary: true, value: `${u.username}@invalid.example`, type: 'work' }],
    active: !(u as User & { disabled?: boolean }).disabled,
    roles: u.roles.map(r => ({ value: r, primary: false })),
    meta: { resourceType: 'User', created: u.createdAt, lastModified: u.createdAt, location: `/scim/v2/Users/${u.id}` }
  };
}

// ---- Service config ----
scimRouter.get('/v2/ServiceProviderConfig', (_req, res) => {
  res.json({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 200 },
    changePassword: { supported: true },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [{ type: 'oauthbearertoken', name: 'OAuth Bearer Token', description: 'Bearer SCIM_TOKEN' }]
  });
});

scimRouter.get('/v2/Schemas', (_req, res) => {
  res.json({ totalResults: 2, Resources: [
    { id: 'urn:ietf:params:scim:schemas:core:2.0:User' },
    { id: 'urn:ietf:params:scim:schemas:core:2.0:Group' }
  ] });
});

scimRouter.get('/v2/ResourceTypes', (_req, res) => {
  res.json({ totalResults: 2, Resources: [
    { id: 'User', name: 'User', endpoint: '/Users', schema: 'urn:ietf:params:scim:schemas:core:2.0:User' },
    { id: 'Group', name: 'Group', endpoint: '/Groups', schema: 'urn:ietf:params:scim:schemas:core:2.0:Group' }
  ] });
});

// ---- Users ----
scimRouter.get('/v2/Users', scimAuth, (req, res) => {
  // Minimal eq-filter: userName eq "x". Cap filter length and validate
  // the captured value against the username charset so the comparison
  // can't be coerced by NUL / CR-LF / control bytes.
  const filter = String(req.query.filter ?? '').slice(0, 200);
  let users = rawUsers();
  // Filter charset must match the create-side validation (line 134
  // `SCIM_USERNAME_RE`) — otherwise SCIM clients can search for
  // usernames the API would refuse to create, leaking provisioning
  // intent and creating asymmetric provider behavior.
  const m = /userName\s+eq\s+"([^"]{1,80})"/.exec(filter);
  if (m && SCIM_USERNAME_RE.test(m[1]!)) {
    users = users.filter(u => u.username === m[1]);
  } else if (m) {
    // Filter present but malformed: return empty rather than the full list.
    users = [];
  }
  // Validate pagination inputs per RFC 7644 §3.4.2.4. startIndex is
  // 1-based with a minimum of 1; count is non-negative and capped to
  // a sane upper bound to prevent slice abuse / DoS.
  const rawStart = Number(req.query.startIndex);
  const rawCount = Number(req.query.count);
  const startIndex = Number.isFinite(rawStart) && rawStart >= 1 ? Math.floor(rawStart) : 1;
  const SCIM_MAX_COUNT = 200;
  const count = Number.isFinite(rawCount) && rawCount >= 0 ? Math.min(Math.floor(rawCount), SCIM_MAX_COUNT) : 100;
  const slice = users.slice(startIndex - 1, startIndex - 1 + count);
  res.json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: users.length,
    startIndex, itemsPerPage: slice.length,
    Resources: slice.map(userToScim)
  });
});

scimRouter.get('/v2/Users/:id', scimAuth, (req, res) => {
  const u = getUserById(req.params.id);
  if (!u) { res.status(404).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], detail: 'not found', status: '404' }); return; }
  res.json(userToScim(u));
});

function mapRoles(input: unknown): UserRole[] {
  if (!Array.isArray(input)) return ['analyst'];
  const out: UserRole[] = [];
  for (const r of input) {
    const v = typeof r === 'string' ? r : (r as { value?: string }).value;
    const allowed: UserRole[] = ['admin', 'architect', 'analyst', 'product-owner', 'approver-security', 'approver-risk', 'approver-architecture', 'approver-compliance'];
    if (v && allowed.includes(v as UserRole)) out.push(v as UserRole);
  }
  return out.length ? out : ['analyst'];
}

// Same constraints applied at local-auth user creation; SCIM must
// not be a back door for arbitrary usernames.
const SCIM_USERNAME_RE = /^[A-Za-z0-9._-]+$/;
function badRequest(res: Response, detail: string): void {
  res.status(400).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], scimType: 'invalidValue', detail, status: '400' });
}

scimRouter.post('/v2/Users', scimAuth, async (req, res) => {
  const body = req.body as Record<string, unknown>;
  const username = String(body.userName ?? body.externalId ?? '');
  if (!username) { badRequest(res, 'userName required'); return; }
  if (username.length > 80 || !SCIM_USERNAME_RE.test(username)) {
    badRequest(res, 'userName must be 1-80 chars of [A-Za-z0-9._-]'); return;
  }
  if (getUserByUsername(username)) { res.status(409).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], detail: 'exists', status: '409' }); return; }
  const rawDisplay = body.displayName ?? (body.name as Record<string, unknown>)?.formatted ?? username;
  const displayName = String(rawDisplay).slice(0, 200);
  if (!displayName || displayName.length < 1) { badRequest(res, 'displayName required'); return; }
  const u: User = {
    id: uuid(),
    username,
    displayName,
    passwordHash: await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 4),  // random — user must reset via /api/auth
    roles: mapRoles(body.roles),
    createdAt: new Date().toISOString()
  };
  if (body.active === false) (u as User & { disabled?: boolean }).disabled = true;
  saveUser(u);
  appendAudit({ actor: 'scim', action: 'scim.user.create', target: u.id, details: { username: u.username, roles: u.roles } });
  res.status(201).json(userToScim(u));
});

scimRouter.put('/v2/Users/:id', scimAuth, (req, res) => {
  const existing = getUserById(req.params.id);
  if (!existing) { res.status(404).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], detail: 'not found', status: '404' }); return; }
  const body = req.body as Record<string, unknown>;
  const nextDisplay = String(body.displayName ?? existing.displayName).slice(0, 200);
  if (!nextDisplay) { badRequest(res, 'displayName required'); return; }
  const updated: User = {
    ...existing,
    displayName: nextDisplay,
    roles: mapRoles(body.roles ?? existing.roles)
  };
  if (typeof body.active === 'boolean') (updated as User & { disabled?: boolean }).disabled = !body.active;
  saveUser(updated);
  appendAudit({ actor: 'scim', action: 'scim.user.update', target: updated.id });
  res.json(userToScim(updated));
});

scimRouter.patch('/v2/Users/:id', scimAuth, (req, res) => {
  const existing = getUserById(req.params.id);
  if (!existing) { res.status(404).json({ detail: 'not found' }); return; }
  const ops = (req.body as { Operations?: { op?: string; path?: string; value?: unknown }[] }).Operations ?? [];
  const SUPPORTED_PATHS = new Set(['active', 'displayName', 'roles']);
  const SUPPORTED_OPS = new Set(['replace', 'add']);
  // Validate every operation BEFORE mutating — refuse the whole patch
  // if any op is unsupported. Otherwise a malformed batch could
  // silently apply only some changes and leave the user surprised.
  for (const op of ops) {
    const verb = (op.op ?? '').toLowerCase();
    if (!op.path || !SUPPORTED_PATHS.has(op.path)) {
      res.status(400).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], scimType: 'invalidPath', detail: `unsupported path: ${op.path ?? '(none)'}`, status: '400' });
      return;
    }
    if (!SUPPORTED_OPS.has(verb)) {
      res.status(400).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], scimType: 'invalidSyntax', detail: `unsupported op: ${op.op ?? '(none)'}`, status: '400' });
      return;
    }
  }
  const u = { ...existing } as User & { disabled?: boolean };
  for (const op of ops) {
    if (op.path === 'active') u.disabled = op.value === false;
    else if (op.path === 'displayName') u.displayName = String(op.value);
    else if (op.path === 'roles') u.roles = mapRoles(op.value);
  }
  saveUser(u);
  appendAudit({ actor: 'scim', action: 'scim.user.patch', target: u.id });
  res.json(userToScim(u));
});

scimRouter.delete('/v2/Users/:id', scimAuth, (req, res) => {
  const ok = deleteUser(req.params.id);
  appendAudit({ actor: 'scim', action: 'scim.user.delete', target: req.params.id });
  res.status(ok ? 204 : 404).end();
});

// ---- Groups (read-only — roles are managed inside the user resource) ----
scimRouter.get('/v2/Groups', scimAuth, (_req, res) => {
  const groups: UserRole[] = ['admin', 'architect', 'analyst', 'product-owner', 'approver-security', 'approver-risk', 'approver-architecture', 'approver-compliance'];
  res.json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: groups.length,
    Resources: groups.map(g => ({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
      id: g, displayName: g,
      members: rawUsers().filter(u => u.roles.includes(g)).map(u => ({ value: u.id, display: u.username }))
    }))
  });
});
