// User and session storage. Single-file JSON persistence; replace with
// Postgres/SCIM in a real deployment. Sessions are signed cookies — no
// server-side session store needed.

import fs from 'fs';
import path from 'path';
import { User } from '../types/assessment';

const DATA_DIR = path.join(__dirname, '..', '..', '.data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

let cache: User[] | null = null;

function loadFromDisk(): User[] {
  if (cache) return cache;
  if (!fs.existsSync(USERS_FILE)) { cache = []; return cache; }
  try {
    cache = JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8')) as User[];
  } catch {
    cache = [];
  }
  return cache;
}

function persist(): void {
  if (!cache) return;
  fs.writeFileSync(USERS_FILE, JSON.stringify(cache, null, 2));
}

// listUsers / getUserById / getUserByUsername hide soft-deleted users
// by default so they never resolve at the auth layer. Hard delete and
// the admin "deleted users" view use `rawUsers()` which includes them.
export function listUsers(): User[] {
  return loadFromDisk().filter(u => !u.deletedAt).map(u => ({ ...u, passwordHash: '<redacted>' }));
}

export function listAllUsersIncludingDeleted(): User[] {
  return loadFromDisk().map(u => ({ ...u, passwordHash: '<redacted>' }));
}

export function rawUsers(): User[] {
  return loadFromDisk();
}

// Filter on deletedAt INSIDE the predicate. `.find()` returns the
// first match; if a soft-deleted row precedes a recreated active row
// with the same username/id, filtering after the find would return
// undefined and the active row would be invisible to auth.
export function getUserById(id: string): User | undefined {
  return loadFromDisk().find(x => x.id === id && !x.deletedAt);
}

export function getUserByUsername(username: string): User | undefined {
  const lc = username.toLowerCase();
  return loadFromDisk().find(x => x.username.toLowerCase() === lc && !x.deletedAt);
}

// Lookup that DOES include soft-deleted users. Used by hard-delete
// flows so a soft-deleted row can still be erased.
export function getUserByIdIncludingDeleted(id: string): User | undefined {
  return loadFromDisk().find(x => x.id === id);
}

export function saveUser(u: User): User {
  const all = loadFromDisk();
  const idx = all.findIndex(x => x.id === u.id);
  if (idx >= 0) all[idx] = u; else all.push(u);
  persist();
  return u;
}

// Soft delete: mark deletedAt so the row is preserved for audit but
// hidden from the active-user surface. Auth lookups (getUserById /
// getUserByUsername) honour this and refuse to resolve the user.
export function softDeleteUser(id: string): boolean {
  const all = loadFromDisk();
  const u = all.find(x => x.id === id);
  if (!u || u.deletedAt) return false;
  u.deletedAt = new Date().toISOString();
  u.disabled = true;  // belt+suspenders — disabled is the canonical "no auth" flag
  persist();
  return true;
}

// Hard delete is irreversible and reserved for super-admin workflows
// (data-subject erasure, GDPR, etc). Routes calling this must require
// sudo and an explicit `?hard=1` confirmation.
export function hardDeleteUser(id: string): boolean {
  const all = loadFromDisk();
  const idx = all.findIndex(u => u.id === id);
  if (idx < 0) return false;
  all.splice(idx, 1);
  persist();
  return true;
}

// Legacy export, retained as a soft-delete alias so existing callers
// upgrade gracefully. New callers should use softDeleteUser explicitly.
export const deleteUser = softDeleteUser;

export function isOpenMode(): boolean {
  // When no users are provisioned the platform runs in open mode
  // (everyone is anonymous Admin). The login UI shows a banner.
  return loadFromDisk().length === 0;
}
