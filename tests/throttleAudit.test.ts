import { isLocked, recordFailure, recordSuccess } from '../src/auth/loginThrottle';
import { appendAudit, verifyChain } from '../src/store/auditStore';
import fs from 'fs';
import path from 'path';

describe('login throttle', () => {
  test('locks after threshold failures', () => {
    const u = 'throttle-' + Math.random();
    expect(isLocked(u, 'ip').locked).toBe(false);
    for (let i = 0; i < 5; i++) recordFailure(u, 'ip');
    expect(isLocked(u, 'ip').locked).toBe(true);
  });
  test('success clears the counter', () => {
    const u = 'throttle-' + Math.random();
    recordFailure(u, 'ip');
    recordSuccess(u, 'ip');
    expect(isLocked(u, 'ip').locked).toBe(false);
  });
});

describe('audit chain integrity', () => {
  const auditFile = path.join(__dirname, '..', '.data', 'audit.jsonl');
  beforeAll(() => {
    // Start from a clean chain — earlier dev runs may have written legacy entries.
    if (fs.existsSync(auditFile)) fs.unlinkSync(auditFile);
    const headFile = path.join(__dirname, '..', '.data', 'audit-head');
    if (fs.existsSync(headFile)) fs.unlinkSync(headFile);
  });
  test('verifies a clean chain', () => {
    appendAudit({ actor: 'test', action: 'test.event', target: 't1' });
    appendAudit({ actor: 'test', action: 'test.event', target: 't2' });
    const r = verifyChain();
    expect(r.ok).toBe(true);
  });
  test('detects tampering', () => {
    if (!fs.existsSync(auditFile)) return;
    const original = fs.readFileSync(auditFile, 'utf-8');
    const lines = original.split('\n').filter(Boolean);
    if (!lines.length) return;
    // Tamper one byte in the middle (without breaking JSON shape)
    const tampered = lines.map((l, i) => i === Math.floor(lines.length / 2) ? l.replace(/"action":"[^"]+"/, '"action":"hacked"') : l).join('\n') + '\n';
    fs.writeFileSync(auditFile, tampered);
    const r = verifyChain();
    expect(r.ok).toBe(false);
    // Restore
    fs.writeFileSync(auditFile, original);
  });
});
