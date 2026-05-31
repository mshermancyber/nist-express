import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { appendAudit, verifyChain } from '../src/store/auditStore';
import { rotateSessionSecret } from '../src/auth/auth';

const DATA = path.join(__dirname, '..', '.data');
const AUDIT = path.join(DATA, 'audit.jsonl');
const HEAD = path.join(DATA, 'audit-head');
const SESSION_SECRET = path.join(DATA, 'session-secret');

describe('audit chain — rotation independence', () => {
  beforeAll(() => {
    if (fs.existsSync(AUDIT)) fs.unlinkSync(AUDIT);
    if (fs.existsSync(HEAD)) fs.unlinkSync(HEAD);
  });

  test('verify survives session-secret rotation', () => {
    appendAudit({ actor: 'a', action: 'before.rotate', target: 't1' });
    appendAudit({ actor: 'a', action: 'before.rotate', target: 't2' });
    expect(verifyChain().ok).toBe(true);

    // Rotate the session secret — must NOT invalidate the audit chain
    // because the chain key lives in its own file.
    rotateSessionSecret();

    appendAudit({ actor: 'a', action: 'after.rotate', target: 't3' });
    const r = verifyChain();
    expect(r.ok).toBe(true);
    expect(r.entries).toBe(3);
  });
});
