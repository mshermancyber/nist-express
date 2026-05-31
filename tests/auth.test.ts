import { signToken, verifyToken } from '../src/auth/auth';
import bcrypt from 'bcryptjs';

describe('auth primitives', () => {
  test('signed tokens round-trip and bind to a user id', () => {
    const t = signToken('user-1');
    const p = verifyToken(t);
    expect(p?.sub).toBe('user-1');
  });
  test('verifyToken rejects tampered tokens', () => {
    const t = signToken('user-1');
    const dot = t.indexOf('.');
    const tampered = 'AAAA' + t.slice(4, dot) + t.slice(dot);
    expect(verifyToken(tampered)).toBeNull();
  });
  test('verifyToken rejects malformed tokens without throwing', () => {
    expect(verifyToken('garbage')).toBeNull();
    expect(verifyToken('abc.def')).toBeNull();
    expect(verifyToken('')).toBeNull();
  });
  test('bcrypt hashes are verifiable', async () => {
    const h = await bcrypt.hash('secret', 4);
    expect(await bcrypt.compare('secret', h)).toBe(true);
    expect(await bcrypt.compare('nope', h)).toBe(false);
  });
});
