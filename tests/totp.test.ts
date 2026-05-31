import { generateSecret, totpNow, verifyTotp, base32Encode, base32Decode } from '../src/auth/totp';

describe('TOTP RFC 6238', () => {
  test('round-trips base32', () => {
    const s = Buffer.from('helloworld');
    expect(base32Decode(base32Encode(s)).toString()).toBe('helloworld');
  });
  test('verifies a freshly-generated code', () => {
    const sec = generateSecret();
    const code = totpNow(sec);
    expect(verifyTotp(sec, code)).toBe(true);
  });
  test('rejects an obviously wrong code', () => {
    const sec = generateSecret();
    expect(verifyTotp(sec, '000000')).toBe(false);
  });
});
