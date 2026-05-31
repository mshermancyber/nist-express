import { safeFetch } from '../src/engine/safeFetch';

describe('safeFetch SSRF guard', () => {
  test('blocks loopback', async () => {
    await expect(safeFetch('http://127.0.0.1:1/path', { timeoutMs: 500 })).rejects.toThrow(/private|metadata|loopback/);
  });
  test('blocks AWS metadata', async () => {
    await expect(safeFetch('http://169.254.169.254/latest/meta-data', { timeoutMs: 500 })).rejects.toThrow(/private|metadata|loopback/);
  });
  test('blocks RFC1918 directly', async () => {
    await expect(safeFetch('http://10.1.2.3/', { timeoutMs: 500 })).rejects.toThrow();
  });
  test('rejects file:// and gopher://', async () => {
    await expect(safeFetch('file:///etc/passwd', { timeoutMs: 500 })).rejects.toThrow(/scheme/);
    await expect(safeFetch('gopher://localhost/', { timeoutMs: 500 })).rejects.toThrow(/scheme/);
  });
});
