// Throttle adapter — abstracts the counter store so login-throttle and
// per-user-limit work across multiple nodes when configured.
//
//   - MemAdapter  : default, in-process maps (single-node)
//   - RedisAdapter: opt-in via REDIS_URL, uses lazy-loaded ioredis if
//                   available; otherwise the platform logs and falls
//                   back to memory.

export interface ThrottleAdapter {
  kind(): 'mem' | 'redis';
  /** Read+increment in a single op, returning current count for window. */
  hit(key: string, windowMs: number): Promise<number>;
  /** Set a sticky cooldown deadline. */
  setCooldown(key: string, untilEpochMs: number): Promise<void>;
  getCooldown(key: string): Promise<number | null>;
  /** Reset both the counter and cooldown for a key. */
  reset(key: string): Promise<void>;
}

class MemAdapter implements ThrottleAdapter {
  private hits = new Map<string, number[]>();
  private cooldowns = new Map<string, number>();
  kind(): 'mem' { return 'mem'; }
  async hit(key: string, windowMs: number): Promise<number> {
    const now = Date.now();
    const arr = (this.hits.get(key) ?? []).filter(t => t > now - windowMs);
    arr.push(now);
    this.hits.set(key, arr);
    return arr.length;
  }
  async setCooldown(key: string, until: number): Promise<void> { this.cooldowns.set(key, until); }
  async getCooldown(key: string): Promise<number | null> {
    const v = this.cooldowns.get(key);
    if (!v) return null;
    if (v <= Date.now()) { this.cooldowns.delete(key); return null; }
    return v;
  }
  async reset(key: string): Promise<void> { this.hits.delete(key); this.cooldowns.delete(key); }
}

let active: ThrottleAdapter | null = null;

export async function getThrottleAdapter(): Promise<ThrottleAdapter> {
  if (active) return active;
  if (process.env.REDIS_URL) {
    try {
      // Optional dep: ioredis is not bundled with the platform. If
      // operators want distributed throttling they install it. We
      // import via a string variable so tsc doesn't try to resolve
      // the module at type-check time.
      const moduleName = 'ioredis';
      const mod = await (Function('m', 'return import(m)') as (m: string) => Promise<unknown>)(moduleName).catch(() => null);
      if (mod) {
        const RedisCtor = (mod as { Redis: new (url: string) => unknown }).Redis;
        active = await buildRedisAdapter(new RedisCtor(process.env.REDIS_URL!) as never);
        return active!;
      }
    } catch { /* fall through */ }
  }
  active = new MemAdapter();
  return active;
}

interface RedisLike {
  zadd: (key: string, score: number, value: string) => Promise<unknown>;
  zremrangebyscore: (key: string, min: number, max: number) => Promise<unknown>;
  zcard: (key: string) => Promise<number>;
  pexpire: (key: string, ms: number) => Promise<unknown>;
  set: (key: string, value: string, ...args: unknown[]) => Promise<unknown>;
  get: (key: string) => Promise<string | null>;
  del: (...keys: string[]) => Promise<unknown>;
}

async function buildRedisAdapter(client: RedisLike): Promise<ThrottleAdapter> {
  return {
    kind: () => 'redis',
    async hit(key, windowMs) {
      const now = Date.now();
      const ns = `arb:throttle:${key}`;
      await client.zremrangebyscore(ns, 0, now - windowMs);
      await client.zadd(ns, now, `${now}:${Math.random()}`);
      await client.pexpire(ns, windowMs);
      return await client.zcard(ns);
    },
    async setCooldown(key, until) { await client.set(`arb:cooldown:${key}`, String(until), 'PX', Math.max(0, until - Date.now())); },
    async getCooldown(key) {
      const v = await client.get(`arb:cooldown:${key}`);
      if (!v) return null;
      const n = Number(v);
      return n > Date.now() ? n : null;
    },
    async reset(key) { await client.del(`arb:throttle:${key}`, `arb:cooldown:${key}`); }
  };
}
