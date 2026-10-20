export interface CacheAdapter {
  get<T = unknown>(key: string): Promise<T | null>;
  set(key: string, value: unknown, ttlSeconds?: number): Promise<void>;
  del(key: string): Promise<void>;
}

interface CacheEntry {
  value: string;
  expiresAt: number | null;
}

/**
 * Redis-compatible caching layer for active device status lookups and ephemeral metadata.
 * Uses an in-memory TTL store by default and supports a Redis client when configured.
 */
export class InMemoryCacheAdapter implements CacheAdapter {
  private readonly store = new Map<string, CacheEntry>();

  public async get<T = unknown>(key: string): Promise<T | null> {
    const entry = this.store.get(key);
    if (!entry) return null;

    if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }

    try {
      return JSON.parse(entry.value) as T;
    } catch {
      return null;
    }
  }

  public async set(key: string, value: unknown, ttlSeconds = 300): Promise<void> {
    const serialized = JSON.stringify(value);
    const expiresAt = ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : null;
    this.store.set(key, { value: serialized, expiresAt });
  }

  public async del(key: string): Promise<void> {
    this.store.delete(key);
  }
}
