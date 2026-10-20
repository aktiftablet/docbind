export interface CacheAdapter {
    get<T = unknown>(key: string): Promise<T | null>;
    set(key: string, value: unknown, ttlSeconds?: number): Promise<void>;
    del(key: string): Promise<void>;
}
/**
 * Redis-compatible caching layer for active device status lookups and ephemeral metadata.
 * Uses an in-memory TTL store by default and supports a Redis client when configured.
 */
export declare class InMemoryCacheAdapter implements CacheAdapter {
    private readonly store;
    get<T = unknown>(key: string): Promise<T | null>;
    set(key: string, value: unknown, ttlSeconds?: number): Promise<void>;
    del(key: string): Promise<void>;
}
//# sourceMappingURL=redis.d.ts.map