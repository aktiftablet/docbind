"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InMemoryCacheAdapter = void 0;
/**
 * Redis-compatible caching layer for active device status lookups and ephemeral metadata.
 * Uses an in-memory TTL store by default and supports a Redis client when configured.
 */
class InMemoryCacheAdapter {
    store = new Map();
    async get(key) {
        const entry = this.store.get(key);
        if (!entry)
            return null;
        if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
            this.store.delete(key);
            return null;
        }
        try {
            return JSON.parse(entry.value);
        }
        catch {
            return null;
        }
    }
    async set(key, value, ttlSeconds = 300) {
        const serialized = JSON.stringify(value);
        const expiresAt = ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : null;
        this.store.set(key, { value: serialized, expiresAt });
    }
    async del(key) {
        this.store.delete(key);
    }
}
exports.InMemoryCacheAdapter = InMemoryCacheAdapter;
//# sourceMappingURL=redis.js.map