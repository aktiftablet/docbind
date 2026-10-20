import { type Express } from 'express';
import { type DataRepository } from './db/repository.js';
import { type StorageAdapter } from './storage/storage.js';
import { type CacheAdapter } from './cache/redis.js';
export interface AppConfig {
    repository?: DataRepository;
    storage?: StorageAdapter;
    cache?: CacheAdapter;
    allowDefaultOrgFallback?: boolean;
}
export declare function createApp(config?: AppConfig): {
    app: Express;
    repository: DataRepository;
    storage: StorageAdapter;
    cache: CacheAdapter;
};
//# sourceMappingURL=app.d.ts.map