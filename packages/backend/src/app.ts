import { getMaxUploadBytes } from './utils/mime.js';
import express, { type Express, type Request, type Response } from 'express';
import cors from 'cors';
import { InMemoryRepository, type DataRepository } from './db/repository.js';
import { InMemoryEncryptedStorage, type StorageAdapter } from './storage/storage.js';
import { InMemoryCacheAdapter, type CacheAdapter } from './cache/redis.js';
import { createAuthMiddleware } from './middleware/auth.js';
import { createDeviceRouter } from './routes/devices.js';
import { createDocumentRouter } from './routes/documents.js';

export interface AppConfig {
  repository?: DataRepository;
  storage?: StorageAdapter;
  cache?: CacheAdapter;
  allowDefaultOrgFallback?: boolean;
}

export function createApp(config: AppConfig = {}): {
  app: Express;
  repository: DataRepository;
  storage: StorageAdapter;
  cache: CacheAdapter;
} {
  const repository = config.repository ?? new InMemoryRepository(true);
  const storage = config.storage ?? new InMemoryEncryptedStorage();
  const cache = config.cache ?? new InMemoryCacheAdapter();
  const allowDefaultOrgFallback = config.allowDefaultOrgFallback ?? true;

  const app = express();

  app.disable('x-powered-by');
  app.use(cors());
  app.use(express.json({ limit: Math.ceil((getMaxUploadBytes() * 4) / 3) + 1024 * 1024 }));
  app.use(express.urlencoded({ extended: true }));

  app.get('/health', (_req: Request, res: Response) => {
    res.status(200).json({
      status: 'ok',
      service: 'docbind-api',
      version: '1.0.0',
      crypto: {
        envelope: 'AES-256-GCM + RSA-OAEP-256',
        zero_disk_writes: true,
      },
    });
  });

  // Organization onboarding endpoint (for B2B tenant creation)
  app.post('/v1/organizations', async (req: Request, res: Response) => {
    const name = req.body?.name;
    if (!name || typeof name !== 'string') {
      res.status(400).json({ success: false, error: 'Organization name is required' });
      return;
    }
    const org = await repository.createOrganization(name.trim());
    res.status(201).json({
      success: true,
      organization: {
        id: org.id,
        name: org.name,
        api_key: org.api_key,
        createdAt: org.createdAt,
      },
    });
  });

  const authMiddleware = createAuthMiddleware(repository, allowDefaultOrgFallback);

  app.use('/v1/devices', authMiddleware, createDeviceRouter(repository, cache));
  app.use('/v1/documents', authMiddleware, createDocumentRouter(repository, storage));

  return { app, repository, storage, cache };
}
