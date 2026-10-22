import crypto from 'node:crypto';
import { asyncHandler } from './middleware/async.js';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import { InMemoryRepository, type DataRepository } from './db/repository.js';
import { InMemoryEncryptedStorage, type StorageAdapter } from './storage/storage.js';
import { createAuthMiddleware, secretsEqual, TokenService } from './middleware/auth.js';
import { createDeviceRouter } from './routes/devices.js';
import { createDocumentRouter } from './routes/documents.js';
import { getHardUploadCapBytes } from './utils/mime.js';

export interface AppConfig {
  repository?: DataRepository;
  storage?: StorageAdapter;
  tokenSecret?: string;
  provisioningKey?: string;
  rateLimit?: number;
  maxConcurrentUploads?: number;
}

export function createApp(config: AppConfig = {}): { app: Express; repository: DataRepository; storage: StorageAdapter; tokens: TokenService } {
  const production = process.env.NODE_ENV === 'production';
  if (production && (!config.repository || !config.storage || !config.tokenSecret)) {
    throw new Error('Production requires persistent repository, storage and TOKEN_SIGNING_SECRET');
  }
  const repository = config.repository ?? new InMemoryRepository();
  const storage = config.storage ?? new InMemoryEncryptedStorage();
  const tokens = new TokenService(config.tokenSecret ?? crypto.randomBytes(48).toString('hex'));
  const app = express();
  app.disable('x-powered-by');
  app.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
  // Do not trust arbitrary forwarding headers. Configure the ingress to preserve client IPs.
  app.use(cors({ origin: process.env.CORS_ORIGINS?.split(',').map(s => s.trim()) ?? false }));
  app.use(rateLimit({ windowMs: 60_000, limit: config.rateLimit ?? 120, standardHeaders: 'draft-7', legacyHeaders: false }));
  app.get('/health', (_req: Request, res: Response) => { res.json({ status: 'ok', service: 'docbind-api' }); });

  app.post('/v1/organizations', (req: Request, res: Response, next: NextFunction) => {
    const supplied = req.get('x-provisioning-key');
    if (!config.provisioningKey || !supplied || !secretsEqual(supplied, config.provisioningKey)) {
      res.status(401).json({ error: 'Provisioning credentials required' }); return;
    }
    next();
  }, express.json({ limit: '16kb', inflate: false }), asyncHandler(async (req: Request, res: Response) => {
    const name = req.body?.name;
    if (typeof name !== 'string' || !name.trim() || name.length > 200) { res.status(400).json({ error: 'Organization name required (1–200 characters)' }); return; }
    const org = await repository.createOrganization(name.trim());
    res.status(201).json({ success: true, organization: org });
  }));

  app.use('/v1', createAuthMiddleware(repository, tokens));
  app.use('/v1/devices', express.json({ limit: '32kb', inflate: false }), createDeviceRouter(repository, tokens));

  // Bound simultaneous buffering of large authenticated uploads, including slow clients.
  let uploads = 0;
  app.use('/v1/documents/seal', (req: Request, res: Response, next: NextFunction) => {
    if (req.principal?.role !== 'admin') { res.status(403).json({ error: 'Insufficient permissions' }); return; }
    if (uploads >= (config.maxConcurrentUploads ?? 2)) { res.status(503).json({ error: 'Upload capacity reached' }); return; }
    uploads++;
    let released = false;
    const release = () => { if (!released) { uploads--; released = true; } };
    res.once('finish', release); res.once('close', release);
    next();
  }, express.json({ limit: Math.ceil(getHardUploadCapBytes() * 4 / 3) + 16384, inflate: false }));
  app.use('/v1/documents', createDocumentRouter(repository, storage));
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const type = (err as { type?: string })?.type;
    const status = type === 'entity.too.large' ? 413 : type === 'entity.parse.failed' ? 400 : type === 'encoding.unsupported' ? 415 : 500;
    res.status(status).json({ success: false, error: status === 413 ? 'Request body too large' : status === 400 ? 'Invalid JSON' : status === 415 ? 'Compressed request bodies are not supported' : 'Internal server error' });
  });
  return { app, repository, storage, tokens };
}
