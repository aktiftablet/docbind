import { createApp } from './app.js';
import { S3Client } from '@aws-sdk/client-s3';
import { PrismaRepository, type PrismaClientLike } from './db/repository.js';
import { S3EncryptedStorage } from './storage/storage.js';

export * from './app.js';
export * from './crypto/envelope.js';
export * from './db/repository.js';
export * from './storage/storage.js';

export async function startServer() {
  const production = process.env.NODE_ENV === 'production';
  const databaseUrl = process.env.DATABASE_URL;
  const bucket = process.env.S3_BUCKET_NAME;
  const tokenSecret = process.env.TOKEN_SIGNING_SECRET;
  if (production && (!databaseUrl || !bucket || !tokenSecret)) {
    throw new Error('Production requires DATABASE_URL, S3_BUCKET_NAME and TOKEN_SIGNING_SECRET');
  }
  // The deployment generates Prisma's client before startup. Keep development builds
  // independent of downloaded native engines when DATABASE_URL is not configured.
  type RuntimePrisma = PrismaClientLike & { $connect(): Promise<void>; $disconnect(): Promise<void> };
  let prisma: RuntimePrisma | undefined;
  if (databaseUrl) {
    const generated = await import('@prisma/client') as unknown as { PrismaClient: new () => RuntimePrisma };
    prisma = new generated.PrismaClient();
  }
  if (prisma) await prisma.$connect();
  const s3 = bucket ? new S3Client({ region: process.env.AWS_REGION ?? 'us-east-1', endpoint: process.env.S3_ENDPOINT, forcePathStyle: Boolean(process.env.S3_ENDPOINT) }) : undefined;
  const { app } = createApp({
    repository: prisma ? new PrismaRepository(prisma) : undefined,
    storage: s3 && bucket ? new S3EncryptedStorage(s3, bucket) : undefined,
    tokenSecret,
    provisioningKey: process.env.PROVISIONING_API_KEY,
  });
  const server = app.listen(Number(process.env.PORT ?? 4000), () => {
    console.log('[DocBind API] Listening');
    if (!prisma || !s3) console.warn('[DocBind API] Development memory adapters enabled; data may be lost on restart.');
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 15_000;
  const shutdown = () => {
    server.close(() => { void prisma?.$disconnect(); s3?.destroy(); });
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
  return server;
}

if (process.argv[1]?.endsWith('src/index.ts') || process.argv[1]?.endsWith('dist/index.js')) {
  void startServer().catch(err => { console.error(err.message); process.exitCode = 1; });
}
