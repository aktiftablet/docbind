import { createApp } from './app.js';
import { InMemoryRepository } from './db/repository.js';

export * from './app.js';
export * from './crypto/envelope.js';
export * from './db/repository.js';
export * from './storage/storage.js';
export * from './cache/redis.js';

const isDirectRun =
  process.argv[1]?.endsWith('src/index.ts') ||
  process.argv[1]?.endsWith('dist/index.js');

if (isDirectRun) {
  const port = Number(process.env.PORT || 4000);
  const { app } = createApp();

  app.listen(port, () => {
    console.log(`[DocBind API] Listening on http://localhost:${port}`);
    console.log(`[DocBind API] Default Dev API Key: ${InMemoryRepository.DEFAULT_API_KEY}`);
  });
}
