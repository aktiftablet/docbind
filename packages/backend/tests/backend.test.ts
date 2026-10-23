import crypto from 'node:crypto';
import request from './request.js';
import { describe, it, expect, vi } from 'vitest';
import { createApp } from '../src/app.js';
import { EnvelopeCryptoService as Crypto } from '../src/crypto/envelope.js';
import { InMemoryRepository, PrismaRepository } from '../src/db/repository.js';
import { TokenService } from '../src/middleware/auth.js';
import { S3EncryptedStorage } from '../src/storage/storage.js';
import { resolveMimeType } from '../src/utils/mime.js';

function keypair(bits = 2048) {
  return crypto.generateKeyPairSync('rsa', { modulusLength: bits, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
}
const keys = keypair(), attacker = keypair();
async function fixture(options: Parameters<typeof createApp>[0] = {}) {
  const context = createApp({ tokenSecret: 't'.repeat(48), provisioningKey: 'provision-secret', ...options });
  const org = await context.repository.createOrganization('Test organization');
  const register = (publicKey = keys.publicKey, hash = 'same-hardware', algorithm = 'RSA-OAEP-256') => request(context.app)
    .post('/v1/devices/register').set('x-api-key', org.api_key)
    .send({ public_key: publicKey, hardware_hash: hash, key_algorithm: algorithm });
  const seal = (id: string, content = Buffer.from('%PDF-1.7 confidential')) => request(context.app)
    .post('/v1/documents/seal').set('x-api-key', org.api_key)
    .field('target_device_id', id).attach('file', content, 'private.pdf');
  return { ...context, org, register, seal };
}

describe('Authentication and scoped credentials', () => {
  it('rejects missing, invalid, old development and malformed bearer credentials before parsing JSON', async () => {
    const { app } = createApp();
    for (const headers of [{}, { 'x-api-key': 'docbind_dev_api_key_2026' }, { authorization: 'Bearer nonsense' }]) {
      await request(app).post('/v1/devices/register').set(headers).set('Content-Type', 'application/json').send('{invalid').expect(401);
    }
    await request(app).post('/v1/organizations').send({ name: 'Anonymous' }).expect(401);
  });
  it('requires a separate provisioning key and validates tenant names', async () => {
    const { app } = await fixture();
    await request(app).post('/v1/organizations').set('x-provisioning-key', 'wrong').send({ name: 'x' }).expect(401);
    await request(app).post('/v1/organizations').set('x-provisioning-key', 'provision-secret').send({ name: ' ' }).expect(400);
    const res = await request(app).post('/v1/organizations').set('x-provisioning-key', 'provision-secret').send({ name: 'New tenant' }).expect(201);
    expect(res.body.organization.api_key).toMatch(/^db_live_/);
  });
  it('binds enrollment to the approved public key and prevents client administrative operations', async () => {
    const { app, org, register } = await fixture();
    const approval = await request(app).post('/v1/devices/enrollment-tokens').set('x-api-key', org.api_key).send({ public_key: keys.publicKey }).expect(201);
    const enroll = (pub: string) => request(app).post('/v1/devices/register').auth(approval.body.enrollment_token, { type: 'bearer' }).send({ public_key: pub });
    await enroll(attacker.publicKey).expect(403);
    const reg = await enroll(keys.publicKey).expect(201);
    const other = await register(attacker.publicKey);
    const client = () => request(app).post(`/v1/devices/${other.body.registered_device_id}/revoke`).auth(reg.body.device_token, { type: 'bearer' });
    await client().expect(403);
    await request(app).post('/v1/documents/seal').auth(reg.body.device_token, { type: 'bearer' }).send({}).expect(403);
    await request(app).post('/v1/devices/enrollment-tokens').auth(reg.body.device_token, { type: 'bearer' }).send({ public_key: attacker.publicKey }).expect(403);
    await request(app).get(`/v1/devices/${other.body.registered_device_id}`).auth(reg.body.device_token, { type: 'bearer' }).expect(404);
    await request(app).post('/v1/devices/register').auth(reg.body.device_token, { type: 'bearer' }).send({ public_key: attacker.publicKey }).expect(403);
  });
  it('rejects expired and modified tokens', () => {
    const signer = new TokenService('s'.repeat(48));
    expect(signer.verify(signer.issue('device', 'org', 'device', -1))).toBeNull();
    const valid = signer.issue('device', 'org', 'device');
    expect(signer.verify(valid + 'x')).toBeNull();
    expect(signer.verify(valid)?.subject).toBe('device');
    expect(new TokenService('b'.repeat(48)).verify(valid)).toBeNull();
  });
  it('limits anonymous requests and authenticated metadata bodies', async () => {
    const limited = createApp({ rateLimit: 2 });
    await request(limited.app).get('/health').expect(200);
    await request(limited.app).get('/health').expect(200);
    await request(limited.app).get('/health').expect(429);
    const { app, org } = await fixture();
    await request(app).post('/v1/devices/register').set('x-api-key', org.api_key).send({ metadata: 'x'.repeat(33000) }).expect(413);
  });
});

describe('Immutable device identity and document binding', () => {
  it('does not reactivate revoked keys or let a copied hardware hash replace their ID/key', async () => {
    const { app, org, register, seal, repository } = await fixture();
    const first = await register();
    const id = first.body.registered_device_id;
    const old = await seal(id);
    await request(app).post(`/v1/devices/${id}/revoke`).set('x-api-key', org.api_key).expect(200);
    await register().expect(403);
    const second = await register(attacker.publicKey).expect(201);
    expect(second.body.registered_device_id).not.toBe(id);
    expect((await repository.findDeviceById(id))?.public_key).toBe(keys.publicKey.trim());
    expect((await repository.findDeviceById(id))?.status).toBe('REVOKED');
    await seal(id).expect(403);
    await request(app).get(`/v1/documents/${old.body.document_id}/payload`).auth(first.body.device_token, { type: 'bearer' }).expect(401);
    await request(app).get(`/v1/documents/${old.body.document_id}/payload`).auth(second.body.device_token, { type: 'bearer' }).expect(403);
    expect(() => Crypto.unsealDocument(Buffer.from(old.body.encrypted_document, 'base64'), old.body.encrypted_dek, old.body.iv, attacker.privateKey,
      { targetDeviceId: id, documentId: old.body.document_id, mimeType: 'application/pdf' })).toThrow();
  });
  it('preserves identity when display/timezone/hash changes and never exposes the hash', async () => {
    const { app, org, register } = await fixture();
    const first = await register();
    const again = await register(keys.publicKey, 'changed-monitor-and-timezone').expect(200);
    expect(again.body.registered_device_id).toBe(first.body.registered_device_id);
    const metadata = await request(app).get(`/v1/devices/${again.body.registered_device_id}`).set('x-api-key', org.api_key).expect(200);
    expect(metadata.body.device.hardware_hash).toBeUndefined();
    expect(again.body.hardware_hash).toBeUndefined();
  });
  it('delivers a v2 envelope only to its device, independently of spoofed headers', async () => {
    const { app, org, register, seal } = await fixture();
    const reg = await register(), other = await register(attacker.publicKey);
    const id = reg.body.registered_device_id;
    const sealed = await seal(id).expect(201);
    const path = `/v1/documents/${sealed.body.document_id}/payload`;
    await request(app).get(path).expect(401);
    await request(app).get(path).set('x-api-key', org.api_key).expect(403);
    await request(app).get(path).auth(other.body.device_token, { type: 'bearer' }).set('x-device-id', id).expect(403);
    const payload = await request(app).get(path).auth(reg.body.device_token, { type: 'bearer' }).expect(200);
    const binding = { targetDeviceId: id, documentId: sealed.body.document_id, mimeType: 'application/pdf' };
    expect(payload.body.aad_version).toBe('v2');
    expect(Crypto.unsealDocument(Buffer.from(payload.body.encrypted_document, 'base64'), payload.body.encrypted_dek, payload.body.iv, keys.privateKey, binding).toString()).toBe('%PDF-1.7 confidential');
    expect(() => Crypto.unsealDocument(Buffer.from(payload.body.encrypted_document, 'base64'), payload.body.encrypted_dek, payload.body.iv, keys.privateKey, { ...binding, documentId: 'swapped' })).toThrow();
  });
  it('isolates organizations even with valid device credentials', async () => {
    const f = await fixture();
    const foreign = await f.repository.createOrganization('Foreign');
    const reg = await f.register();
    const sealed = await f.seal(reg.body.registered_device_id);
    const other = await request(f.app).post('/v1/devices/register').set('x-api-key', foreign.api_key).send({ public_key: attacker.publicKey }).expect(201);
    await request(f.app).get(`/v1/documents/${sealed.body.document_id}/payload`).auth(other.body.device_token, { type: 'bearer' }).expect(404);
    await request(f.app).post(`/v1/devices/${reg.body.registered_device_id}/revoke`).set('x-api-key', foreign.api_key).expect(404);
  });
  it('rejects weak or invalid keys and changes to an enrolled algorithm', async () => {
    const { register } = await fixture();
    await register('invalid').expect(400);
    await register(keypair(1024).publicKey).expect(400);
    await register().expect(201);
    await register(keys.publicKey, 'same-hardware', 'RSA-OAEP-256-MGF1-SHA1').expect(409);
  });
});

describe('Encryption and resource controls', () => {
  it.each(['RSA-OAEP-256', 'RSA-OAEP-256-MGF1-SHA1'] as const)('round trips %s, rejects wrong keys and authenticates metadata', algorithm => {
    const binding = { targetDeviceId: 'device', documentId: 'document', mimeType: 'text/plain' };
    const sealed = Crypto.sealDocument(Buffer.from('secret'), keys.publicKey, binding, algorithm);
    expect(Crypto.unsealDocument(sealed.encryptedDocument, sealed.encryptedDek, sealed.iv, keys.privateKey, binding, algorithm).toString()).toBe('secret');
    expect(() => Crypto.unsealDocument(sealed.encryptedDocument, sealed.encryptedDek, sealed.iv, attacker.privateKey, binding, algorithm)).toThrow();
    expect(() => Crypto.unsealDocument(sealed.encryptedDocument, sealed.encryptedDek, sealed.iv, keys.privateKey, { ...binding, mimeType: 'image/png' }, algorithm)).toThrow();
  });
  it('applies category limits and rejects oversized multipart fields', async () => {
    const f = await fixture(); const reg = await f.register();
    vi.stubEnv('MAX_VIDEO_MB', String(100 / 1024 / 1024));
    try {
      const mp4 = Buffer.concat([Buffer.from([0, 0, 0, 24]), Buffer.from('ftypisom'), Buffer.alloc(200)]);
      await request(f.app).post('/v1/documents/seal').set('x-api-key', f.org.api_key).field('target_device_id', reg.body.registered_device_id).attach('file', mp4, 'video.mp4').expect(413);
      await request(f.app).post('/v1/documents/seal').set('x-api-key', f.org.api_key).field('target_device_id', 'x'.repeat(9000)).expect(413);
    } finally { vi.unstubAllEnvs(); }
  });
  it('limits concurrent uploads before large body parsing', async () => {
    const f = await fixture({ maxConcurrentUploads: 0 });
    await request(f.app).post('/v1/documents/seal').set('x-api-key', f.org.api_key).send({}).expect(503);
  });
  it('rejects malformed multipart without crashing the server', async () => {
    const f = await fixture();
    await request(f.app).post('/v1/documents/seal').set('x-api-key', f.org.api_key).set('Content-Type', 'multipart/form-data; boundary=broken').send('--broken\r\ninvalid').expect(400);
    await request(f.app).get('/health').expect(200);
  });
  it('recognizes supported file signatures', () => {
    expect(resolveMimeType(Buffer.from('%PDF-1.7'), 'image/png')).toBe('application/pdf');
    expect(resolveMimeType(Buffer.from([0xff, 0xd8, 0xff]))).toBe('image/jpeg');
    expect(resolveMimeType(Buffer.from('text'), undefined, 'file.txt')).toBe('text/plain');
  });
});

describe('Persistent adapters', () => {
  it('recovers a concurrent registration winner without overwriting its state', async () => {
    const winner = { id: 'existing', status: 'REVOKED' };
    const findUnique = vi.fn().mockResolvedValueOnce(null).mockResolvedValueOnce(winner);
    const prisma = { device: { findUnique, create: vi.fn().mockRejectedValue({ code: 'P2002' }) } };
    const repo = new PrismaRepository(prisma as any);
    const result = await repo.registerDevice({ orgId: 'org', hardwareHash: 'hash', publicKey: keys.publicKey, publicKeyFingerprint: 'fingerprint', keyAlgorithm: 'RSA-OAEP-256' });
    expect(result).toEqual({ device: winner, created: false });
  });
  it('writes, reads and deletes S3 ciphertext without exposing plaintext or cross-bucket paths', async () => {
    const send = vi.fn().mockResolvedValueOnce({}).mockResolvedValueOnce({ Body: { transformToByteArray: async () => Buffer.from('ciphertext') } }).mockResolvedValueOnce({});
    const storage = new S3EncryptedStorage({ send } as any, 'vault');
    const url = await storage.putEncryptedBlob('doc', 'org', Buffer.from('ciphertext'));
    expect(send.mock.calls[0][0].input).toMatchObject({ Bucket: 'vault', Key: 'org/doc.enc', Body: Buffer.from('ciphertext') });
    expect((await storage.getEncryptedBlob(url)).toString()).toBe('ciphertext');
    await storage.deleteEncryptedBlob(url);
    await expect(storage.getEncryptedBlob('s3://foreign/org/doc.enc')).rejects.toThrow();
  });
  it('fails closed when production persistence/signing configuration is absent', () => {
    vi.stubEnv('NODE_ENV', 'production');
    try { expect(() => createApp()).toThrow(/Production requires/); } finally { vi.unstubAllEnvs(); }
  });
});
