import crypto from 'node:crypto';
import request from 'supertest';
import { describe, it, expect, beforeAll } from 'vitest';
import { createApp } from '../src/app.js';
import { EnvelopeCryptoService } from '../src/crypto/envelope.js';
import { resolveMimeType } from '../src/utils/mime.js';

function generateTestRsaKeyPair(modulusLength = 2048): {
  publicKeyPem: string;
  privateKeyPem: string;
} {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}

describe('DocBind Backend - Cryptographic Architecture & REST API', () => {
  let deviceKeyPair: { publicKeyPem: string; privateKeyPem: string };
  let secondDeviceKeyPair: { publicKeyPem: string; privateKeyPem: string };

  beforeAll(() => {
    deviceKeyPair = generateTestRsaKeyPair(2048);
    secondDeviceKeyPair = generateTestRsaKeyPair(2048);
  });

  describe('EnvelopeCryptoService (AES-256-GCM + RSA-OAEP-256)', () => {
    it('seals and unseals a PDF buffer in memory with AAD hardware device binding', () => {
      const samplePdf = Buffer.from(
        '%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nstream\nBT (Top Secret M&A Contract) Tj ET\nendstream\n%%EOF',
        'utf-8'
      );
      const targetDeviceId = 'device-uuid-1234';

      const sealed = EnvelopeCryptoService.sealDocument(
        samplePdf,
        deviceKeyPair.publicKeyPem,
        targetDeviceId
      );

      expect(sealed.encryptedDek).toBeTruthy();
      expect(sealed.iv).toBeTruthy();
      expect(sealed.authTag).toBeTruthy();
      expect(sealed.encryptedDocument.equals(samplePdf)).toBe(false);

      const unsealed = EnvelopeCryptoService.unsealDocument(
        sealed.encryptedDocument,
        sealed.encryptedDek,
        sealed.iv,
        deviceKeyPair.privateKeyPem,
        targetDeviceId
      );

      expect(unsealed.equals(samplePdf)).toBe(true);
    });

    it('fails decryption if targetDeviceId AAD is mismatched or another device private key is used', () => {
      const samplePdf = Buffer.from('%PDF-1.7 Confidential Payload', 'utf-8');
      const sealed = EnvelopeCryptoService.sealDocument(
        samplePdf,
        deviceKeyPair.publicKeyPem,
        'authorized-device-id'
      );

      // Wrong targetDeviceId (AAD mismatch)
      expect(() =>
        EnvelopeCryptoService.unsealDocument(
          sealed.encryptedDocument,
          sealed.encryptedDek,
          sealed.iv,
          deviceKeyPair.privateKeyPem,
          'spoofed-device-id'
        )
      ).toThrow();

      // Wrong device private key
      expect(() =>
        EnvelopeCryptoService.unsealDocument(
          sealed.encryptedDocument,
          sealed.encryptedDek,
          sealed.iv,
          secondDeviceKeyPair.privateKeyPem,
          'authorized-device-id'
        )
      ).toThrow();
    });

    it('rejects weak RSA keys (< 2048 bits) or malformed PEM strings', () => {
      const weakKeys = generateTestRsaKeyPair(1024);
      expect(() => EnvelopeCryptoService.validateRsaPublicKey(weakKeys.publicKeyPem)).toThrow(
        /below minimum 2048 bits/
      );
      expect(() => EnvelopeCryptoService.validateRsaPublicKey('not-a-pem-key')).toThrow(
        /Invalid device public key/
      );
    });
  });

  describe('REST Endpoints (/v1/devices/register, /v1/documents/seal, /v1/documents/:id/payload)', () => {
    it('executes full device registration, multipart PDF sealing, and authorized payload retrieval', async () => {
      const { app } = createApp();
      const rawFingerprint = 'ios|iPhone16,2|arm64|unique-hw-id-998877';

      // 1. Register Device
      const regRes = await request(app)
        .post('/v1/devices/register')
        .send({
          device_id: rawFingerprint,
          public_key: deviceKeyPair.publicKeyPem,
          metadata: { os: 'iOS 18.0', model: 'iPhone 16 Pro' },
        })
        .expect(201);

      expect(regRes.body.success).toBe(true);
      expect(regRes.body.registered_device_id).toBeTypeOf('string');
      expect(regRes.body.hardware_hash).toMatch(/^[a-f0-9]{64}$/);

      const registeredDeviceId = regRes.body.registered_device_id as string;
      const hardwareHash = regRes.body.hardware_hash as string;

      // 2. Seal Document via multipart/form-data
      const plaintextPdf = Buffer.from(
        '%PDF-1.7\nBT (Board Resolution - Strictly Confidential) Tj ET\n%%EOF',
        'utf-8'
      );

      const sealRes = await request(app)
        .post('/v1/documents/seal')
        .field('target_device_id', registeredDeviceId)
        .attach('file', plaintextPdf, 'board-resolution.pdf')
        .expect(201);

      expect(sealRes.body.success).toBe(true);
      expect(sealRes.body.document_id).toBeTypeOf('string');
      expect(sealRes.body.target_device_id).toBe(registeredDeviceId);
      expect(sealRes.body.encrypted_dek).toBeTypeOf('string');
      expect(sealRes.body.encrypted_document).toBeTypeOf('string');

      const documentId = sealRes.body.document_id as string;

      // 3. Fetch Encrypted Payload for Authorized Device
      const payloadRes = await request(app)
        .get(`/v1/documents/${documentId}/payload`)
        .set('x-device-id', registeredDeviceId)
        .set('x-hardware-hash', hardwareHash)
        .expect(200);

      expect(payloadRes.body.success).toBe(true);
      expect(payloadRes.body.document_id).toBe(documentId);
      expect(payloadRes.body.encrypted_dek).toBe(sealRes.body.encrypted_dek);

      // Verify target device can decrypt the fetched payload in RAM
      const decryptedBuffer = EnvelopeCryptoService.unsealDocument(
        Buffer.from(payloadRes.body.encrypted_document, 'base64'),
        payloadRes.body.encrypted_dek,
        payloadRes.body.iv,
        deviceKeyPair.privateKeyPem,
        registeredDeviceId
      );
      expect(decryptedBuffer.toString('utf-8')).toBe(plaintextPdf.toString('utf-8'));

      // 4. Reject Unauthorized Hardware Fingerprint on Payload Fetch
      await request(app)
        .get(`/v1/documents/${documentId}/payload`)
        .set('x-hardware-hash', '0000000000000000000000000000000000000000000000000000000000000000')
        .expect(403);

      // 5. Revoke Device & Verify Payload Access is Blocked
      await request(app)
        .post(`/v1/devices/${registeredDeviceId}/revoke`)
        .expect(200);

      await request(app)
        .get(`/v1/documents/${documentId}/payload`)
        .expect(403);
    });

    it('seals non-PDF files (image, video) and resolves MIME types from content', async () => {
      const { app } = createApp();
      const regRes = await request(app)
        .post('/v1/devices/register')
        .send({ device_id: 'android|pixel|multi-format', public_key: deviceKeyPair.publicKeyPem })
        .expect(201);
      const deviceId = regRes.body.registered_device_id as string;
      const hardwareHash = regRes.body.hardware_hash as string;

      const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4]);
      const mp4 = Buffer.concat([
        Buffer.from([0, 0, 0, 0x18]),
        Buffer.from('ftypisom', 'latin1'),
        Buffer.alloc(32, 7),
      ]);

      // Multipart image upload
      const imgSeal = await request(app)
        .post('/v1/documents/seal')
        .field('target_device_id', deviceId)
        .attach('file', png, 'photo.png')
        .expect(201);

      // Base64 JSON video upload without declared MIME -> sniffed from magic bytes
      const vidSeal = await request(app)
        .post('/v1/documents/seal')
        .send({ target_device_id: deviceId, file_base64: mp4.toString('base64'), filename: 'clip.mp4' })
        .expect(201);

      for (const [seal, original, mime] of [
        [imgSeal, png, 'image/png'],
        [vidSeal, mp4, 'video/mp4'],
      ] as const) {
        const payload = await request(app)
          .get(`/v1/documents/${seal.body.document_id}/payload`)
          .set('x-device-id', deviceId)
          .set('x-hardware-hash', hardwareHash)
          .expect(200);
        expect(payload.body.mime_type).toBe(mime);
        const decrypted = EnvelopeCryptoService.unsealDocument(
          Buffer.from(payload.body.encrypted_document, 'base64'),
          payload.body.encrypted_dek,
          payload.body.iv,
          deviceKeyPair.privateKeyPem,
          deviceId
        );
        expect(decrypted.equals(original)).toBe(true);
      }
    });

    it('rejects files exceeding the per-category size limit with 413', async () => {
      const { app } = createApp();
      const regRes = await request(app)
        .post('/v1/devices/register')
        .send({ device_id: 'android|pixel|limit-test', public_key: deviceKeyPair.publicKeyPem })
        .expect(201);
      const deviceId = regRes.body.registered_device_id as string;

      const prevVideo = process.env.MAX_VIDEO_MB;
      const prevUpload = process.env.MAX_UPLOAD_MB;
      process.env.MAX_VIDEO_MB = String(100 / (1024 * 1024)); // 100 bytes
      process.env.MAX_UPLOAD_MB = String(1000 / (1024 * 1024)); // 1000 bytes
      try {
        const mp4 = Buffer.concat([Buffer.from([0, 0, 0, 0x18]), Buffer.from('ftypisom', 'latin1'), Buffer.alloc(200)]);
        const res = await request(app)
          .post('/v1/documents/seal')
          .field('target_device_id', deviceId)
          .attach('file', mp4, 'big.mp4')
          .expect(413);
        expect(res.body.mime_type).toBe('video/mp4');
        expect(res.body.max_bytes).toBe(100);

        // Same-size non-media file fits under MAX_UPLOAD_MB
        await request(app)
          .post('/v1/documents/seal')
          .field('target_device_id', deviceId)
          .attach('file', Buffer.alloc(200, 0x41), 'notes.txt')
          .expect(201);
      } finally {
        if (prevVideo === undefined) delete process.env.MAX_VIDEO_MB;
        else process.env.MAX_VIDEO_MB = prevVideo;
        if (prevUpload === undefined) delete process.env.MAX_UPLOAD_MB;
        else process.env.MAX_UPLOAD_MB = prevUpload;
      }
    });
  });

  describe('MIME resolution', () => {
    it('prefers magic bytes, then declared type, then extension', () => {
      expect(resolveMimeType(Buffer.from('%PDF-1.7'), 'image/png')).toBe('application/pdf');
      expect(resolveMimeType(Buffer.from([0xff, 0xd8, 0xff, 0xe0]))).toBe('image/jpeg');
      expect(resolveMimeType(Buffer.from('PK\u0003\u0004'), undefined, 'report.docx')).toBe(
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      );
      expect(resolveMimeType(Buffer.from('hello'), 'application/octet-stream', 'notes.txt')).toBe('text/plain');
      expect(resolveMimeType(Buffer.from('???'))).toBe('application/octet-stream');
    });
  });
});
