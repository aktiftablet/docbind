import crypto from 'node:crypto';
import request from 'supertest';
import { describe, it, expect, beforeAll } from 'vitest';
import { createApp } from '../src/app.js';
import { EnvelopeCryptoService } from '../src/crypto/envelope.js';

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
  });
});
