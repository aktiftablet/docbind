import crypto from 'node:crypto';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, it, expect } from 'vitest';
import {
  DocumentSealer,
  HardwareFingerprint,
  DeviceKeyStore,
  ScreenCaptureGuard,
  createReactNativeScreenGuard,
  createReactNativeKeystore,
} from '../src/index.js';
import { EnvelopeCryptoService } from '../../backend/src/crypto/envelope.js';

describe('@secure-doc/sdk - Client SDK Core Logic & Secure Viewer', () => {
  it('generates a deterministic 64-char SHA-256 hardware fingerprint from React Native device traits', async () => {
    const mockRnDeviceInfo = {
      getUniqueId: async () => 'ios-secure-enclave-uuid-9911',
      getDeviceId: () => 'iPhone16,2',
      getBrand: () => 'Apple',
      getSystemName: () => 'iOS',
      getHardware: async () => 'A17Pro',
      getTotalMemory: async () => 8589934592,
    };

    const first = await HardwareFingerprint.generateHash(mockRnDeviceInfo);
    const second = await HardwareFingerprint.generateHash(mockRnDeviceInfo);

    expect(first.hardwareHash).toMatch(/^[a-f0-9]{64}$/);
    expect(first.hardwareHash).toBe(second.hardwareHash);
    expect(first.metadata).toEqual({
      platform: 'iOS',
      brand: 'Apple',
      deviceId: 'iPhone16,2',
      hardware: 'A17Pro',
      totalMemory: 8589934592,
    });
  });

  it('generates non-extractable RSA-OAEP 2048 keys via WebCrypto and decrypts backend-sealed envelope in RAM', async () => {
    const keyStore = new DeviceKeyStore(undefined, 'test_alias_webcrypto');
    const publicKeyPem = await keyStore.getOrCreatePublicKeyPem();

    expect(publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----');
    expect(publicKeyPem).toContain('-----END PUBLIC KEY-----');

    // Backend seals a PDF document for this device's public key
    const targetDeviceId = 'device-webcrypto-001';
    const originalPdfBytes = Buffer.from(
      '%PDF-1.7\n1 0 obj\nstream\nBT (Zero Disk Write In-Memory PDF Content) Tj ET\nendstream\n%%EOF',
      'utf-8'
    );

    const sealed = EnvelopeCryptoService.sealDocument(
      originalPdfBytes,
      publicKeyPem,
      targetDeviceId
    );

    // Client SDK decrypts the envelope strictly in RAM using WebCrypto unwrapKey + decrypt
    const decryptedBytes = await keyStore.decryptEnvelopeInMemory({
      encryptedDocumentBase64: sealed.encryptedDocument.toString('base64'),
      encryptedDekBase64: sealed.encryptedDek,
      ivBase64: sealed.iv,
      targetDeviceId,
    });

    expect(Buffer.from(decryptedBytes).toString('utf-8')).toBe(
      originalPdfBytes.toString('utf-8')
    );
  });

  it('supports mobile hardware keystore bridge (iOS Keychain / Android Keystore) for in-memory decryption', async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const rnKeystore = createReactNativeKeystore({
      hasKeyPair: async () => true,
      generateRsaKeyPair: async () => ({ publicKeyPem: publicKey }),
      getPublicKeyPem: async () => publicKey,
      rsaOaepDecrypt: async (_alias, encryptedDekBase64) => {
        const decrypted = crypto.privateDecrypt(
          {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
          },
          Buffer.from(encryptedDekBase64, 'base64')
        );
        return decrypted.toString('base64');
      },
    });

    const keyStore = new DeviceKeyStore(rnKeystore, 'rn_hardware_alias');
    const pubPem = await keyStore.getOrCreatePublicKeyPem();
    expect(pubPem).toBe(publicKey);

    const targetDeviceId = 'rn-mobile-device-77';
    const pdfPayload = Buffer.from('%PDF-1.7 Mobile Hardware Keystore Test', 'utf-8');
    const sealed = EnvelopeCryptoService.sealDocument(pdfPayload, pubPem, targetDeviceId);

    const decrypted = await keyStore.decryptEnvelopeInMemory({
      encryptedDocumentBase64: sealed.encryptedDocument.toString('base64'),
      encryptedDekBase64: sealed.encryptedDek,
      ivBase64: sealed.iv,
      targetDeviceId,
    });

    expect(Buffer.from(decrypted).equals(pdfPayload)).toBe(true);
  });

  it('completes end-to-end DocumentSealer.getDeviceToken(), fetchAndDecryptInMemory(), and RAM wipe on dispose()', async () => {
    let registeredDeviceId = 'dev-e2e-999';
    let storedPublicKeyPem = '';

    const plaintextPdf = Buffer.from(
      '%PDF-1.7\nBT (Confidential Acquisition Term Sheet) Tj ET\n%%EOF',
      'utf-8'
    );

    // Mock fetch simulating Backend API (/v1/devices/register and /v1/documents/:id/payload)
    const mockFetch: typeof fetch = async (input, init) => {
      const url = String(input);
      if (url.endsWith('/v1/devices/register')) {
        const body = JSON.parse(String(init?.body));
        storedPublicKeyPem = body.public_key;
        return new Response(
          JSON.stringify({
            success: true,
            registered_device_id: registeredDeviceId,
            hardware_hash: body.hardware_hash,
            status: 'ACTIVE',
            device_token: 'scoped-device-token',
          }),
          { status: 201, headers: { 'Content-Type': 'application/json' } }
        );
      }

      if (url.includes('/v1/documents/doc-123/payload')) {
        const sealed = EnvelopeCryptoService.sealDocument(
          plaintextPdf,
          storedPublicKeyPem,
          registeredDeviceId
        );
        return new Response(
          JSON.stringify({
            success: true,
            document_id: 'doc-123',
            target_device_id: registeredDeviceId,
            mime_type: 'application/pdf',
            encrypted_dek: sealed.encryptedDek,
            iv: sealed.iv,
            auth_tag: sealed.authTag,
            encrypted_document: sealed.encryptedDocument.toString('base64'),
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }

      return new Response('Not Found', { status: 404 });
    };

    DocumentSealer.configure({
      apiUrl: 'https://api.docbind.internal',
      enrollmentToken: 'approved-enrollment-token',
      customFetch: mockFetch,
    });

    // 1. Init & Get Device Token
    const deviceToken = await DocumentSealer.getDeviceToken({ forceRefresh: true });
    expect(deviceToken.deviceId).toBe(registeredDeviceId);
    expect(deviceToken.hardwareHash).toMatch(/^[a-f0-9]{64}$/);
    expect(deviceToken.token).toBeTruthy();

    // 2. Fetch & Decrypt Document in RAM
    const decryptedDoc = await DocumentSealer.fetchAndDecryptInMemory(
      'https://api.docbind.internal/v1/documents/doc-123/payload'
    );

    expect(decryptedDoc.documentId).toBe('doc-123');
    expect(Buffer.from(decryptedDoc.bytes).toString('utf-8')).toBe(
      plaintextPdf.toString('utf-8')
    );

    // 3. Verify dispose() zeroes out the RAM buffer
    decryptedDoc.dispose();
    expect(decryptedDoc.bytes.every((byte) => byte === 0)).toBe(true);
  });

  it('activates Android FLAG_SECURE and iOS UIScreen.capturedDidChangeNotification via ScreenCaptureGuard and renders DocumentSealer.Viewer', async () => {
    let flagSecureActive = false;
    let captureListener: ((captured: boolean) => void) | null = null;

    const rnGuard = createReactNativeScreenGuard({
      enableSecureFlag: () => {
        flagSecureActive = true;
      },
      disableSecureFlag: () => {
        flagSecureActive = false;
      },
      isScreenCaptured: () => false,
      addCaptureListener: (cb) => {
        captureListener = cb;
        return {
          remove: () => {
            captureListener = null;
          },
        };
      },
    });

    const events: Array<{ obscured: boolean; reason?: string }> = [];
    const cleanup = ScreenCaptureGuard.activate(
      {
        onCaptureStateChange: (obscured, reason) => {
          events.push({ obscured, reason });
        },
      },
      rnGuard
    );

    expect(flagSecureActive).toBe(true);
    expect(captureListener).toBeTypeOf('function');

    // Simulate iOS UIScreen.capturedDidChangeNotification firing
    captureListener!(true);
    expect(events).toHaveLength(1);
    expect(events[0].obscured).toBe(true);
    expect(events[0].reason).toContain('capturedDidChangeNotification');

    cleanup();
    expect(flagSecureActive).toBe(false);

    // Verify <DocumentSealer.Viewer /> component matches specification interface
    const html = renderToStaticMarkup(
      <DocumentSealer.Viewer
        payloadUrl="https://api.docbind.internal/v1/documents/doc-123/payload"
        preventScreenshot={true}
        watermark={{ text: 'user@ip', color: 'rgba(0,0,0,0.1)' }}
      />
    );

    expect(html).toContain('data-testid="docbind-secure-viewer"');
    expect(html).toContain('data-prevent-screenshot="true"');
  });
});

import { getMediaCategory } from '../src/media.js';

describe('getMediaCategory', () => {
  it('maps MIME types to viewer renderer categories', () => {
    expect(getMediaCategory('application/pdf')).toBe('pdf');
    expect(getMediaCategory('image/png')).toBe('image');
    expect(getMediaCategory('video/mp4; codecs="avc1"')).toBe('video');
    expect(getMediaCategory('audio/mpeg')).toBe('audio');
    expect(getMediaCategory('application/json')).toBe('text');
    expect(getMediaCategory('application/vnd.openxmlformats-officedocument.wordprocessingml.document')).toBe('other');
    expect(getMediaCategory(undefined)).toBe('other');
  });
});

import { DocumentSealer as Sealer, DocumentTooLargeError } from '../src/DocumentSealer.js';

describe('in-memory decrypt size limits', () => {
  const basePayload = {
    document_id: 'd1',
    target_device_id: 'dev',
    encrypted_dek: 'x',
    iv: 'x',
    auth_tag: 'x',
    encrypted_document: '',
  };

  it('resolves default and configured limits per category', () => {
    Sealer.configure({});
    expect(Sealer.getMaxDecryptBytes('video/mp4')).toBe(100 * 1024 * 1024);
    expect(Sealer.getMaxDecryptBytes('application/pdf')).toBe(50 * 1024 * 1024);
    Sealer.configure({ maxDecryptBytes: { media: 10 } });
    expect(Sealer.getMaxDecryptBytes('audio/mpeg')).toBe(10);
    Sealer.configure({ maxDecryptBytes: 5 });
    expect(Sealer.getMaxDecryptBytes('image/png')).toBe(5);
  });

  it('rejects oversize payloads before decrypting', async () => {
    Sealer.configure({ maxDecryptBytes: { media: 1000, default: 10 } });
    await expect(
      Sealer.decryptPayloadInMemory({ ...basePayload, mime_type: 'video/mp4', size_bytes: 2000 })
    ).rejects.toBeInstanceOf(DocumentTooLargeError);
    await expect(
      Sealer.decryptPayloadInMemory({ ...basePayload, mime_type: 'application/pdf', size_bytes: 11 })
    ).rejects.toBeInstanceOf(DocumentTooLargeError);
  });

  it('rejects via response headers before reading the body', async () => {
    let bodyRead = false;
    const fakeFetch = (async () => ({
      ok: true,
      headers: new Headers({ 'x-docbind-size-bytes': '5000', 'x-docbind-mime-type': 'video/mp4' }),
      json: async () => {
        bodyRead = true;
        return {};
      },
    })) as unknown as typeof fetch;
    Sealer.configure({ apiUrl: 'https://x', deviceToken: 'device-token', customFetch: fakeFetch, maxDecryptBytes: { media: 1000 } });
    await expect(Sealer.fetchAndDecryptInMemory('https://x/v1/documents/a/payload')).rejects.toBeInstanceOf(
      DocumentTooLargeError
    );
    expect(bodyRead).toBe(false);
    Sealer.configure({ maxDecryptBytes: undefined, customFetch: undefined });
  });
});

describe('Hardened enrollment and envelope compatibility', () => {
  it('decrypts authenticated v2 metadata in WebCrypto and rejects a document swap', async () => {
    const store = new DeviceKeyStore(undefined, 'v2-key');
    const publicKey = await store.getOrCreatePublicKeyPem();
    const binding = { targetDeviceId: 'device', documentId: 'doc', mimeType: 'text/plain' };
    const sealed = EnvelopeCryptoService.sealDocument(Buffer.from('v2 secret'), publicKey, binding);
    const input = {
      encryptedDocumentBase64: sealed.encryptedDocument.toString('base64'),
      encryptedDekBase64: sealed.encryptedDek,
      ivBase64: sealed.iv,
      ...binding,
      aadVersion: sealed.aadVersion,
      keyAlgorithm: sealed.keyAlgorithm,
    };
    expect(Buffer.from(await store.decryptEnvelopeInMemory(input)).toString()).toBe('v2 secret');
    await expect(store.decryptEnvelopeInMemory({ ...input, documentId: 'swapped' })).rejects.toThrow();
  });

  it('negotiates Android MGF1-SHA1, supports reopening its key and decrypts a v2 envelope', async () => {
    const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
    let exists = false;
    const native = createReactNativeKeystore({
      keyAlgorithm: 'RSA-OAEP-256-MGF1-SHA1',
      hasKeyPair: async () => exists,
      generateRsaKeyPair: async () => { exists = true; return pair.publicKey; },
      getPublicKeyPem: async () => pair.publicKey,
      rsaOaepDecrypt: async (_alias, encrypted) => EnvelopeCryptoService.unwrapDek(Buffer.from(encrypted, 'base64'), pair.privateKey, 'RSA-OAEP-256-MGF1-SHA1'),
    });
    const store = new DeviceKeyStore(native);
    expect(await store.getOrCreatePublicKeyPem()).toBe(pair.publicKey);
    expect(await new DeviceKeyStore(native).getOrCreatePublicKeyPem()).toBe(pair.publicKey);
    const binding = { targetDeviceId: 'android', documentId: 'doc', mimeType: 'text/plain' };
    const sealed = EnvelopeCryptoService.sealDocument(Buffer.from('android secret'), pair.publicKey, binding, native.keyAlgorithm);
    expect(Buffer.from(await store.decryptEnvelopeInMemory({
      encryptedDocumentBase64: sealed.encryptedDocument.toString('base64'), encryptedDekBase64: sealed.encryptedDek,
      ivBase64: sealed.iv, ...binding, aadVersion: sealed.aadVersion, keyAlgorithm: sealed.keyAlgorithm,
    })).toString()).toBe('android secret');
  });

  it('uses scoped bearer credentials, accepts false capture state and subscribes to native capture events', async () => {
    let listener: ((captured: boolean) => void) | undefined;
    let removed = false;
    const guard = createReactNativeScreenGuard({ isScreenCaptured: async () => false }, {
      addListener: (name, cb) => {
        expect(name).toBe('DocBindCaptureChanged'); listener = cb;
        return { remove: () => { removed = true; } };
      },
    });
    expect(await guard.isScreenCaptured!()).toBe(false);
    const states: boolean[] = [];
    const dispose = guard.addCaptureChangeListener!(captured => states.push(captured));
    listener!(true); listener!(false); dispose();
    expect(states).toEqual([true, false]); expect(removed).toBe(true);

    const fetcher: typeof fetch = async (_url, init) => {
      const headers = init?.headers as Record<string, string>;
      expect(headers.Authorization).toBe('Bearer approved-key');
      expect(headers['x-api-key']).toBeUndefined();
      return new Response(JSON.stringify({ registered_device_id: 'approved-device', device_token: 'device-only' }), { status: 201 });
    };
    DocumentSealer.configure({ apiUrl: 'https://api.example.com', enrollmentToken: 'approved-key', customFetch: fetcher });
    const device = await DocumentSealer.getDeviceToken({ forceRefresh: true });
    expect(device.deviceToken).toBe('device-only');
    await expect(DocumentSealer.fetchAndDecryptInMemory('https://foreign.example.com/payload')).rejects.toThrow(/configured API origin/);
    DocumentSealer.configure({ apiUrl: undefined, deviceToken: undefined, enrollmentToken: undefined, customFetch: undefined });
  });
});
