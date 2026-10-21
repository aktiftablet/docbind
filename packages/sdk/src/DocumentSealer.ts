import type { FC } from 'react';
import { HardwareFingerprint } from './fingerprint/HardwareFingerprint.js';
import { DeviceKeyStore } from './crypto/KeyStore.js';
import type {
  DecryptedDocumentInMemory,
  DeviceTokenResult,
  DocumentSealerConfig,
  EncryptedDocumentPayload,
  SecureViewerProps,
} from './types.js';
import { getMediaCategory } from './media.js';

const MB = 1024 * 1024;
/** Default client-side decrypt limits (single-block decrypt => ~4-5x file size peak RAM). */
export const DEFAULT_MAX_DECRYPT_BYTES = { default: 50 * MB, media: 100 * MB };

/** Thrown when a payload exceeds the configured in-memory decrypt limit. Nothing is decrypted. */
export class DocumentTooLargeError extends Error {
  constructor(
    public readonly sizeBytes: number,
    public readonly maxBytes: number,
    public readonly mimeType: string
  ) {
    super(
      `Document too large to decrypt in memory: ${sizeBytes} bytes exceeds limit of ${maxBytes} bytes (${mimeType}).`
    );
    this.name = 'DocumentTooLargeError';
  }
}

/**
 * Core SDK singleton & static interface matching the DocBind specification:
 *
 * ```ts
 * import { DocumentSealer } from '@secure-doc/sdk';
 *
 * const deviceToken = await DocumentSealer.getDeviceToken();
 *
 * <DocumentSealer.Viewer
 *   payloadUrl="https://api..."
 *   preventScreenshot={true}
 *   watermark={{ text: "user@ip", color: "rgba(0,0,0,0.1)" }}
 * />
 * ```
 */
export class DocumentSealer {
  private static config: DocumentSealerConfig = {
    apiUrl: 'http://localhost:4000',
  };

  private static keyStore = new DeviceKeyStore();
  private static cachedDeviceToken: DeviceTokenResult | null = null;

  /**
   * Attached by `components/Viewer.tsx` so `<DocumentSealer.Viewer ... />` works out of the box.
   */
  public static Viewer: FC<SecureViewerProps>;

  /**
   * Configures the SDK with backend API URL, organization API key, and optional React Native bridges.
   */
  public static configure(config: DocumentSealerConfig): void {
    this.config = {
      ...this.config,
      ...config,
    };
    this.keyStore = new DeviceKeyStore(config.nativeModules?.secureKeystore);
    this.cachedDeviceToken = null;
  }

  public static getConfig(): DocumentSealerConfig {
    return this.config;
  }

  /** Resolves the in-memory decrypt limit for a MIME type from `maxDecryptBytes` config. */
  public static getMaxDecryptBytes(mimeType: string): number {
    const cfg = this.config.maxDecryptBytes;
    const isMedia = ['video', 'audio'].includes(getMediaCategory(mimeType));
    if (typeof cfg === 'number') return cfg;
    if (isMedia) return cfg?.media ?? DEFAULT_MAX_DECRYPT_BYTES.media;
    return cfg?.default ?? DEFAULT_MAX_DECRYPT_BYTES.default;
  }

  private static assertWithinLimit(sizeBytes: number, mimeType: string): void {
    if (!Number.isFinite(sizeBytes) || sizeBytes <= 0) return;
    const max = this.getMaxDecryptBytes(mimeType);
    if (sizeBytes > max) throw new DocumentTooLargeError(sizeBytes, max, mimeType);
  }

  /**
   * 1. Generates or retrieves the non-extractable RSA-OAEP 2048 key pair in Secure Enclave / Keystore / IndexedDB.
   * 2. Computes the deterministic SHA-256 hardware fingerprint hash.
   * 3. Registers the device with `POST /v1/devices/register` if `apiUrl` is reachable,
   *    returning the registered `deviceId`, `hardwareHash`, `publicKeyPem`, and composite `token`.
   */
  public static async getDeviceToken(options?: {
    forceRefresh?: boolean;
    skipBackendRegistration?: boolean;
  }): Promise<DeviceTokenResult> {
    if (this.cachedDeviceToken && !options?.forceRefresh) {
      return this.cachedDeviceToken;
    }

    const [{ hardwareHash, metadata }, publicKeyPem] = await Promise.all([
      HardwareFingerprint.generateHash(this.config.nativeModules?.deviceInfo),
      this.keyStore.getOrCreatePublicKeyPem(),
    ]);

    let registeredDeviceId = `local_${hardwareHash.slice(0, 16)}`;

    if (!options?.skipBackendRegistration && this.config.apiUrl) {
      const fetchFn = this.config.customFetch ?? globalThis.fetch;
      if (typeof fetchFn === 'function') {
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
        };
        if (this.config.apiKey) {
          headers['x-api-key'] = this.config.apiKey;
        }

        const registerUrl = `${this.config.apiUrl.replace(/\/$/, '')}/v1/devices/register`;
        const response = await fetchFn(registerUrl, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            device_id: hardwareHash,
            hardware_hash: hardwareHash,
            public_key: publicKeyPem,
            metadata,
          }),
        });

        if (!response.ok) {
          const errBody = await response.text().catch(() => '');
          throw new Error(
            `Device registration failed (${response.status}): ${errBody || response.statusText}`
          );
        }

        const data = (await response.json()) as {
          success: boolean;
          registered_device_id: string;
        };
        registeredDeviceId = data.registered_device_id;
      }
    }

    const tokenPayload = JSON.stringify({
      deviceId: registeredDeviceId,
      hardwareHash,
    });
    const encodedToken = this.keyStore.uint8ArrayToBase64(
      new TextEncoder().encode(tokenPayload)
    );

    const result: DeviceTokenResult = {
      deviceId: registeredDeviceId,
      hardwareHash,
      publicKeyPem,
      token: encodedToken,
    };

    this.cachedDeviceToken = result;
    return result;
  }

  /**
   * Fetches an encrypted payload from `payloadUrl` and decrypts it strictly in RAM (`Uint8Array`).
   */
  public static async fetchAndDecryptInMemory(
    payloadUrl: string,
    apiKeyOverride?: string
  ): Promise<DecryptedDocumentInMemory> {
    const fetchFn = this.config.customFetch ?? globalThis.fetch;
    if (typeof fetchFn !== 'function') {
      throw new Error('Global fetch is not available. Provide customFetch in DocumentSealer.configure().');
    }

    const deviceInfo =
      this.cachedDeviceToken ??
      (await this.getDeviceToken({ skipBackendRegistration: true }));

    const headers: Record<string, string> = {
      Accept: 'application/json',
      'x-hardware-hash': deviceInfo.hardwareHash,
    };

    if (!deviceInfo.deviceId.startsWith('local_')) {
      headers['x-device-id'] = deviceInfo.deviceId;
    }

    const effectiveApiKey = apiKeyOverride ?? this.config.apiKey;
    if (effectiveApiKey) {
      headers['x-api-key'] = effectiveApiKey;
    }

    const response = await fetchFn(payloadUrl, {
      method: 'GET',
      headers,
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      throw new Error(
        `Failed to fetch encrypted document payload (${response.status}): ${errorText || response.statusText}`
      );
    }

    // Pre-flight size check BEFORE buffering the body into RAM.
    const headerMime = response.headers.get('x-docbind-mime-type');
    const headerSize = Number(response.headers.get('x-docbind-size-bytes'));
    const contentLength = Number(response.headers.get('content-length'));
    if (headerMime && Number.isFinite(headerSize) && headerSize > 0) {
      this.assertWithinLimit(headerSize, headerMime);
    } else if (headerMime && Number.isFinite(contentLength) && contentLength > 0) {
      // Base64 JSON: plaintext ~= 3/4 of body length
      this.assertWithinLimit(Math.floor((contentLength * 3) / 4), headerMime);
    }
    // Without a MIME header, the check runs in decryptPayloadInMemory() before decoding/decrypting.

    const payload = (await response.json()) as EncryptedDocumentPayload;
    return this.decryptPayloadInMemory(payload);
  }

  /**
   * Decrypts an `EncryptedDocumentPayload` entirely in application RAM (`Uint8Array`).
   * Never writes any temporary or plaintext file to disk.
   */
  public static async decryptPayloadInMemory(
    payload: EncryptedDocumentPayload
  ): Promise<DecryptedDocumentInMemory> {
    // Final check before base64 decode + decrypt (covers servers without size headers).
    const mime = payload.mime_type ?? 'application/octet-stream';
    const estimatedSize =
      payload.size_bytes ?? Math.floor((payload.encrypted_document.length * 3) / 4);
    this.assertWithinLimit(estimatedSize, mime);

    const decryptedBytes = await this.keyStore.decryptEnvelopeInMemory({
      encryptedDocumentBase64: payload.encrypted_document,
      encryptedDekBase64: payload.encrypted_dek,
      ivBase64: payload.iv,
      targetDeviceId: payload.target_device_id,
    });

    return {
      documentId: payload.document_id,
      targetDeviceId: payload.target_device_id,
      mimeType: payload.mime_type ?? 'application/octet-stream',
      originalName: payload.original_name ?? null,
      bytes: decryptedBytes,
      dispose: () => {
        // Cryptographically zero out decrypted file bytes from RAM on unmount
        decryptedBytes.fill(0);
      },
    };
  }
}
