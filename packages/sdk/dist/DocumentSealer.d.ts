import type { FC } from 'react';
import type { DecryptedDocumentInMemory, DeviceTokenResult, DocumentSealerConfig, EncryptedDocumentPayload, SecureViewerProps } from './types.js';
/** Default client-side decrypt limits (single-block decrypt => ~4-5x file size peak RAM). */
export declare const DEFAULT_MAX_DECRYPT_BYTES: {
    default: number;
    media: number;
};
/** Thrown when a payload exceeds the configured in-memory decrypt limit. Nothing is decrypted. */
export declare class DocumentTooLargeError extends Error {
    readonly sizeBytes: number;
    readonly maxBytes: number;
    readonly mimeType: string;
    constructor(sizeBytes: number, maxBytes: number, mimeType: string);
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
export declare class DocumentSealer {
    private static config;
    private static keyStore;
    private static cachedDeviceToken;
    /**
     * Attached by `components/Viewer.tsx` so `<DocumentSealer.Viewer ... />` works out of the box.
     */
    static Viewer: FC<SecureViewerProps>;
    /**
     * Configures the SDK with backend API URL, organization API key, and optional React Native bridges.
     */
    static configure(config: DocumentSealerConfig): void;
    static getConfig(): DocumentSealerConfig;
    /** Resolves the in-memory decrypt limit for a MIME type from `maxDecryptBytes` config. */
    static getMaxDecryptBytes(mimeType: string): number;
    private static assertWithinLimit;
    /**
     * 1. Generates or retrieves the non-extractable RSA-OAEP 2048 key pair in Secure Enclave / Keystore / IndexedDB.
     * 2. Computes the deterministic SHA-256 hardware fingerprint hash.
     * 3. Registers the device with `POST /v1/devices/register` if `apiUrl` is reachable,
     *    returning the registered `deviceId`, `hardwareHash`, `publicKeyPem`, and composite `token`.
     */
    static getDeviceToken(options?: {
        forceRefresh?: boolean;
        skipBackendRegistration?: boolean;
    }): Promise<DeviceTokenResult>;
    /**
     * Fetches an encrypted payload from `payloadUrl` and decrypts it strictly in RAM (`Uint8Array`).
     */
    static fetchAndDecryptInMemory(payloadUrl: string, apiKeyOverride?: string): Promise<DecryptedDocumentInMemory>;
    /**
     * Decrypts an `EncryptedDocumentPayload` entirely in application RAM (`Uint8Array`).
     * Never writes any temporary or plaintext file to disk.
     */
    static decryptPayloadInMemory(payload: EncryptedDocumentPayload): Promise<DecryptedDocumentInMemory>;
}
//# sourceMappingURL=DocumentSealer.d.ts.map