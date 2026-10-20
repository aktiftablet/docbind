import type { NativeHardwareKeystoreLike } from '../types.js';
export interface StoredKeyPairRecord {
    alias: string;
    publicKeyPem: string;
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    createdAt: number;
}
/**
 * Manages hardware-bound RSA-OAEP 2048 key pairs and performs zero-knowledge
 * in-memory envelope decryption:
 * - On Mobile (React Native): Uses iOS Secure Enclave / Android Keystore via NativeHardwareKeystoreLike.
 * - On Web: Generates WebCrypto RSA-OAEP 2048 keys with `extractable: false` and persists the
 *   non-extractable CryptoKey handle in IndexedDB so raw private key bytes can never be exported.
 */
export declare class DeviceKeyStore {
    private readonly nativeKeystore?;
    private readonly keyAlias;
    private memoryKeyPairCache;
    constructor(nativeKeystore?: NativeHardwareKeystoreLike | undefined, keyAlias?: string);
    /**
     * Ensures an RSA-OAEP 2048-bit key pair exists for this device and returns its PEM SPKI Public Key.
     * The private key is strictly non-extractable.
     */
    getOrCreatePublicKeyPem(): Promise<string>;
    /**
     * Decrypts a sealed document payload entirely in RAM (`Uint8Array`) without ever
     * writing the DEK or plaintext PDF to disk.
     */
    decryptEnvelopeInMemory(params: {
        encryptedDocumentBase64: string;
        encryptedDekBase64: string;
        ivBase64: string;
        targetDeviceId: string;
    }): Promise<Uint8Array>;
    private getSubtleCrypto;
    private loadWebKeyPair;
    private saveWebKeyPair;
    private openIndexedDb;
    private spkiBufferToPem;
    uint8ArrayToBase64(bytes: Uint8Array): string;
    base64ToUint8Array(base64: string): Uint8Array;
    private toArrayBuffer;
}
//# sourceMappingURL=KeyStore.d.ts.map