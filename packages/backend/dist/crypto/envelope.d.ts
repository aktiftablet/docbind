export interface SealedEnvelopeResult {
    /** Ciphertext concatenated with 16-byte GCM authentication tag (WebCrypto AES-GCM standard format) */
    encryptedDocument: Buffer;
    /** Base64-encoded DEK encrypted with the target device's RSA-OAEP-256 Public Key */
    encryptedDek: string;
    /** Base64-encoded 12-byte Initialization Vector */
    iv: string;
    /** Base64-encoded 16-byte GCM Authentication Tag */
    authTag: string;
}
export declare class EnvelopeCryptoService {
    private static readonly AES_ALGORITHM;
    private static readonly DEK_BYTE_LENGTH;
    private static readonly IV_BYTE_LENGTH;
    private static readonly AUTH_TAG_BYTE_LENGTH;
    /**
     * Validates that a provided string is a valid RSA public key in PEM format
     * with at least 2048 bits modulus length.
     */
    static validateRsaPublicKey(publicKeyPem: string): void;
    /**
     * Performs Envelope Encryption on a document buffer for a specific target device:
     * 1. Generates an ephemeral 256-bit AES-GCM Data Encryption Key (DEK) and 96-bit IV.
     * 2. Encrypts the document buffer in-memory using AES-256-GCM (binding targetDeviceId as AAD).
     * 3. Encrypts the DEK with the target device's RSA-OAEP (SHA-256) Public Key.
     * 4. Zeroes out the plaintext DEK buffer in memory before returning.
     */
    static sealDocument(plaintextDocument: Buffer, devicePublicKeyPem: string, targetDeviceId: string): SealedEnvelopeResult;
    /**
     * Utility for verifying/unsealing in Node environments (used in tests and SDK Node runtime).
     * Decrypts the DEK using the device's RSA-OAEP Private Key and then decrypts the document in-memory.
     */
    static unsealDocument(encryptedDocumentWithTag: Buffer, encryptedDekBase64: string, ivBase64: string, devicePrivateKeyPem: string, targetDeviceId: string): Buffer;
    /**
     * Computes a deterministic SHA-256 hardware fingerprint hash from normalized attributes.
     */
    static hashHardwareFingerprint(rawFingerprint: string): string;
}
//# sourceMappingURL=envelope.d.ts.map