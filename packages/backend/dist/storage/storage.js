"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InMemoryEncryptedStorage = void 0;
/**
 * Stores ONLY AES-256-GCM encrypted ciphertext blobs in memory (or S3-compatible bucket).
 * Plaintext PDFs are never persisted to disk.
 */
class InMemoryEncryptedStorage {
    blobs = new Map();
    bucketName;
    constructor(bucketName = process.env.S3_BUCKET_NAME || 'docbind-encrypted-vault') {
        this.bucketName = bucketName;
    }
    async putEncryptedBlob(documentId, orgId, ciphertext) {
        const storageUrl = `s3://${this.bucketName}/${orgId}/${documentId}.enc`;
        this.blobs.set(storageUrl, Buffer.from(ciphertext));
        return storageUrl;
    }
    async getEncryptedBlob(storageUrl) {
        const blob = this.blobs.get(storageUrl);
        if (!blob) {
            throw new Error(`Encrypted payload not found at storage URL: ${storageUrl}`);
        }
        return blob;
    }
    async deleteEncryptedBlob(storageUrl) {
        this.blobs.delete(storageUrl);
    }
}
exports.InMemoryEncryptedStorage = InMemoryEncryptedStorage;
//# sourceMappingURL=storage.js.map