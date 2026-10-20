export interface StorageAdapter {
    putEncryptedBlob(documentId: string, orgId: string, ciphertext: Buffer): Promise<string>;
    getEncryptedBlob(storageUrl: string): Promise<Buffer>;
    deleteEncryptedBlob(storageUrl: string): Promise<void>;
}
/**
 * Stores ONLY AES-256-GCM encrypted ciphertext blobs in memory (or S3-compatible bucket).
 * Plaintext PDFs are never persisted to disk.
 */
export declare class InMemoryEncryptedStorage implements StorageAdapter {
    private readonly blobs;
    private readonly bucketName;
    constructor(bucketName?: string);
    putEncryptedBlob(documentId: string, orgId: string, ciphertext: Buffer): Promise<string>;
    getEncryptedBlob(storageUrl: string): Promise<Buffer>;
    deleteEncryptedBlob(storageUrl: string): Promise<void>;
}
//# sourceMappingURL=storage.d.ts.map