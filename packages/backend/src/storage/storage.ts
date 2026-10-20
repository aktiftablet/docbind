export interface StorageAdapter {
  putEncryptedBlob(documentId: string, orgId: string, ciphertext: Buffer): Promise<string>;
  getEncryptedBlob(storageUrl: string): Promise<Buffer>;
  deleteEncryptedBlob(storageUrl: string): Promise<void>;
}

/**
 * Stores ONLY AES-256-GCM encrypted ciphertext blobs in memory (or S3-compatible bucket).
 * Plaintext PDFs are never persisted to disk.
 */
export class InMemoryEncryptedStorage implements StorageAdapter {
  private readonly blobs = new Map<string, Buffer>();
  private readonly bucketName: string;

  constructor(bucketName = process.env.S3_BUCKET_NAME || 'docbind-encrypted-vault') {
    this.bucketName = bucketName;
  }

  public async putEncryptedBlob(
    documentId: string,
    orgId: string,
    ciphertext: Buffer
  ): Promise<string> {
    const storageUrl = `s3://${this.bucketName}/${orgId}/${documentId}.enc`;
    this.blobs.set(storageUrl, Buffer.from(ciphertext));
    return storageUrl;
  }

  public async getEncryptedBlob(storageUrl: string): Promise<Buffer> {
    const blob = this.blobs.get(storageUrl);
    if (!blob) {
      throw new Error(`Encrypted payload not found at storage URL: ${storageUrl}`);
    }
    return blob;
  }

  public async deleteEncryptedBlob(storageUrl: string): Promise<void> {
    this.blobs.delete(storageUrl);
  }
}
