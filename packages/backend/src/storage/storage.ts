import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';

export interface StorageAdapter {
  putEncryptedBlob(documentId: string, orgId: string, ciphertext: Buffer): Promise<string>;
  getEncryptedBlob(storageUrl: string): Promise<Buffer>;
  deleteEncryptedBlob(storageUrl: string): Promise<void>;
}

/** Development/test storage. Encrypted data is lost on restart. */
export class InMemoryEncryptedStorage implements StorageAdapter {
  private readonly blobs = new Map<string, Buffer>();
  async putEncryptedBlob(documentId: string, orgId: string, ciphertext: Buffer): Promise<string> {
    const url = `memory://${orgId}/${documentId}.enc`;
    this.blobs.set(url, Buffer.from(ciphertext));
    return url;
  }
  async getEncryptedBlob(url: string): Promise<Buffer> {
    const blob = this.blobs.get(url);
    if (!blob) throw new Error('Encrypted payload not found');
    return blob;
  }
  async deleteEncryptedBlob(url: string): Promise<void> { this.blobs.delete(url); }
}

/** Stores ciphertext only. Credentials use the standard AWS credential provider chain. */
export class S3EncryptedStorage implements StorageAdapter {
  constructor(private readonly client: S3Client, private readonly bucket: string) {}
  private key(url: string): string {
    const prefix = `s3://${this.bucket}/`;
    if (!url.startsWith(prefix) || !/^[\w-]+\/[\w-]+\.enc$/.test(url.slice(prefix.length))) throw new Error('Invalid storage location');
    return url.slice(prefix.length);
  }
  async putEncryptedBlob(documentId: string, orgId: string, ciphertext: Buffer): Promise<string> {
    const url = `s3://${this.bucket}/${orgId}/${documentId}.enc`;
    await this.client.send(new PutObjectCommand({ Bucket: this.bucket, Key: this.key(url), Body: ciphertext, ContentType: 'application/octet-stream' }));
    return url;
  }
  async getEncryptedBlob(url: string): Promise<Buffer> {
    const result = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: this.key(url) }));
    if (!result.Body) throw new Error('Encrypted payload not found');
    return Buffer.from(await result.Body.transformToByteArray());
  }
  async deleteEncryptedBlob(url: string): Promise<void> {
    await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: this.key(url) }));
  }
}
