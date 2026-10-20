import crypto from 'node:crypto';

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

export class EnvelopeCryptoService {
  private static readonly AES_ALGORITHM = 'aes-256-gcm';
  private static readonly DEK_BYTE_LENGTH = 32; // 256 bits
  private static readonly IV_BYTE_LENGTH = 12; // 96 bits recommended for GCM
  private static readonly AUTH_TAG_BYTE_LENGTH = 16; // 128 bits

  /**
   * Validates that a provided string is a valid RSA public key in PEM format
   * with at least 2048 bits modulus length.
   */
  public static validateRsaPublicKey(publicKeyPem: string): void {
    try {
      const keyObj = crypto.createPublicKey(publicKeyPem);
      if (keyObj.asymmetricKeyType !== 'rsa') {
        throw new Error(`Unsupported asymmetric key type: ${keyObj.asymmetricKeyType}. Expected 'rsa'.`);
      }
      const modulusLength = keyObj.asymmetricKeyDetails?.modulusLength;
      if (modulusLength !== undefined && modulusLength < 2048) {
        throw new Error(`RSA key modulus length (${modulusLength}) is below minimum 2048 bits.`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Invalid PEM public key';
      throw new Error(`Invalid device public key: ${message}`);
    }
  }

  /**
   * Performs Envelope Encryption on a document buffer for a specific target device:
   * 1. Generates an ephemeral 256-bit AES-GCM Data Encryption Key (DEK) and 96-bit IV.
   * 2. Encrypts the document buffer in-memory using AES-256-GCM (binding targetDeviceId as AAD).
   * 3. Encrypts the DEK with the target device's RSA-OAEP (SHA-256) Public Key.
   * 4. Zeroes out the plaintext DEK buffer in memory before returning.
   */
  public static sealDocument(
    plaintextDocument: Buffer,
    devicePublicKeyPem: string,
    targetDeviceId: string
  ): SealedEnvelopeResult {
    this.validateRsaPublicKey(devicePublicKeyPem);

    const dek = crypto.randomBytes(this.DEK_BYTE_LENGTH);
    const iv = crypto.randomBytes(this.IV_BYTE_LENGTH);

    try {
      const cipher = crypto.createCipheriv(this.AES_ALGORITHM, dek, iv, {
        authTagLength: this.AUTH_TAG_BYTE_LENGTH,
      });

      // Bind the ciphertext to the target device ID via Additional Authenticated Data (AAD)
      const aadBuffer = Buffer.from(targetDeviceId, 'utf-8');
      cipher.setAAD(aadBuffer);

      const ciphertext = Buffer.concat([
        cipher.update(plaintextDocument),
        cipher.final(),
      ]);
      const authTag = cipher.getAuthTag();

      // WebCrypto AES-GCM expects ciphertext || authTag (16 bytes appended at the end)
      const encryptedDocument = Buffer.concat([ciphertext, authTag]);

      // Encrypt the DEK using the target device's RSA-OAEP (SHA-256) Public Key
      const encryptedDekBuffer = crypto.publicEncrypt(
        {
          key: devicePublicKeyPem,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        dek
      );

      return {
        encryptedDocument,
        encryptedDek: encryptedDekBuffer.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
      };
    } finally {
      // Zero out the plaintext DEK in RAM immediately after sealing
      dek.fill(0);
    }
  }

  /**
   * Utility for verifying/unsealing in Node environments (used in tests and SDK Node runtime).
   * Decrypts the DEK using the device's RSA-OAEP Private Key and then decrypts the document in-memory.
   */
  public static unsealDocument(
    encryptedDocumentWithTag: Buffer,
    encryptedDekBase64: string,
    ivBase64: string,
    devicePrivateKeyPem: string,
    targetDeviceId: string
  ): Buffer {
    const encryptedDek = Buffer.from(encryptedDekBase64, 'base64');
    const iv = Buffer.from(ivBase64, 'base64');

    const dek = crypto.privateDecrypt(
      {
        key: devicePrivateKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      encryptedDek
    );

    try {
      if (encryptedDocumentWithTag.length < this.AUTH_TAG_BYTE_LENGTH) {
        throw new Error('Encrypted document payload is too short to contain GCM auth tag.');
      }

      const ciphertext = encryptedDocumentWithTag.subarray(
        0,
        encryptedDocumentWithTag.length - this.AUTH_TAG_BYTE_LENGTH
      );
      const authTag = encryptedDocumentWithTag.subarray(
        encryptedDocumentWithTag.length - this.AUTH_TAG_BYTE_LENGTH
      );

      const decipher = crypto.createDecipheriv(this.AES_ALGORITHM, dek, iv, {
        authTagLength: this.AUTH_TAG_BYTE_LENGTH,
      });

      decipher.setAAD(Buffer.from(targetDeviceId, 'utf-8'));
      decipher.setAuthTag(authTag);

      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } finally {
      dek.fill(0);
    }
  }

  /**
   * Computes a deterministic SHA-256 hardware fingerprint hash from normalized attributes.
   */
  public static hashHardwareFingerprint(rawFingerprint: string): string {
    return crypto.createHash('sha256').update(rawFingerprint.trim()).digest('hex');
  }
}
