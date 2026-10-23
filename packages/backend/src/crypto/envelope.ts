import crypto from 'node:crypto';

/**
 * Key-encryption algorithms supported for wrapping the DEK with a device public key.
 *
 * - `RSA-OAEP-256`: OAEP with SHA-256 label hash **and** MGF1-SHA-256 (WebCrypto, iOS
 *   `kSecKeyAlgorithmRSAEncryptionOAEPSHA256`).
 * - `RSA-OAEP-256-MGF1-SHA1`: OAEP with SHA-256 label hash and MGF1-SHA-1. This is what
 *   AndroidKeyStore supports on all API levels (`RSA/ECB/OAEPWithSHA-256AndMGF1Padding`
 *   with the default MGF1 digest). Node cannot produce it natively, so OAEP encoding is
 *   implemented here per RFC 8017 §7.1 and applied with raw RSA.
 */
export const KEY_ALGORITHMS = ['RSA-OAEP-256', 'RSA-OAEP-256-MGF1-SHA1'] as const;
export type KeyAlgorithm = (typeof KEY_ALGORITHMS)[number];
export const DEFAULT_KEY_ALGORITHM: KeyAlgorithm = 'RSA-OAEP-256';

export function isKeyAlgorithm(value: unknown): value is KeyAlgorithm {
  return typeof value === 'string' && (KEY_ALGORITHMS as readonly string[]).includes(value);
}

/** AAD format version. `v1` = target device id only (legacy); `v2` = device id + document id + MIME type. */
export type AadVersion = 'v1' | 'v2';
export const CURRENT_AAD_VERSION: AadVersion = 'v2';

export interface AadBinding {
  targetDeviceId: string;
  documentId: string;
  mimeType: string;
}

/**
 * Builds the Additional Authenticated Data bound to the ciphertext.
 * `v2` binds the document id and MIME type too, so stored metadata cannot be swapped
 * (e.g. re-labelling a document as another type or moving ciphertext between records).
 * The SDK must build the exact same byte string (see `packages/sdk/src/crypto/aad.ts`).
 */
export function buildAad(binding: AadBinding | string, version: AadVersion = CURRENT_AAD_VERSION): Buffer {
  if (typeof binding === 'string' || version === 'v1') {
    const deviceId = typeof binding === 'string' ? binding : binding.targetDeviceId;
    return Buffer.from(deviceId, 'utf-8');
  }
  return Buffer.from(
    `docbind:v2|${binding.targetDeviceId}|${binding.documentId}|${binding.mimeType}`,
    'utf-8'
  );
}

export interface SealedEnvelopeResult {
  /** Ciphertext concatenated with 16-byte GCM authentication tag (WebCrypto AES-GCM standard format) */
  encryptedDocument: Buffer;
  /** Base64-encoded DEK encrypted with the target device's public key (see `keyAlgorithm`) */
  encryptedDek: string;
  /** Base64-encoded 12-byte Initialization Vector */
  iv: string;
  /** Base64-encoded 16-byte GCM Authentication Tag */
  authTag: string;
  /** AAD format used for this envelope */
  aadVersion: AadVersion;
  /** Algorithm used to wrap the DEK */
  keyAlgorithm: KeyAlgorithm;
}

function mgf1(seed: Buffer, length: number, hash: string): Buffer {
  const hLen = crypto.createHash(hash).digest().length;
  const chunks: Buffer[] = [];
  const counter = Buffer.alloc(4);
  for (let i = 0; i < Math.ceil(length / hLen); i++) {
    counter.writeUInt32BE(i, 0);
    chunks.push(crypto.createHash(hash).update(seed).update(counter).digest());
  }
  return Buffer.concat(chunks).subarray(0, length);
}

function xor(a: Buffer, b: Buffer): Buffer {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** RFC 8017 §7.1.1 EME-OAEP encoding with independent label-hash and MGF1-hash. */
export function oaepEncode(
  message: Buffer,
  modulusBytes: number,
  labelHash = 'sha256',
  mgf1Hash = 'sha256'
): Buffer {
  const lHash = crypto.createHash(labelHash).digest();
  const hLen = lHash.length;
  const maxLen = modulusBytes - 2 * hLen - 2;
  if (message.length > maxLen) {
    throw new Error(`OAEP message too long (${message.length} > ${maxLen}).`);
  }
  const ps = Buffer.alloc(maxLen - message.length);
  const db = Buffer.concat([lHash, ps, Buffer.from([0x01]), message]);
  const seed = crypto.randomBytes(hLen);
  const maskedDb = xor(db, mgf1(seed, db.length, mgf1Hash));
  const maskedSeed = xor(seed, mgf1(maskedDb, hLen, mgf1Hash));
  return Buffer.concat([Buffer.from([0x00]), maskedSeed, maskedDb]);
}

/** RFC 8017 §7.1.2 EME-OAEP decoding. Throws a single generic error on any failure. */
export function oaepDecode(
  encoded: Buffer,
  modulusBytes: number,
  labelHash = 'sha256',
  mgf1Hash = 'sha256'
): Buffer {
  const lHash = crypto.createHash(labelHash).digest();
  const hLen = lHash.length;
  const fail = () => new Error('OAEP decoding error.');
  if (encoded.length !== modulusBytes || modulusBytes < 2 * hLen + 2) throw fail();

  const maskedSeed = encoded.subarray(1, 1 + hLen);
  const maskedDb = encoded.subarray(1 + hLen);
  const seed = xor(maskedSeed, mgf1(maskedDb, hLen, mgf1Hash));
  const db = xor(maskedDb, mgf1(seed, maskedDb.length, mgf1Hash));

  let bad = encoded[0] !== 0x00 ? 1 : 0;
  bad |= crypto.timingSafeEqual(db.subarray(0, hLen), lHash) ? 0 : 1;
  let sepIndex = -1;
  for (let i = hLen; i < db.length; i++) {
    if (sepIndex === -1 && db[i] === 0x01) sepIndex = i;
    else if (sepIndex === -1 && db[i] !== 0x00) bad |= 1;
  }
  if (bad || sepIndex === -1) throw fail();
  return db.subarray(sepIndex + 1);
}

function rsaModulusBytes(key: crypto.KeyObject): number {
  const bits = key.asymmetricKeyDetails?.modulusLength;
  if (!bits) throw new Error('Unable to determine RSA modulus length.');
  return Math.ceil(bits / 8);
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
      if (modulusLength === undefined || modulusLength < 2048) {
        throw new Error(`RSA key modulus length (${modulusLength}) is below minimum 2048 bits.`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Invalid PEM public key';
      throw new Error(`Invalid device public key: ${message}`);
    }
  }

  /**
   * Stable identifier of a public key: SHA-256 (hex) over its DER-encoded SPKI.
   * Formatting differences in the PEM (line breaks, whitespace) do not change it.
   */
  public static publicKeyFingerprint(publicKeyPem: string): string {
    const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
    return crypto.createHash('sha256').update(der).digest('hex');
  }

  /** Wraps a DEK with the device public key using the requested OAEP variant. */
  public static wrapDek(dek: Buffer, devicePublicKeyPem: string, keyAlgorithm: KeyAlgorithm): Buffer {
    if (keyAlgorithm === 'RSA-OAEP-256') {
      return crypto.publicEncrypt(
        { key: devicePublicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        dek
      );
    }
    const key = crypto.createPublicKey(devicePublicKeyPem);
    const encoded = oaepEncode(dek, rsaModulusBytes(key), 'sha256', 'sha1');
    try {
      return crypto.publicEncrypt({ key, padding: crypto.constants.RSA_NO_PADDING }, encoded);
    } finally {
      encoded.fill(0);
    }
  }

  /** Unwraps a DEK with the device private key (Node utility, used by tests / Node runtimes). */
  public static unwrapDek(
    encryptedDek: Buffer,
    devicePrivateKeyPem: string,
    keyAlgorithm: KeyAlgorithm
  ): Buffer {
    if (keyAlgorithm === 'RSA-OAEP-256') {
      return crypto.privateDecrypt(
        { key: devicePrivateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        encryptedDek
      );
    }
    const key = crypto.createPrivateKey(devicePrivateKeyPem);
    const encoded = crypto.privateDecrypt({ key, padding: crypto.constants.RSA_NO_PADDING }, encryptedDek);
    try {
      return Buffer.from(oaepDecode(encoded, rsaModulusBytes(key), 'sha256', 'sha1'));
    } finally {
      encoded.fill(0);
    }
  }

  /**
   * Performs Envelope Encryption on a document buffer for a specific target device:
   * 1. Generates an ephemeral 256-bit AES-GCM Data Encryption Key (DEK) and 96-bit IV.
   * 2. Encrypts the document buffer in-memory using AES-256-GCM, binding the AAD
   *    (`v2`: device id + document id + MIME type; a plain string binding yields legacy `v1`).
   * 3. Wraps the DEK with the target device's RSA public key (`keyAlgorithm`).
   * 4. Zeroes out the plaintext DEK buffer before returning.
   *
   * Note: the server sees the plaintext while sealing. This is server-side envelope encryption,
   * not a zero-knowledge scheme.
   */
  public static sealDocument(
    plaintextDocument: Buffer,
    devicePublicKeyPem: string,
    binding: AadBinding | string,
    keyAlgorithm: KeyAlgorithm = DEFAULT_KEY_ALGORITHM
  ): SealedEnvelopeResult {
    this.validateRsaPublicKey(devicePublicKeyPem);

    const aadVersion: AadVersion = typeof binding === 'string' ? 'v1' : CURRENT_AAD_VERSION;
    const dek = crypto.randomBytes(this.DEK_BYTE_LENGTH);
    const iv = crypto.randomBytes(this.IV_BYTE_LENGTH);

    try {
      const cipher = crypto.createCipheriv(this.AES_ALGORITHM, dek, iv, {
        authTagLength: this.AUTH_TAG_BYTE_LENGTH,
      });
      cipher.setAAD(buildAad(binding, aadVersion));

      const ciphertext = Buffer.concat([cipher.update(plaintextDocument), cipher.final()]);
      const authTag = cipher.getAuthTag();

      // WebCrypto AES-GCM expects ciphertext || authTag (16 bytes appended at the end)
      const encryptedDocument = Buffer.concat([ciphertext, authTag]);
      const encryptedDekBuffer = this.wrapDek(dek, devicePublicKeyPem, keyAlgorithm);

      return {
        encryptedDocument,
        encryptedDek: encryptedDekBuffer.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        aadVersion,
        keyAlgorithm,
      };
    } finally {
      dek.fill(0);
    }
  }

  /**
   * Utility for verifying/unsealing in Node environments (used in tests and SDK Node runtime).
   * Decrypts the DEK using the device's RSA Private Key and then decrypts the document in-memory.
   * `binding` must match what was used when sealing (string => `v1`, object => `v2`).
   */
  public static unsealDocument(
    encryptedDocumentWithTag: Buffer,
    encryptedDekBase64: string,
    ivBase64: string,
    devicePrivateKeyPem: string,
    binding: AadBinding | string,
    keyAlgorithm: KeyAlgorithm = DEFAULT_KEY_ALGORITHM
  ): Buffer {
    const encryptedDek = Buffer.from(encryptedDekBase64, 'base64');
    const iv = Buffer.from(ivBase64, 'base64');
    const aadVersion: AadVersion = typeof binding === 'string' ? 'v1' : CURRENT_AAD_VERSION;

    const dek = this.unwrapDek(encryptedDek, devicePrivateKeyPem, keyAlgorithm);

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

      decipher.setAAD(buildAad(binding, aadVersion));
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
