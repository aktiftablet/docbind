import type { NativeHardwareKeystoreLike } from '../types.js';

const IDB_DB_NAME = 'docbind_secure_enclave_db';
const IDB_STORE_NAME = 'hardware_keys';
const DEFAULT_KEY_ALIAS = 'docbind_device_rsa_oaep_2048';

export interface StoredKeyPairRecord {
  alias: string;
  publicKeyPem: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  createdAt: number;
}

/**
 * Manages platform-protected RSA-OAEP 2048 key pairs and performs
 * in-memory envelope decryption:
 * - On Mobile (React Native): Uses iOS Keychain / Android Keystore via NativeHardwareKeystoreLike.
 * - On Web: Generates WebCrypto RSA-OAEP 2048 keys with `extractable: false` and persists the
 *   non-extractable CryptoKey handle in IndexedDB so raw private key bytes can never be exported.
 */
export class DeviceKeyStore {
  private memoryKeyPairCache = new Map<string, StoredKeyPairRecord>();

  constructor(
    private readonly nativeKeystore?: NativeHardwareKeystoreLike,
    private readonly keyAlias: string = DEFAULT_KEY_ALIAS
  ) {}

  /**
   * Ensures an RSA-OAEP 2048-bit key pair exists for this device and returns its PEM SPKI Public Key.
   * Web private keys are non-extractable through WebCrypto; native protection depends on the platform.
   */
  public async getOrCreatePublicKeyPem(): Promise<string> {
    if (this.nativeKeystore) {
      const exists = await this.nativeKeystore.hasKeyPair(this.keyAlias);
      if (!exists) {
        const created = await this.nativeKeystore.generateRsaKeyPair(this.keyAlias);
        return created.publicKeyPem;
      }
      return this.nativeKeystore.getPublicKeyPem(this.keyAlias);
    }

    const existing = await this.loadWebKeyPair(this.keyAlias);
    if (existing) {
      return existing.publicKeyPem;
    }

    const subtle = this.getSubtleCrypto();

    // Generate RSA-OAEP 2048 key pair with extractable: false so the private key
    // cannot be exported via subtle.exportKey() by any script.
    const keyPair = await subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
        hash: 'SHA-256',
      },
      false, // CRITICAL: extractable = false protects Private Key from export
      ['decrypt', 'unwrapKey']
    );

    const spkiBuffer = await subtle.exportKey('spki', keyPair.publicKey);
    const publicKeyPem = this.spkiBufferToPem(spkiBuffer);

    const record: StoredKeyPairRecord = {
      alias: this.keyAlias,
      publicKeyPem,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      createdAt: Date.now(),
    };

    await this.saveWebKeyPair(record);
    return publicKeyPem;
  }

  /**
   * Decrypts a sealed document payload entirely in RAM (`Uint8Array`) without ever
   * writing the DEK or plaintext PDF to disk.
   */
  public async decryptEnvelopeInMemory(params: {
    encryptedDocumentBase64: string;
    encryptedDekBase64: string;
    ivBase64: string;
    targetDeviceId: string;
    documentId?: string;
    mimeType?: string;
    aadVersion?: 'v1' | 'v2';
    keyAlgorithm?: 'RSA-OAEP-256' | 'RSA-OAEP-256-MGF1-SHA1';
  }): Promise<Uint8Array> {
    const subtle = this.getSubtleCrypto();
    const encryptedDocBytes = this.base64ToUint8Array(params.encryptedDocumentBase64);
    const encryptedDekBytes = this.base64ToUint8Array(params.encryptedDekBase64);
    const ivBytes = this.base64ToUint8Array(params.ivBase64);
    const version = params.aadVersion ?? 'v1';
    if (version !== 'v1' && version !== 'v2') throw new Error('Unsupported AAD version');
    if (version === 'v2' && (!params.documentId || !params.mimeType)) throw new Error('Missing authenticated document metadata');
    const aadBytes = new TextEncoder().encode(version === 'v2'
      ? `docbind:v2|${params.targetDeviceId}|${params.documentId}|${params.mimeType}` : params.targetDeviceId);
    const keyAlgorithm = params.keyAlgorithm ?? 'RSA-OAEP-256';
    if (keyAlgorithm !== (this.nativeKeystore?.keyAlgorithm ?? 'RSA-OAEP-256')) {
      throw new Error('Envelope key algorithm does not match this keystore');
    }

    if (this.nativeKeystore) {
      // Mobile Native Keystore path: decrypt DEK in Keychain / Android Keystore
      const rawDekBytes = await this.nativeKeystore.rsaOaepDecrypt(
        this.keyAlias,
        params.encryptedDekBase64
      );
      try {
        const aesKey = await subtle.importKey(
          'raw',
          this.toArrayBuffer(rawDekBytes),
          { name: 'AES-GCM', length: 256 },
          false,
          ['decrypt']
        );
        const plaintextBuffer = await subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: this.toArrayBuffer(ivBytes),
            additionalData: this.toArrayBuffer(aadBytes),
            tagLength: 128,
          },
          aesKey,
          this.toArrayBuffer(encryptedDocBytes)
        );
        return new Uint8Array(plaintextBuffer);
      } finally {
        // Zero out DEK bytes in RAM immediately
        rawDekBytes.fill(0);
      }
    }

    // WebCrypto path: Use subtle.unwrapKey to unwrap the RSA-encrypted DEK directly
    // into a non-extractable AES-GCM CryptoKey handle in RAM!
    const keyRecord = await this.loadWebKeyPair(this.keyAlias);
    if (!keyRecord) {
      throw new Error(
        'Device private key not found in secure keystore. Call DocumentSealer.getDeviceToken() first.'
      );
    }

    const unwrappedAesKey = await subtle.unwrapKey(
      'raw',
      this.toArrayBuffer(encryptedDekBytes),
      keyRecord.privateKey,
      {
        name: 'RSA-OAEP',
      },
      {
        name: 'AES-GCM',
        length: 256,
      },
      false, // Non-extractable ephemeral DEK in RAM
      ['decrypt']
    );

    const decryptedBuffer = await subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: this.toArrayBuffer(ivBytes),
        additionalData: this.toArrayBuffer(aadBytes),
        tagLength: 128,
      },
      unwrappedAesKey,
      this.toArrayBuffer(encryptedDocBytes)
    );

    return new Uint8Array(decryptedBuffer);
  }

  private getSubtleCrypto(): SubtleCrypto {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) {
      throw new Error('WebCrypto SubtleCrypto is required for in-memory cryptographic operations.');
    }
    return subtle;
  }

  private async loadWebKeyPair(alias: string): Promise<StoredKeyPairRecord | null> {
    if (this.memoryKeyPairCache.has(alias)) {
      return this.memoryKeyPairCache.get(alias)!;
    }

    if (typeof indexedDB === 'undefined') {
      return null;
    }

    try {
      const db = await this.openIndexedDb();
      return await new Promise<StoredKeyPairRecord | null>((resolve, reject) => {
        const tx = db.transaction(IDB_STORE_NAME, 'readonly');
        const store = tx.objectStore(IDB_STORE_NAME);
        const req = store.get(alias);
        req.onsuccess = () => {
          const result = (req.result as StoredKeyPairRecord | undefined) ?? null;
          if (result) {
            this.memoryKeyPairCache.set(alias, result);
          }
          resolve(result);
        };
        req.onerror = () => reject(req.error);
      });
    } catch {
      return null;
    }
  }

  private async saveWebKeyPair(record: StoredKeyPairRecord): Promise<void> {
    this.memoryKeyPairCache.set(record.alias, record);

    if (typeof indexedDB === 'undefined') {
      return;
    }

    try {
      const db = await this.openIndexedDb();
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(IDB_STORE_NAME, 'readwrite');
        const store = tx.objectStore(IDB_STORE_NAME);
        const req = store.put(record);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
      });
    } catch {
      // Fallback to in-memory cache if IndexedDB is blocked in private browsing
    }
  }

  private openIndexedDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(IDB_DB_NAME, 1);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(IDB_STORE_NAME)) {
          db.createObjectStore(IDB_STORE_NAME, { keyPath: 'alias' });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  private spkiBufferToPem(spkiBuffer: ArrayBuffer): string {
    const base64 = this.uint8ArrayToBase64(new Uint8Array(spkiBuffer));
    const lines = base64.match(/.{1,64}/g) ?? [base64];
    return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
  }

  public uint8ArrayToBase64(bytes: Uint8Array): string {
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(bytes).toString('base64');
    }
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  public base64ToUint8Array(base64: string): Uint8Array {
    if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(base64, 'base64'));
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  private toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  }
}
