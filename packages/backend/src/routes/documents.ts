import crypto from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import multer from 'multer';
import type { DataRepository } from '../db/repository.js';
import type { StorageAdapter } from '../storage/storage.js';
import { EnvelopeCryptoService } from '../crypto/envelope.js';
import { getHardUploadCapBytes, getMaxBytesForMime, resolveMimeType } from '../utils/mime.js';

/**
 * Use Multer memoryStorage strictly so uploaded plaintext files (documents, images, video, audio)
 * never touch the server's disk.
 */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    // Transport cap = largest category limit; per-category limits are enforced after MIME resolution.
    fileSize: getHardUploadCapBytes(),
  },
});

/** Wraps Multer so oversize uploads return 413 instead of a generic 500. */
function uploadSingle(field: string) {
  const handler = upload.single(field);
  return (req: Request, res: Response, next: (err?: unknown) => void): void => {
    handler(req, res, (err?: unknown) => {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        res.status(413).json({
          success: false,
          error: 'File too large.',
          max_bytes: getHardUploadCapBytes(),
        });
        return;
      }
      next(err);
    });
  };
}

export function createDocumentRouter(
  repo: DataRepository,
  storage: StorageAdapter
): Router {
  const router = Router();

  /**
   * POST /v1/documents/seal
   * Encrypts any file (PDF, Office, image, video, audio, ...) in-memory for a specific target device using Envelope Encryption.
   * Request: multipart/form-data (file + target_device_id)
   * Logic: Generate AES-256-GCM DEK -> Encrypt File in RAM -> Encrypt DEK with Device RSA-OAEP Public Key -> Store & Return.
   */
  router.post(
    '/seal',
    uploadSingle('file'),
    async (req: Request, res: Response): Promise<void> => {
      try {
        const targetDeviceId = req.body?.target_device_id as string | undefined;
        if (!targetDeviceId || typeof targetDeviceId !== 'string') {
          res.status(400).json({
            success: false,
            error: 'Missing required field: target_device_id',
          });
          return;
        }

        // Support multipart file upload or base64 buffer in JSON body
        let fileBuffer: Buffer | undefined = req.file?.buffer;
        let originalName: string | undefined = req.file?.originalname;
        let declaredMime: string | undefined = req.file?.mimetype;

        if (!fileBuffer && typeof req.body?.file_base64 === 'string') {
          fileBuffer = Buffer.from(req.body.file_base64, 'base64');
          originalName = req.body.filename ?? originalName;
          declaredMime = req.body.mime_type ?? declaredMime;
        }

        if (!fileBuffer || fileBuffer.length === 0) {
          res.status(400).json({
            success: false,
            error: 'Missing document file. Upload via multipart/form-data field "file".',
          });
          return;
        }

        const mimeType = resolveMimeType(fileBuffer, declaredMime, originalName);
        originalName = originalName ?? 'document';

        // Single-block AES-GCM => whole file must fit in client RAM. Enforce per-category limit.
        const maxBytes = getMaxBytesForMime(mimeType);
        if (fileBuffer.length > maxBytes) {
          fileBuffer.fill(0);
          res.status(413).json({
            success: false,
            error: `File too large for ${mimeType}: ${fileBuffer.length} bytes exceeds limit of ${maxBytes} bytes.`,
            mime_type: mimeType,
            max_bytes: maxBytes,
          });
          return;
        }

        const device = await repo.findDeviceById(targetDeviceId);
        if (!device || device.org_id !== req.organization!.id) {
          res.status(404).json({
            success: false,
            error: `Target device not found: ${targetDeviceId}`,
          });
          return;
        }

        if (device.status !== 'ACTIVE') {
          res.status(403).json({
            success: false,
            error: `Target device ${targetDeviceId} is ${device.status} and cannot receive sealed documents.`,
          });
          return;
        }

        const documentId = crypto.randomUUID();

        // Perform Envelope Encryption in RAM
        const sealed = EnvelopeCryptoService.sealDocument(
          fileBuffer,
          device.public_key,
          device.id
        );

        // Zero out plaintext upload buffer immediately after encryption
        fileBuffer.fill(0);

        const storageUrl = await storage.putEncryptedBlob(
          documentId,
          req.organization!.id,
          sealed.encryptedDocument
        );

        const docRecord = await repo.createDocument({
          id: documentId,
          orgId: req.organization!.id,
          targetDeviceId: device.id,
          encryptedDek: sealed.encryptedDek,
          iv: sealed.iv,
          authTag: sealed.authTag,
          storageUrl,
          originalName,
          mimeType,
          sizeBytes: sealed.encryptedDocument.length,
        });

        res.status(201).json({
          success: true,
          document_id: docRecord.id,
          target_device_id: docRecord.target_device_id,
          encrypted_dek: docRecord.encrypted_dek,
          iv: docRecord.iv,
          auth_tag: docRecord.auth_tag,
          storage_url: docRecord.storage_url,
          payload_url: `/v1/documents/${docRecord.id}/payload`,
          encrypted_document: sealed.encryptedDocument.toString('base64'),
        });
      } catch (err) {
        res.status(500).json({
          success: false,
          error: err instanceof Error ? err.message : 'Failed to seal document',
        });
      }
    }
  );

  /**
   * GET /v1/documents/:id/payload
   * Fetches the encrypted document payload and wrapped DEK for the target device SDK.
   * Optionally verifies `x-device-hardware-hash` header if provided by the client SDK.
   */
  router.get('/:id/payload', async (req: Request, res: Response): Promise<void> => {
    try {
      const document = await repo.findDocumentById(req.params.id);
      if (!document || document.org_id !== req.organization!.id) {
        res.status(404).json({
          success: false,
          error: 'Document not found',
        });
        return;
      }

      const device = await repo.findDeviceById(document.target_device_id);
      if (!device || device.status !== 'ACTIVE') {
        res.status(403).json({
          success: false,
          error: 'Target device is revoked or inactive. Decryption payload denied.',
        });
        return;
      }

      // If client SDK sends its hardware fingerprint hash or device ID header, enforce match
      const requestingDeviceId = req.headers['x-device-id'] as string | undefined;
      if (requestingDeviceId && requestingDeviceId !== device.id) {
        res.status(403).json({
          success: false,
          error: 'Device ID mismatch: document is bound to a different hardware device.',
        });
        return;
      }

      const requestingHardwareHash = req.headers['x-hardware-hash'] as string | undefined;
      if (requestingHardwareHash) {
        const normalizedReqHash = /^[a-f0-9]{64}$/i.test(requestingHardwareHash)
          ? requestingHardwareHash.toLowerCase()
          : EnvelopeCryptoService.hashHardwareFingerprint(requestingHardwareHash);

        if (normalizedReqHash !== device.hardware_hash) {
          res.status(403).json({
            success: false,
            error: 'Hardware fingerprint mismatch: unauthorized device.',
          });
          return;
        }
      }

      const encryptedBlob = await storage.getEncryptedBlob(document.storage_url);

      // Prevent caching of sensitive encrypted payloads on intermediaries
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
      // Lets the SDK reject oversize payloads before buffering the body into RAM.
      res.setHeader('X-DocBind-Size-Bytes', String(encryptedBlob.length));
      res.setHeader('X-DocBind-Mime-Type', document.mime_type);
      res.setHeader('Access-Control-Expose-Headers', 'X-DocBind-Size-Bytes, X-DocBind-Mime-Type');

      res.status(200).json({
        success: true,
        document_id: document.id,
        target_device_id: document.target_device_id,
        mime_type: document.mime_type,
        original_name: document.original_name,
        size_bytes: encryptedBlob.length,
        encrypted_dek: document.encrypted_dek,
        iv: document.iv,
        auth_tag: document.auth_tag,
        encrypted_document: encryptedBlob.toString('base64'),
        algorithm: {
          document_cipher: 'AES-256-GCM',
          key_encryption: 'RSA-OAEP-256',
          aad_binding: 'target_device_id',
        },
      });
    } catch (err) {
      res.status(500).json({
        success: false,
        error: err instanceof Error ? err.message : 'Failed to fetch document payload',
      });
    }
  });

  return router;
}
