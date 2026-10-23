import crypto from 'node:crypto';
import { requireRole } from '../middleware/auth.js';
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
    files: 1, fields: 4, parts: 5, fieldSize: 8192, fieldNameSize: 100,
  },
});

/** Wraps Multer so oversize uploads return 413 instead of a generic 500. */
function uploadSingle(field: string) {
  const handler = upload.single(field);
  return (req: Request, res: Response, next: (err?: unknown) => void): void => {
    handler(req, res, (err?: unknown) => {
      if (err instanceof multer.MulterError) {
        res.status(413).json({
          success: false,
          error: 'File too large.',
          max_bytes: getHardUploadCapBytes(),
        });
        return;
      }
      if (err) { res.status(400).json({ error: 'Malformed multipart upload' }); return; }
      next();
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
    requireRole('admin'),
    uploadSingle('file'),
    async (req: Request, res: Response): Promise<void> => {
      let fileBuffer: Buffer | undefined;
      let uncommittedStorageUrl: string | undefined;
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
        fileBuffer = req.file?.buffer;
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
          { targetDeviceId: device.id, documentId, mimeType },
          device.key_algorithm
        );

        // Zero out plaintext upload buffer immediately after encryption
        fileBuffer.fill(0);

        const storageUrl = await storage.putEncryptedBlob(
          documentId,
          req.organization!.id,
          sealed.encryptedDocument
        );

        uncommittedStorageUrl = storageUrl;
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
          encryptedSizeBytes: sealed.encryptedDocument.length,
          aadVersion: sealed.aadVersion,
          keyAlgorithm: sealed.keyAlgorithm,
        });

        uncommittedStorageUrl = undefined;
        res.status(201).json({
          success: true,
          document_id: docRecord.id,
          target_device_id: docRecord.target_device_id,
          aad_version: docRecord.aad_version,
          key_algorithm: docRecord.key_algorithm,
          encrypted_dek: docRecord.encrypted_dek,
          iv: docRecord.iv,
          auth_tag: docRecord.auth_tag,
          storage_url: docRecord.storage_url,
          payload_url: `/v1/documents/${docRecord.id}/payload`,
          encrypted_document: sealed.encryptedDocument.toString('base64'),
        });
      } catch (err) {
        if (uncommittedStorageUrl) await storage.deleteEncryptedBlob(uncommittedStorageUrl).catch(() => {});
        res.status(500).json({
          success: false,
          error: 'Failed to seal document',
        });
      } finally {
        fileBuffer?.fill(0);
        req.file?.buffer.fill(0);
        if (req.body) delete req.body.file_base64;
      }
    }
  );

  /**
   * GET /v1/documents/:id/payload
   * Fetches the encrypted document payload and wrapped DEK for the target device SDK.
   * Requires an active, device-scoped bearer token matching the target device.
   */
  router.get('/:id/payload', requireRole('device'), async (req: Request, res: Response): Promise<void> => {
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

      if (req.principal!.subject !== document.target_device_id) {
        res.status(403).json({ error: 'Document belongs to a different device' });
        return;
      }
      if (document.expires_at && document.expires_at <= new Date()) {
        res.status(410).json({ error: 'Document expired' });
        return;
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
        aad_version: document.aad_version,
        key_algorithm: document.key_algorithm,
        encrypted_dek: document.encrypted_dek,
        iv: document.iv,
        auth_tag: document.auth_tag,
        encrypted_document: encryptedBlob.toString('base64'),
        algorithm: {
          document_cipher: 'AES-256-GCM',
          key_encryption: document.key_algorithm,
          aad_binding: document.aad_version,
        },
      });
    } catch (err) {
      res.status(500).json({
        success: false,
        error: 'Failed to fetch document payload',
      });
    }
  });

  return router;
}
