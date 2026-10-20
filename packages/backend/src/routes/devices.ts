import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import type { DataRepository } from '../db/repository.js';
import type { CacheAdapter } from '../cache/redis.js';
import { EnvelopeCryptoService } from '../crypto/envelope.js';

const RegisterDeviceSchema = z
  .object({
    device_id: z.string().min(4).optional(),
    hardware_hash: z.string().min(4).optional(),
    public_key: z.string().min(64, 'PEM public_key is required'),
    metadata: z.record(z.unknown()).optional(),
  })
  .refine((data) => Boolean(data.device_id || data.hardware_hash), {
    message: 'Either device_id or hardware_hash must be provided',
    path: ['device_id'],
  });

export function createDeviceRouter(repo: DataRepository, cache?: CacheAdapter): Router {
  const router = Router();

  /**
   * POST /v1/devices/register
   * Registers a device fingerprint and stores its RSA Public Key (PEM).
   * Request: { device_id, public_key, metadata }
   * Response: { success, registered_device_id, hardware_hash, status }
   */
  router.post('/register', async (req: Request, res: Response) => {
    const parsed = RegisterDeviceSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: parsed.error.flatten().fieldErrors,
      });
      return;
    }

    const { device_id, hardware_hash, public_key, metadata } = parsed.data;
    const rawFingerprint = (hardware_hash || device_id)!;

    // Normalize fingerprint to deterministic SHA-256 hex if not already a 64-char hex digest
    const normalizedHardwareHash = /^[a-f0-9]{64}$/i.test(rawFingerprint)
      ? rawFingerprint.toLowerCase()
      : EnvelopeCryptoService.hashHardwareFingerprint(rawFingerprint);

    try {
      EnvelopeCryptoService.validateRsaPublicKey(public_key);
    } catch (err) {
      res.status(400).json({
        success: false,
        error: err instanceof Error ? err.message : 'Invalid RSA public key',
      });
      return;
    }

    const orgId = req.organization!.id;
    const device = await repo.upsertDevice({
      orgId,
      hardwareHash: normalizedHardwareHash,
      publicKey: public_key.trim(),
      metadata,
    });

    await cache?.set(`device:${device.id}`, device, 300);

    res.status(201).json({
      success: true,
      registered_device_id: device.id,
      hardware_hash: device.hardware_hash,
      status: device.status,
    });
  });

  /**
   * POST /v1/devices/:id/revoke
   * Revokes a registered device so it can no longer seal or fetch document payloads.
   */
  router.post('/:id/revoke', async (req: Request, res: Response) => {
    const device = await repo.findDeviceById(req.params.id);
    if (!device || device.org_id !== req.organization!.id) {
      res.status(404).json({
        success: false,
        error: 'Device not found',
      });
      return;
    }

    const updated = await repo.updateDeviceStatus(device.id, 'REVOKED');
    await cache?.del(`device:${device.id}`);

    res.status(200).json({
      success: true,
      registered_device_id: updated!.id,
      status: updated!.status,
    });
  });

  /**
   * GET /v1/devices/:id
   * Retrieves device metadata and active status.
   */
  router.get('/:id', async (req: Request, res: Response) => {
    const device = await repo.findDeviceById(req.params.id);
    if (!device || device.org_id !== req.organization!.id) {
      res.status(404).json({
        success: false,
        error: 'Device not found',
      });
      return;
    }

    res.status(200).json({
      success: true,
      device: {
        id: device.id,
        hardware_hash: device.hardware_hash,
        status: device.status,
        metadata: device.metadata,
        createdAt: device.createdAt,
      },
    });
  });

  return router;
}
