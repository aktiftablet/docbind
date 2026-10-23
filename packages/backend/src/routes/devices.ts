import { asyncHandler } from '../middleware/async.js';
import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import type { DataRepository } from '../db/repository.js';
import { EnvelopeCryptoService, KEY_ALGORITHMS } from '../crypto/envelope.js';
import { requireRole, type TokenService } from '../middleware/auth.js';

const PublicKeySchema = z.object({ public_key: z.string().min(64).max(8192) });
const RegisterSchema = PublicKeySchema.extend({
  device_id: z.string().min(4).max(256).optional(),
  hardware_hash: z.string().min(4).max(256).optional(),
  key_algorithm: z.enum(KEY_ALGORITHMS).default('RSA-OAEP-256'),
  metadata: z.record(z.unknown()).optional(),
});

export function createDeviceRouter(repo: DataRepository, tokens: TokenService): Router {
  const router = Router();

  // Trusted application server authorizes one public key, never the whole organization.
  router.post('/enrollment-tokens', requireRole('admin'), (req: Request, res: Response) => {
    const parsed = PublicKeySchema.safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ error: 'Valid public_key required' }); return; }
    try {
      EnvelopeCryptoService.validateRsaPublicKey(parsed.data.public_key);
      const fingerprint = EnvelopeCryptoService.publicKeyFingerprint(parsed.data.public_key);
      res.status(201).json({ enrollment_token: tokens.issue('enrollment', req.organization!.id, fingerprint, 300), expires_in: 300 });
    } catch { res.status(400).json({ error: 'Invalid RSA public key' }); }
  });

  router.post('/register', requireRole('admin', 'enrollment', 'device'), asyncHandler(async (req: Request, res: Response) => {
    const parsed = RegisterSchema.safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ success: false, error: 'Invalid device registration' }); return; }
    const { public_key, hardware_hash, device_id, key_algorithm, metadata } = parsed.data;
    let fingerprint: string;
    try {
      EnvelopeCryptoService.validateRsaPublicKey(public_key);
      fingerprint = EnvelopeCryptoService.publicKeyFingerprint(public_key);
    } catch { res.status(400).json({ error: 'Invalid RSA public key' }); return; }
    const principal = req.principal!;
    if (principal.role === 'enrollment' && principal.subject !== fingerprint) {
      res.status(403).json({ error: 'Enrollment is bound to a different public key' }); return;
    }
    if (principal.role === 'device') {
      const current = await repo.findDeviceById(principal.subject!);
      if (current?.public_key_fingerprint !== fingerprint || current.key_algorithm !== key_algorithm) {
        res.status(403).json({ error: 'Device identity is immutable' }); return;
      }
    }
    const { device, created } = await repo.registerDevice({
      orgId: req.organization!.id,
      hardwareHash: EnvelopeCryptoService.hashHardwareFingerprint(hardware_hash ?? device_id ?? fingerprint),
      publicKey: public_key.trim(), publicKeyFingerprint: fingerprint, keyAlgorithm: key_algorithm, metadata,
    });
    if (device.status !== 'ACTIVE') { res.status(403).json({ error: 'Revoked devices cannot re-enroll' }); return; }
    if (device.key_algorithm !== key_algorithm) { res.status(409).json({ error: 'Device algorithm is immutable' }); return; }
    res.status(created ? 201 : 200).json({
      success: true, registered_device_id: device.id, status: device.status,
      device_token: tokens.issue('device', device.org_id, device.id), expires_in: 3600,
    });
  }));

  router.post('/:id/revoke', requireRole('admin'), asyncHandler(async (req: Request, res: Response) => {
    const device = await repo.findDeviceById(req.params.id);
    if (!device || device.org_id !== req.organization!.id) { res.status(404).json({ error: 'Device not found' }); return; }
    await repo.updateDeviceStatus(device.id, 'REVOKED');
    res.json({ success: true, registered_device_id: device.id, status: 'REVOKED' });
  }));

  router.get('/:id', requireRole('admin', 'device'), asyncHandler(async (req: Request, res: Response) => {
    const device = await repo.findDeviceById(req.params.id);
    if (!device || device.org_id !== req.organization!.id || (req.principal!.role === 'device' && req.principal!.subject !== device.id)) {
      res.status(404).json({ error: 'Device not found' }); return;
    }
    res.json({ success: true, device: { id: device.id, status: device.status, metadata: device.metadata, createdAt: device.createdAt } });
  }));
  return router;
}
