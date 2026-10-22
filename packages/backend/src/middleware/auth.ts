import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import type { DataRepository, OrganizationRecord } from '../db/repository.js';

export interface TokenClaims {
  role: 'device' | 'enrollment';
  orgId: string;
  subject: string;
  exp: number;
}

declare global {
  namespace Express {
    interface Request {
      organization?: OrganizationRecord;
      principal?: { role: 'admin' | 'device' | 'enrollment'; subject?: string };
    }
  }
}

export function secretsEqual(a: string, b: string): boolean {
  const hash = (s: string) => crypto.createHash('sha256').update(s).digest();
  return crypto.timingSafeEqual(hash(a), hash(b));
}

/** App-local signer; production must supply a persistent, randomly generated secret. */
export class TokenService {
  constructor(private readonly secret: string) {
    if (Buffer.byteLength(secret) < 32) throw new Error('TOKEN_SIGNING_SECRET must contain at least 32 bytes');
  }
  issue(role: TokenClaims['role'], orgId: string, subject: string, ttlSeconds = 3600): string {
    const body = Buffer.from(JSON.stringify({ role, orgId, subject, exp: Math.floor(Date.now() / 1000) + ttlSeconds })).toString('base64url');
    return `${body}.${this.sign(body)}`;
  }
  verify(token: string): TokenClaims | null {
    if (token.length > 4096) return null;
    const parts = token.split('.');
    if (parts.length !== 2 || !secretsEqual(parts[1], this.sign(parts[0]))) return null;
    try {
      const claims = JSON.parse(Buffer.from(parts[0], 'base64url').toString()) as TokenClaims;
      if (!['device', 'enrollment'].includes(claims.role) || typeof claims.orgId !== 'string' || typeof claims.subject !== 'string' || !Number.isSafeInteger(claims.exp) || claims.exp <= Date.now() / 1000) return null;
      return claims;
    } catch { return null; }
  }
  private sign(body: string): string {
    return crypto.createHmac('sha256', this.secret).update(body).digest('base64url');
  }
}

export function createAuthMiddleware(repo: DataRepository, tokens: TokenService) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const apiKey = req.get('x-api-key');
      if (apiKey) {
        const org = await repo.findOrgByApiKey(apiKey);
        if (org) {
          req.organization = org;
          req.principal = { role: 'admin' };
          next();
          return;
        }
      } else {
        const match = /^Bearer (\S+)$/i.exec(req.get('authorization') ?? '');
        const claims = match && tokens.verify(match[1]);
        if (claims) {
          const org = await repo.findOrgById(claims.orgId);
          const device = claims.role === 'device' ? await repo.findDeviceById(claims.subject) : null;
          if (org && (claims.role === 'enrollment' || (device?.org_id === org.id && device.status === 'ACTIVE'))) {
            req.organization = org;
            req.principal = { role: claims.role, subject: claims.subject };
            next();
            return;
          }
        }
      }
      res.status(401).json({ success: false, error: 'Valid credentials required.' });
    } catch (err) { next(err); }
  };
}

export function requireRole(...roles: Array<'admin' | 'device' | 'enrollment'>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.principal || !roles.includes(req.principal.role)) {
      res.status(403).json({ success: false, error: 'Insufficient permissions.' });
      return;
    }
    next();
  };
}
