import type { Request, Response, NextFunction } from 'express';
import { InMemoryRepository, type DataRepository, type OrganizationRecord } from '../db/repository.js';

declare global {
  namespace Express {
    interface Request {
      organization?: OrganizationRecord;
    }
  }
}

/**
 * Resolves the Organization from `x-api-key` or `Authorization: Bearer <api_key>`.
 * Falls back to the default development organization if `ALLOW_DEFAULT_ORG_FALLBACK` is not disabled,
 * enabling zero-config SDK quickstarts while enforcing strict API keys when provided.
 */
export function createAuthMiddleware(repo: DataRepository, allowDefaultFallback = true) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const headerApiKey =
        (req.headers['x-api-key'] as string | undefined) ||
        extractBearerToken(req.headers.authorization);

      const apiKeyToLookup =
        headerApiKey || (allowDefaultFallback ? InMemoryRepository.DEFAULT_API_KEY : undefined);

      if (!apiKeyToLookup) {
        res.status(401).json({
          success: false,
          error: 'Missing API key. Provide x-api-key header or Authorization Bearer token.',
        });
        return;
      }

      const org = await repo.findOrgByApiKey(apiKeyToLookup);
      if (!org) {
        res.status(401).json({
          success: false,
          error: 'Invalid API key.',
        });
        return;
      }

      req.organization = org;
      next();
    } catch (err) {
      next(err);
    }
  };
}

function extractBearerToken(authHeader?: string): string | undefined {
  if (!authHeader) return undefined;
  const parts = authHeader.split(' ');
  if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
    return parts[1];
  }
  return undefined;
}
