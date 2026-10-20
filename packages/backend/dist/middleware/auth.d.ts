import type { Request, Response, NextFunction } from 'express';
import { type DataRepository, type OrganizationRecord } from '../db/repository.js';
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
export declare function createAuthMiddleware(repo: DataRepository, allowDefaultFallback?: boolean): (req: Request, res: Response, next: NextFunction) => Promise<void>;
//# sourceMappingURL=auth.d.ts.map