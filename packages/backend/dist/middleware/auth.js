"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAuthMiddleware = createAuthMiddleware;
const repository_js_1 = require("../db/repository.js");
/**
 * Resolves the Organization from `x-api-key` or `Authorization: Bearer <api_key>`.
 * Falls back to the default development organization if `ALLOW_DEFAULT_ORG_FALLBACK` is not disabled,
 * enabling zero-config SDK quickstarts while enforcing strict API keys when provided.
 */
function createAuthMiddleware(repo, allowDefaultFallback = true) {
    return async (req, res, next) => {
        try {
            const headerApiKey = req.headers['x-api-key'] ||
                extractBearerToken(req.headers.authorization);
            const apiKeyToLookup = headerApiKey || (allowDefaultFallback ? repository_js_1.InMemoryRepository.DEFAULT_API_KEY : undefined);
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
        }
        catch (err) {
            next(err);
        }
    };
}
function extractBearerToken(authHeader) {
    if (!authHeader)
        return undefined;
    const parts = authHeader.split(' ');
    if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
        return parts[1];
    }
    return undefined;
}
//# sourceMappingURL=auth.js.map