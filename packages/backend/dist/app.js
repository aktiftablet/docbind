"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createApp = createApp;
const mime_js_1 = require("./utils/mime.js");
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const repository_js_1 = require("./db/repository.js");
const storage_js_1 = require("./storage/storage.js");
const redis_js_1 = require("./cache/redis.js");
const auth_js_1 = require("./middleware/auth.js");
const devices_js_1 = require("./routes/devices.js");
const documents_js_1 = require("./routes/documents.js");
function createApp(config = {}) {
    const repository = config.repository ?? new repository_js_1.InMemoryRepository(true);
    const storage = config.storage ?? new storage_js_1.InMemoryEncryptedStorage();
    const cache = config.cache ?? new redis_js_1.InMemoryCacheAdapter();
    const allowDefaultOrgFallback = config.allowDefaultOrgFallback ?? true;
    const app = (0, express_1.default)();
    app.disable('x-powered-by');
    app.use((0, cors_1.default)());
    app.use(express_1.default.json({ limit: Math.ceil(((0, mime_js_1.getHardUploadCapBytes)() * 4) / 3) + 1024 * 1024 }));
    app.use(express_1.default.urlencoded({ extended: true }));
    app.get('/health', (_req, res) => {
        res.status(200).json({
            status: 'ok',
            service: 'docbind-api',
            version: '1.0.0',
            crypto: {
                envelope: 'AES-256-GCM + RSA-OAEP-256',
                zero_disk_writes: true,
            },
        });
    });
    // Organization onboarding endpoint (for B2B tenant creation)
    app.post('/v1/organizations', async (req, res) => {
        const name = req.body?.name;
        if (!name || typeof name !== 'string') {
            res.status(400).json({ success: false, error: 'Organization name is required' });
            return;
        }
        const org = await repository.createOrganization(name.trim());
        res.status(201).json({
            success: true,
            organization: {
                id: org.id,
                name: org.name,
                api_key: org.api_key,
                createdAt: org.createdAt,
            },
        });
    });
    const authMiddleware = (0, auth_js_1.createAuthMiddleware)(repository, allowDefaultOrgFallback);
    app.use('/v1/devices', authMiddleware, (0, devices_js_1.createDeviceRouter)(repository, cache));
    app.use('/v1/documents', authMiddleware, (0, documents_js_1.createDocumentRouter)(repository, storage));
    // Oversize JSON (base64) bodies -> 413
    app.use((err, _req, res, next) => {
        if (err?.type === 'entity.too.large') {
            res.status(413).json({ success: false, error: 'Request body too large.', max_bytes: (0, mime_js_1.getHardUploadCapBytes)() });
            return;
        }
        next(err);
    });
    return { app, repository, storage, cache };
}
//# sourceMappingURL=app.js.map