"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.InMemoryRepository = exports.PrismaRepository = void 0;
const node_crypto_1 = __importDefault(require("node:crypto"));
/**
 * Prisma-backed repository for production PostgreSQL deployments.
 */
class PrismaRepository {
    prisma;
    constructor(prisma) {
        this.prisma = prisma;
    }
    async findOrgByApiKey(apiKey) {
        return this.prisma.organization.findUnique({ where: { api_key: apiKey } });
    }
    async createOrganization(name, apiKey) {
        return this.prisma.organization.create({
            data: {
                name,
                api_key: apiKey ?? `db_live_${node_crypto_1.default.randomBytes(24).toString('hex')}`,
            },
        });
    }
    async upsertDevice(params) {
        const record = await this.prisma.device.upsert({
            where: {
                org_id_hardware_hash: {
                    org_id: params.orgId,
                    hardware_hash: params.hardwareHash,
                },
            },
            update: {
                public_key: params.publicKey,
                status: 'ACTIVE',
                metadata: (params.metadata ?? undefined),
            },
            create: {
                org_id: params.orgId,
                hardware_hash: params.hardwareHash,
                public_key: params.publicKey,
                status: 'ACTIVE',
                metadata: (params.metadata ?? undefined),
            },
        });
        return record;
    }
    async findDeviceById(deviceId) {
        const record = await this.prisma.device.findUnique({ where: { id: deviceId } });
        return record;
    }
    async updateDeviceStatus(deviceId, status) {
        const record = await this.prisma.device.update({
            where: { id: deviceId },
            data: { status },
        });
        return record;
    }
    async createDocument(params) {
        return this.prisma.document.create({
            data: {
                id: params.id,
                org_id: params.orgId,
                target_device_id: params.targetDeviceId,
                encrypted_dek: params.encryptedDek,
                iv: params.iv,
                auth_tag: params.authTag,
                storage_url: params.storageUrl,
                original_name: params.originalName,
                mime_type: params.mimeType ?? 'application/octet-stream',
                size_bytes: params.sizeBytes,
            },
        });
    }
    async findDocumentById(documentId) {
        return this.prisma.document.findUnique({ where: { id: documentId } });
    }
}
exports.PrismaRepository = PrismaRepository;
/**
 * In-memory repository implementing the exact Prisma schema semantics.
 * Automatically seeded with a default Organization so local development and E2E tests
 * run without requiring an external PostgreSQL daemon.
 */
class InMemoryRepository {
    organizations = new Map();
    devices = new Map();
    documents = new Map();
    static DEFAULT_API_KEY = 'docbind_dev_api_key_2026';
    static DEFAULT_ORG_ID = '00000000-0000-4000-8000-000000000001';
    constructor(seedDefaultOrg = true) {
        if (seedDefaultOrg) {
            const defaultOrg = {
                id: InMemoryRepository.DEFAULT_ORG_ID,
                api_key: process.env.DEFAULT_ORG_API_KEY || InMemoryRepository.DEFAULT_API_KEY,
                name: 'Default B2B Organization',
                createdAt: new Date(),
            };
            this.organizations.set(defaultOrg.id, defaultOrg);
        }
    }
    async findOrgByApiKey(apiKey) {
        for (const org of this.organizations.values()) {
            if (org.api_key === apiKey) {
                return org;
            }
        }
        return null;
    }
    async createOrganization(name, apiKey) {
        const org = {
            id: node_crypto_1.default.randomUUID(),
            api_key: apiKey ?? `db_live_${node_crypto_1.default.randomBytes(24).toString('hex')}`,
            name,
            createdAt: new Date(),
        };
        this.organizations.set(org.id, org);
        return org;
    }
    async upsertDevice(params) {
        for (const existing of this.devices.values()) {
            if (existing.org_id === params.orgId && existing.hardware_hash === params.hardwareHash) {
                existing.public_key = params.publicKey;
                existing.status = 'ACTIVE';
                existing.metadata = params.metadata ?? existing.metadata;
                existing.updatedAt = new Date();
                return existing;
            }
        }
        const now = new Date();
        const record = {
            id: node_crypto_1.default.randomUUID(),
            org_id: params.orgId,
            hardware_hash: params.hardwareHash,
            public_key: params.publicKey,
            status: 'ACTIVE',
            metadata: params.metadata ?? null,
            createdAt: now,
            updatedAt: now,
        };
        this.devices.set(record.id, record);
        return record;
    }
    async findDeviceById(deviceId) {
        return this.devices.get(deviceId) ?? null;
    }
    async updateDeviceStatus(deviceId, status) {
        const device = this.devices.get(deviceId);
        if (!device)
            return null;
        device.status = status;
        device.updatedAt = new Date();
        return device;
    }
    async createDocument(params) {
        const record = {
            id: params.id ?? node_crypto_1.default.randomUUID(),
            org_id: params.orgId,
            target_device_id: params.targetDeviceId,
            encrypted_dek: params.encryptedDek,
            iv: params.iv,
            auth_tag: params.authTag,
            storage_url: params.storageUrl,
            original_name: params.originalName ?? null,
            mime_type: params.mimeType ?? 'application/octet-stream',
            size_bytes: params.sizeBytes ?? null,
            createdAt: new Date(),
        };
        this.documents.set(record.id, record);
        return record;
    }
    async findDocumentById(documentId) {
        return this.documents.get(documentId) ?? null;
    }
}
exports.InMemoryRepository = InMemoryRepository;
//# sourceMappingURL=repository.js.map