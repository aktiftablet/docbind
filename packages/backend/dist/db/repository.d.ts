export interface PrismaClientLike {
    organization: {
        findUnique(args: {
            where: {
                api_key: string;
            };
        }): Promise<OrganizationRecord | null>;
        create(args: {
            data: {
                name: string;
                api_key: string;
            };
        }): Promise<OrganizationRecord>;
    };
    device: {
        upsert(args: unknown): Promise<unknown>;
        findUnique(args: {
            where: {
                id: string;
            };
        }): Promise<unknown>;
        update(args: {
            where: {
                id: string;
            };
            data: {
                status: DeviceStatus;
            };
        }): Promise<unknown>;
    };
    document: {
        create(args: {
            data: Record<string, unknown>;
        }): Promise<DocumentRecord>;
        findUnique(args: {
            where: {
                id: string;
            };
        }): Promise<DocumentRecord | null>;
    };
}
export type DeviceStatus = 'ACTIVE' | 'REVOKED';
export interface OrganizationRecord {
    id: string;
    api_key: string;
    name: string;
    createdAt: Date;
}
export interface DeviceRecord {
    id: string;
    org_id: string;
    hardware_hash: string;
    public_key: string;
    status: DeviceStatus;
    metadata?: Record<string, unknown> | null;
    createdAt: Date;
    updatedAt: Date;
}
export interface DocumentRecord {
    id: string;
    org_id: string;
    target_device_id: string;
    encrypted_dek: string;
    iv: string;
    auth_tag: string;
    storage_url: string;
    original_name?: string | null;
    mime_type: string;
    size_bytes?: number | null;
    createdAt: Date;
}
export interface DataRepository {
    findOrgByApiKey(apiKey: string): Promise<OrganizationRecord | null>;
    createOrganization(name: string, apiKey?: string): Promise<OrganizationRecord>;
    upsertDevice(params: {
        orgId: string;
        hardwareHash: string;
        publicKey: string;
        metadata?: Record<string, unknown>;
    }): Promise<DeviceRecord>;
    findDeviceById(deviceId: string): Promise<DeviceRecord | null>;
    updateDeviceStatus(deviceId: string, status: DeviceStatus): Promise<DeviceRecord | null>;
    createDocument(params: {
        id?: string;
        orgId: string;
        targetDeviceId: string;
        encryptedDek: string;
        iv: string;
        authTag: string;
        storageUrl: string;
        originalName?: string;
        mimeType?: string;
        sizeBytes?: number;
    }): Promise<DocumentRecord>;
    findDocumentById(documentId: string): Promise<DocumentRecord | null>;
}
/**
 * Prisma-backed repository for production PostgreSQL deployments.
 */
export declare class PrismaRepository implements DataRepository {
    private readonly prisma;
    constructor(prisma: PrismaClientLike);
    findOrgByApiKey(apiKey: string): Promise<OrganizationRecord | null>;
    createOrganization(name: string, apiKey?: string): Promise<OrganizationRecord>;
    upsertDevice(params: {
        orgId: string;
        hardwareHash: string;
        publicKey: string;
        metadata?: Record<string, unknown>;
    }): Promise<DeviceRecord>;
    findDeviceById(deviceId: string): Promise<DeviceRecord | null>;
    updateDeviceStatus(deviceId: string, status: DeviceStatus): Promise<DeviceRecord | null>;
    createDocument(params: {
        id?: string;
        orgId: string;
        targetDeviceId: string;
        encryptedDek: string;
        iv: string;
        authTag: string;
        storageUrl: string;
        originalName?: string;
        mimeType?: string;
        sizeBytes?: number;
    }): Promise<DocumentRecord>;
    findDocumentById(documentId: string): Promise<DocumentRecord | null>;
}
/**
 * In-memory repository implementing the exact Prisma schema semantics.
 * Automatically seeded with a default Organization so local development and E2E tests
 * run without requiring an external PostgreSQL daemon.
 */
export declare class InMemoryRepository implements DataRepository {
    private readonly organizations;
    private readonly devices;
    private readonly documents;
    static readonly DEFAULT_API_KEY = "docbind_dev_api_key_2026";
    static readonly DEFAULT_ORG_ID = "00000000-0000-4000-8000-000000000001";
    constructor(seedDefaultOrg?: boolean);
    findOrgByApiKey(apiKey: string): Promise<OrganizationRecord | null>;
    createOrganization(name: string, apiKey?: string): Promise<OrganizationRecord>;
    upsertDevice(params: {
        orgId: string;
        hardwareHash: string;
        publicKey: string;
        metadata?: Record<string, unknown>;
    }): Promise<DeviceRecord>;
    findDeviceById(deviceId: string): Promise<DeviceRecord | null>;
    updateDeviceStatus(deviceId: string, status: DeviceStatus): Promise<DeviceRecord | null>;
    createDocument(params: {
        id?: string;
        orgId: string;
        targetDeviceId: string;
        encryptedDek: string;
        iv: string;
        authTag: string;
        storageUrl: string;
        originalName?: string;
        mimeType?: string;
        sizeBytes?: number;
    }): Promise<DocumentRecord>;
    findDocumentById(documentId: string): Promise<DocumentRecord | null>;
}
//# sourceMappingURL=repository.d.ts.map