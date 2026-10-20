import crypto from 'node:crypto';

export interface PrismaClientLike {
  organization: {
    findUnique(args: { where: { api_key: string } }): Promise<OrganizationRecord | null>;
    create(args: { data: { name: string; api_key: string } }): Promise<OrganizationRecord>;
  };
  device: {
    upsert(args: unknown): Promise<unknown>;
    findUnique(args: { where: { id: string } }): Promise<unknown>;
    update(args: { where: { id: string }; data: { status: DeviceStatus } }): Promise<unknown>;
  };
  document: {
    create(args: { data: Record<string, unknown> }): Promise<DocumentRecord>;
    findUnique(args: { where: { id: string } }): Promise<DocumentRecord | null>;
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
export class PrismaRepository implements DataRepository {
  constructor(private readonly prisma: PrismaClientLike) {}

  async findOrgByApiKey(apiKey: string): Promise<OrganizationRecord | null> {
    return this.prisma.organization.findUnique({ where: { api_key: apiKey } });
  }

  async createOrganization(name: string, apiKey?: string): Promise<OrganizationRecord> {
    return this.prisma.organization.create({
      data: {
        name,
        api_key: apiKey ?? `db_live_${crypto.randomBytes(24).toString('hex')}`,
      },
    });
  }

  async upsertDevice(params: {
    orgId: string;
    hardwareHash: string;
    publicKey: string;
    metadata?: Record<string, unknown>;
  }): Promise<DeviceRecord> {
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
        metadata: (params.metadata ?? undefined) as any,
      },
      create: {
        org_id: params.orgId,
        hardware_hash: params.hardwareHash,
        public_key: params.publicKey,
        status: 'ACTIVE',
        metadata: (params.metadata ?? undefined) as any,
      },
    });
    return record as unknown as DeviceRecord;
  }

  async findDeviceById(deviceId: string): Promise<DeviceRecord | null> {
    const record = await this.prisma.device.findUnique({ where: { id: deviceId } });
    return record as unknown as DeviceRecord | null;
  }

  async updateDeviceStatus(deviceId: string, status: DeviceStatus): Promise<DeviceRecord | null> {
    const record = await this.prisma.device.update({
      where: { id: deviceId },
      data: { status },
    });
    return record as unknown as DeviceRecord;
  }

  async createDocument(params: {
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
  }): Promise<DocumentRecord> {
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
        mime_type: params.mimeType ?? 'application/pdf',
        size_bytes: params.sizeBytes,
      },
    });
  }

  async findDocumentById(documentId: string): Promise<DocumentRecord | null> {
    return this.prisma.document.findUnique({ where: { id: documentId } });
  }
}

/**
 * In-memory repository implementing the exact Prisma schema semantics.
 * Automatically seeded with a default Organization so local development and E2E tests
 * run without requiring an external PostgreSQL daemon.
 */
export class InMemoryRepository implements DataRepository {
  private readonly organizations = new Map<string, OrganizationRecord>();
  private readonly devices = new Map<string, DeviceRecord>();
  private readonly documents = new Map<string, DocumentRecord>();

  public static readonly DEFAULT_API_KEY = 'docbind_dev_api_key_2026';
  public static readonly DEFAULT_ORG_ID = '00000000-0000-4000-8000-000000000001';

  constructor(seedDefaultOrg = true) {
    if (seedDefaultOrg) {
      const defaultOrg: OrganizationRecord = {
        id: InMemoryRepository.DEFAULT_ORG_ID,
        api_key: process.env.DEFAULT_ORG_API_KEY || InMemoryRepository.DEFAULT_API_KEY,
        name: 'Default B2B Organization',
        createdAt: new Date(),
      };
      this.organizations.set(defaultOrg.id, defaultOrg);
    }
  }

  async findOrgByApiKey(apiKey: string): Promise<OrganizationRecord | null> {
    for (const org of this.organizations.values()) {
      if (org.api_key === apiKey) {
        return org;
      }
    }
    return null;
  }

  async createOrganization(name: string, apiKey?: string): Promise<OrganizationRecord> {
    const org: OrganizationRecord = {
      id: crypto.randomUUID(),
      api_key: apiKey ?? `db_live_${crypto.randomBytes(24).toString('hex')}`,
      name,
      createdAt: new Date(),
    };
    this.organizations.set(org.id, org);
    return org;
  }

  async upsertDevice(params: {
    orgId: string;
    hardwareHash: string;
    publicKey: string;
    metadata?: Record<string, unknown>;
  }): Promise<DeviceRecord> {
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
    const record: DeviceRecord = {
      id: crypto.randomUUID(),
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

  async findDeviceById(deviceId: string): Promise<DeviceRecord | null> {
    return this.devices.get(deviceId) ?? null;
  }

  async updateDeviceStatus(deviceId: string, status: DeviceStatus): Promise<DeviceRecord | null> {
    const device = this.devices.get(deviceId);
    if (!device) return null;
    device.status = status;
    device.updatedAt = new Date();
    return device;
  }

  async createDocument(params: {
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
  }): Promise<DocumentRecord> {
    const record: DocumentRecord = {
      id: params.id ?? crypto.randomUUID(),
      org_id: params.orgId,
      target_device_id: params.targetDeviceId,
      encrypted_dek: params.encryptedDek,
      iv: params.iv,
      auth_tag: params.authTag,
      storage_url: params.storageUrl,
      original_name: params.originalName ?? null,
      mime_type: params.mimeType ?? 'application/pdf',
      size_bytes: params.sizeBytes ?? null,
      createdAt: new Date(),
    };
    this.documents.set(record.id, record);
    return record;
  }

  async findDocumentById(documentId: string): Promise<DocumentRecord | null> {
    return this.documents.get(documentId) ?? null;
  }
}
