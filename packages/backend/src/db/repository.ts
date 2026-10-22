import crypto from 'node:crypto';
import type { AadVersion, KeyAlgorithm } from '../crypto/envelope.js';

export type DeviceStatus = 'ACTIVE' | 'REVOKED';

export type AccessAction = 'SEAL' | 'PAYLOAD_FETCH' | 'DELETE';
export type AccessOutcome = 'GRANTED' | 'DENIED';

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
  /** SHA-256 (hex) of the DER SPKI public key. Device identity within an org. */
  public_key_fingerprint: string;
  key_algorithm: KeyAlgorithm;
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
  /** Size of the stored ciphertext (plaintext + 16-byte GCM tag). */
  encrypted_size_bytes?: number | null;
  aad_version: AadVersion;
  key_algorithm: KeyAlgorithm;
  expires_at?: Date | null;
  createdAt: Date;
}

export interface AccessEventRecord {
  id: string;
  org_id: string;
  document_id: string | null;
  device_id: string | null;
  action: AccessAction;
  outcome: AccessOutcome;
  reason?: string | null;
  ip?: string | null;
  user_agent?: string | null;
  request_id?: string | null;
  createdAt: Date;
}

export interface RegisterDeviceParams {
  orgId: string;
  hardwareHash: string;
  publicKey: string;
  publicKeyFingerprint: string;
  keyAlgorithm: KeyAlgorithm;
  metadata?: Record<string, unknown>;
}

export interface CreateDocumentParams {
  id?: string;
  orgId: string;
  targetDeviceId: string;
  encryptedDek: string;
  iv: string;
  authTag: string;
  storageUrl: string;
  originalName?: string;
  mimeType?: string;
  encryptedSizeBytes?: number;
  aadVersion: AadVersion;
  keyAlgorithm: KeyAlgorithm;
  expiresAt?: Date | null;
}

export type RecordAccessEventParams = Omit<AccessEventRecord, 'id' | 'createdAt'>;

export interface DataRepository {
  findOrgByApiKey(apiKey: string): Promise<OrganizationRecord | null>;
  findOrgById(id: string): Promise<OrganizationRecord | null>;
  createOrganization(name: string, apiKey?: string): Promise<OrganizationRecord>;
  /**
   * Registers a device identified by `(orgId, publicKeyFingerprint)`.
   * If the key is already registered, the existing record is returned **unchanged**:
   * the public key can never be replaced and a REVOKED device is never re-activated.
   */
  registerDevice(params: RegisterDeviceParams): Promise<{ device: DeviceRecord; created: boolean }>;
  findDeviceById(deviceId: string): Promise<DeviceRecord | null>;
  updateDeviceStatus(deviceId: string, status: DeviceStatus): Promise<DeviceRecord | null>;
  createDocument(params: CreateDocumentParams): Promise<DocumentRecord>;
  findDocumentById(documentId: string): Promise<DocumentRecord | null>;
  deleteDocument(documentId: string): Promise<void>;
  recordAccessEvent(event: RecordAccessEventParams): Promise<void>;
  listAccessEvents(documentId: string): Promise<AccessEventRecord[]>;
}

/** Minimal structural type of the generated Prisma client used by {@link PrismaRepository}. */
export interface PrismaClientLike {
  organization: {
    findUnique(args: { where: { api_key?: string; id?: string } }): Promise<OrganizationRecord | null>;
    create(args: { data: { name: string; api_key: string } }): Promise<OrganizationRecord>;
  };
  device: {
    create(args: { data: Record<string, unknown> }): Promise<unknown>;
    findUnique(args: { where: Record<string, unknown> }): Promise<unknown>;
    update(args: { where: { id: string }; data: { status: DeviceStatus } }): Promise<unknown>;
  };
  document: {
    create(args: { data: Record<string, unknown> }): Promise<unknown>;
    findUnique(args: { where: { id: string } }): Promise<unknown>;
    delete(args: { where: { id: string } }): Promise<unknown>;
  };
  accessEvent: {
    create(args: { data: Record<string, unknown> }): Promise<unknown>;
    findMany(args: { where: { document_id: string }; orderBy: { createdAt: 'asc' } }): Promise<unknown[]>;
  };
}

function generateApiKey(): string {
  return `db_live_${crypto.randomBytes(24).toString('hex')}`;
}

function isUniqueConstraintError(err: unknown): boolean {
  return (err as { code?: string })?.code === 'P2002';
}

/**
 * Prisma-backed repository for production PostgreSQL deployments.
 */
export class PrismaRepository implements DataRepository {
  constructor(private readonly prisma: PrismaClientLike) {}

  async findOrgByApiKey(apiKey: string): Promise<OrganizationRecord | null> {
    return this.prisma.organization.findUnique({ where: { api_key: apiKey } });
  }

  async findOrgById(id: string): Promise<OrganizationRecord | null> {
    return this.prisma.organization.findUnique({ where: { id } });
  }

  async createOrganization(name: string, apiKey?: string): Promise<OrganizationRecord> {
    return this.prisma.organization.create({
      data: { name, api_key: apiKey ?? generateApiKey() },
    });
  }

  private async findDeviceByFingerprint(orgId: string, fingerprint: string): Promise<DeviceRecord | null> {
    const record = await this.prisma.device.findUnique({
      where: { org_id_public_key_fingerprint: { org_id: orgId, public_key_fingerprint: fingerprint } },
    });
    return (record as DeviceRecord | null) ?? null;
  }

  async registerDevice(params: RegisterDeviceParams): Promise<{ device: DeviceRecord; created: boolean }> {
    const existing = await this.findDeviceByFingerprint(params.orgId, params.publicKeyFingerprint);
    if (existing) return { device: existing, created: false };

    try {
      const record = await this.prisma.device.create({
        data: {
          org_id: params.orgId,
          hardware_hash: params.hardwareHash,
          public_key: params.publicKey,
          public_key_fingerprint: params.publicKeyFingerprint,
          key_algorithm: params.keyAlgorithm,
          status: 'ACTIVE',
          metadata: params.metadata ?? undefined,
        },
      });
      return { device: record as DeviceRecord, created: true };
    } catch (err) {
      // Concurrent registration of the same key: return the winner's record.
      if (isUniqueConstraintError(err)) {
        const winner = await this.findDeviceByFingerprint(params.orgId, params.publicKeyFingerprint);
        if (winner) return { device: winner, created: false };
      }
      throw err;
    }
  }

  async findDeviceById(deviceId: string): Promise<DeviceRecord | null> {
    const record = await this.prisma.device.findUnique({ where: { id: deviceId } });
    return (record as DeviceRecord | null) ?? null;
  }

  async updateDeviceStatus(deviceId: string, status: DeviceStatus): Promise<DeviceRecord | null> {
    const record = await this.prisma.device.update({ where: { id: deviceId }, data: { status } });
    return record as DeviceRecord;
  }

  async createDocument(params: CreateDocumentParams): Promise<DocumentRecord> {
    const record = await this.prisma.document.create({
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
        encrypted_size_bytes: params.encryptedSizeBytes,
        aad_version: params.aadVersion,
        key_algorithm: params.keyAlgorithm,
        expires_at: params.expiresAt ?? null,
      },
    });
    return record as DocumentRecord;
  }

  async findDocumentById(documentId: string): Promise<DocumentRecord | null> {
    const record = await this.prisma.document.findUnique({ where: { id: documentId } });
    return (record as DocumentRecord | null) ?? null;
  }

  async deleteDocument(documentId: string): Promise<void> {
    await this.prisma.document.delete({ where: { id: documentId } });
  }

  async recordAccessEvent(event: RecordAccessEventParams): Promise<void> {
    await this.prisma.accessEvent.create({ data: { ...event } });
  }

  async listAccessEvents(documentId: string): Promise<AccessEventRecord[]> {
    const rows = await this.prisma.accessEvent.findMany({
      where: { document_id: documentId },
      orderBy: { createdAt: 'asc' },
    });
    return rows as AccessEventRecord[];
  }
}

/**
 * In-memory repository implementing the Prisma schema semantics.
 * Automatically seeded with a default Organization so local development and E2E tests
 * run without requiring an external PostgreSQL daemon. Data is lost on restart.
 */
export class InMemoryRepository implements DataRepository {
  private readonly organizations = new Map<string, OrganizationRecord>();
  private readonly devices = new Map<string, DeviceRecord>();
  private readonly documents = new Map<string, DocumentRecord>();
  private readonly accessEvents: AccessEventRecord[] = [];

  /** Upper bound on retained audit events to keep memory bounded. */
  private static readonly MAX_ACCESS_EVENTS = 10_000;

  async findOrgById(id: string): Promise<OrganizationRecord | null> {
    return this.organizations.get(id) ?? null;
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
      api_key: apiKey ?? generateApiKey(),
      name,
      createdAt: new Date(),
    };
    this.organizations.set(org.id, org);
    return org;
  }

  async registerDevice(params: RegisterDeviceParams): Promise<{ device: DeviceRecord; created: boolean }> {
    for (const existing of this.devices.values()) {
      if (
        existing.org_id === params.orgId &&
        existing.public_key_fingerprint === params.publicKeyFingerprint
      ) {
        return { device: existing, created: false };
      }
    }

    const now = new Date();
    const record: DeviceRecord = {
      id: crypto.randomUUID(),
      org_id: params.orgId,
      hardware_hash: params.hardwareHash,
      public_key: params.publicKey,
      public_key_fingerprint: params.publicKeyFingerprint,
      key_algorithm: params.keyAlgorithm,
      status: 'ACTIVE',
      metadata: params.metadata ?? null,
      createdAt: now,
      updatedAt: now,
    };
    this.devices.set(record.id, record);
    return { device: record, created: true };
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

  async createDocument(params: CreateDocumentParams): Promise<DocumentRecord> {
    const record: DocumentRecord = {
      id: params.id ?? crypto.randomUUID(),
      org_id: params.orgId,
      target_device_id: params.targetDeviceId,
      encrypted_dek: params.encryptedDek,
      iv: params.iv,
      auth_tag: params.authTag,
      storage_url: params.storageUrl,
      original_name: params.originalName ?? null,
      mime_type: params.mimeType ?? 'application/octet-stream',
      encrypted_size_bytes: params.encryptedSizeBytes ?? null,
      aad_version: params.aadVersion,
      key_algorithm: params.keyAlgorithm,
      expires_at: params.expiresAt ?? null,
      createdAt: new Date(),
    };
    this.documents.set(record.id, record);
    return record;
  }

  async findDocumentById(documentId: string): Promise<DocumentRecord | null> {
    return this.documents.get(documentId) ?? null;
  }

  async deleteDocument(documentId: string): Promise<void> {
    this.documents.delete(documentId);
  }

  async recordAccessEvent(event: RecordAccessEventParams): Promise<void> {
    this.accessEvents.push({ ...event, id: crypto.randomUUID(), createdAt: new Date() });
    if (this.accessEvents.length > InMemoryRepository.MAX_ACCESS_EVENTS) {
      this.accessEvents.splice(0, this.accessEvents.length - InMemoryRepository.MAX_ACCESS_EVENTS);
    }
  }

  async listAccessEvents(documentId: string): Promise<AccessEventRecord[]> {
    return this.accessEvents.filter((e) => e.document_id === documentId);
  }
}
