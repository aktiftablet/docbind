-- Baseline of the previously published schema. Existing installations must mark
-- this migration applied before deploying the hardening migration (see README).
CREATE TABLE "Organization" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "api_key" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX "Organization_api_key_key" ON "Organization"("api_key");
CREATE TABLE "Device" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "org_id" TEXT NOT NULL,
  "hardware_hash" TEXT NOT NULL,
  "public_key" TEXT NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'ACTIVE',
  "metadata" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "Device_org_id_fkey" FOREIGN KEY ("org_id") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "Device_org_id_hardware_hash_key" ON "Device"("org_id", "hardware_hash");
CREATE INDEX "Device_hardware_hash_idx" ON "Device"("hardware_hash");
CREATE TABLE "Document" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "org_id" TEXT NOT NULL,
  "target_device_id" TEXT NOT NULL,
  "encrypted_dek" TEXT NOT NULL,
  "iv" TEXT NOT NULL,
  "auth_tag" TEXT NOT NULL,
  "storage_url" TEXT NOT NULL,
  "original_name" TEXT,
  "mime_type" TEXT NOT NULL DEFAULT 'application/octet-stream',
  "size_bytes" INTEGER,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "Document_org_id_fkey" FOREIGN KEY ("org_id") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "Document_target_device_id_fkey" FOREIGN KEY ("target_device_id") REFERENCES "Device"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
CREATE INDEX "Document_target_device_id_idx" ON "Document"("target_device_id");
CREATE INDEX "Document_org_id_idx" ON "Document"("org_id");
