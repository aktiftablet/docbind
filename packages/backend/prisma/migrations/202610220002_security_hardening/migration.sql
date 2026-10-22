BEGIN;
CREATE TYPE "DeviceStatus" AS ENUM ('ACTIVE', 'REVOKED');
CREATE TYPE "AccessAction" AS ENUM ('SEAL', 'PAYLOAD_FETCH', 'DELETE');
CREATE TYPE "AccessOutcome" AS ENUM ('GRANTED', 'DENIED');
ALTER TABLE "Device" ALTER COLUMN "status" DROP DEFAULT;
ALTER TABLE "Device" ALTER COLUMN "status" TYPE "DeviceStatus" USING "status"::"DeviceStatus";
ALTER TABLE "Device" ALTER COLUMN "status" SET DEFAULT 'ACTIVE';
ALTER TABLE "Device" ADD COLUMN "public_key_fingerprint" TEXT;
ALTER TABLE "Device" ADD COLUMN "key_algorithm" TEXT NOT NULL DEFAULT 'RSA-OAEP-256';

-- Convert PKCS#1 RSA public keys to SPKI before fingerprinting, just as Node's
-- createPublicKey(...).export({type:'spki',format:'der'}) does. SHA-256 is built
-- into PostgreSQL; no privileged pgcrypto extension is needed.
CREATE FUNCTION pg_temp.docbind_der(tag INTEGER, payload BYTEA) RETURNS BYTEA
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE n INTEGER := octet_length(payload); length_hex TEXT;
BEGIN
  IF n < 128 THEN length_hex := lpad(to_hex(n), 2, '0');
  ELSIF n < 256 THEN length_hex := '81' || lpad(to_hex(n), 2, '0');
  ELSIF n < 65536 THEN length_hex := '82' || lpad(to_hex(n), 4, '0');
  ELSE RAISE EXCEPTION 'Unsupported public key size'; END IF;
  RETURN decode(lpad(to_hex(tag), 2, '0') || length_hex, 'hex') || payload;
END $$;

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM "Device" WHERE "public_key" NOT LIKE '%-----BEGIN PUBLIC KEY-----%'
    AND "public_key" NOT LIKE '%-----BEGIN RSA PUBLIC KEY-----%') THEN
    RAISE EXCEPTION 'Unsupported legacy public key encoding; normalize keys before migrating';
  END IF;
END $$;

WITH keys AS (
  SELECT "id", "public_key", decode(regexp_replace(
    regexp_replace("public_key", '-----[^-]+-----', '', 'g'), '[[:space:]]', '', 'g'), 'base64') AS der
  FROM "Device"
)
UPDATE "Device" d SET "public_key_fingerprint" = encode(sha256(
  CASE WHEN keys."public_key" LIKE '%-----BEGIN RSA PUBLIC KEY-----%'
    THEN pg_temp.docbind_der(48, decode('300d06092a864886f70d0101010500', 'hex') ||
      pg_temp.docbind_der(3, decode('00', 'hex') || keys.der))
    ELSE keys.der END), 'hex') FROM keys WHERE d."id" = keys."id";

-- Fail rather than silently merge duplicate public keys: changing a device ID
-- would invalidate the authenticated data on its existing documents.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM "Device" GROUP BY "org_id", "public_key_fingerprint" HAVING count(*) > 1) THEN
    RAISE EXCEPTION 'Duplicate legacy public keys within an organization; resolve explicitly before migrating';
  END IF;
END $$;
ALTER TABLE "Device" ALTER COLUMN "public_key_fingerprint" SET NOT NULL;
DROP INDEX "Device_org_id_hardware_hash_key";
DROP INDEX "Device_hardware_hash_idx";
CREATE UNIQUE INDEX "Device_org_id_public_key_fingerprint_key" ON "Device"("org_id", "public_key_fingerprint");
CREATE INDEX "Device_org_id_hardware_hash_idx" ON "Device"("org_id", "hardware_hash");

ALTER TABLE "Document" RENAME COLUMN "size_bytes" TO "encrypted_size_bytes";
-- Preserve the AAD used by existing envelopes; only newly sealed documents use v2.
ALTER TABLE "Document" ADD COLUMN "aad_version" TEXT NOT NULL DEFAULT 'v1';
ALTER TABLE "Document" ALTER COLUMN "aad_version" SET DEFAULT 'v2';
ALTER TABLE "Document" ADD COLUMN "key_algorithm" TEXT NOT NULL DEFAULT 'RSA-OAEP-256';
ALTER TABLE "Document" ADD COLUMN "expires_at" TIMESTAMP(3);
CREATE INDEX "Document_expires_at_idx" ON "Document"("expires_at");
CREATE TABLE "AccessEvent" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "org_id" TEXT NOT NULL,
  "document_id" TEXT,
  "device_id" TEXT,
  "action" "AccessAction" NOT NULL,
  "outcome" "AccessOutcome" NOT NULL,
  "reason" TEXT,
  "ip" TEXT,
  "user_agent" TEXT,
  "request_id" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "AccessEvent_org_id_fkey" FOREIGN KEY ("org_id") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "AccessEvent_org_id_createdAt_idx" ON "AccessEvent"("org_id", "createdAt");
CREATE INDEX "AccessEvent_document_id_idx" ON "AccessEvent"("document_id");
COMMIT;
