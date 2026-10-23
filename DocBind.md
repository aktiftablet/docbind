# DocBind implementation notes

The current implementation and security contract are documented in [README.md](./README.md). This replaces the original design brief where it conflicted with the code.

Documents are sealed server-side with AES-256-GCM and a per-document key wrapped by the target device's immutable RSA public key. New envelopes bind device ID, document ID and MIME type as authenticated data. The server sees plaintext during sealing; this is not zero-knowledge encryption.

Device identity is derived from the public key, while hardware traits are diagnostic. Android requires a hardware-backed Keystore key and negotiates OAEP-SHA256/MGF1-SHA1. iOS uses RSA Keychain keys, not Secure Enclave. WebCrypto's non-extractable keys do not establish a server-verified physical-device identity. Hardware attestation is not implemented.

Tenant administration stays on the trusted application server. Clients receive key-bound enrollment approvals and device-scoped access tokens. Revocation is permanent for the existing key and prevents subsequent API access; it cannot retract copies already downloaded.

Production startup requires PostgreSQL, S3 ciphertext storage and a persistent signing secret. Generated builds, dependencies, environment secrets and caches are excluded from Git; the dependency lockfile and Prisma migrations are tracked.
