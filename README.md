# DocBind

Device-bound document delivery with server-side AES-256-GCM envelope encryption and a React / React Native SDK. Each document targets one immutable device public key. The corresponding private key decrypts its document key.

## Security model

- The server receives plaintext while sealing. This is **server-side envelope encryption**, not zero-knowledge or end-to-end encryption.
- Device identity is `(organization, SHA-256 of DER SPKI public key)`. Public keys cannot be replaced. Re-enrolling a revoked key is denied. A different key always creates a different device ID.
- `hardware_hash` is optional diagnostic information. Display changes, browser zoom, time zone changes and identical hardware cannot replace a device record or change its identity. Neither the hash nor a client-supplied device ID authenticates a request.
- Android requires a hardware-backed RSA key; unsupported devices fail rather than fall back to software. The SDK advertises OAEP-SHA256 with MGF1-SHA1 for Android Keystore compatibility.
- iOS uses RSA in Keychain with `WhenUnlockedThisDeviceOnly`, **not Secure Enclave**. Web uses a non-extractable WebCrypto key in IndexedDB. Neither provides a server-verified physical-device guarantee. Hardware attestation is not implemented.
- A bearer token grants access only to one active device's encrypted payloads. Decryption still requires its private key. Device tokens cannot seal documents, issue enrollments or revoke devices.
- Revocation blocks future API requests. It cannot erase plaintext or encrypted payloads and keys already obtained by a recipient. Losing or deleting the private key makes old documents unrecoverable.
- Screenshot controls are best effort. iOS detects recording/mirroring; Web cannot reliably prevent OS capture. RAM buffers are cleared where possible, but JavaScript/OS copies, swap and browser internals prevent an absolute “never touches disk” guarantee.

## Install and verify

Use Node.js 22.18+ (or a supported newer release) and npm. The lockfile is committed; generated builds and dependencies are ignored.

```bash
npm ci
npm run prisma:generate --workspace=packages/backend
npm run build
npm test
```

Prisma generation downloads native engines when absent. API regression tests use real Express/body parsing/Multer with an in-process HTTP transport, so they do not require a listening port. Persistent storage tests mock provider clients; they do not replace integration tests against a real PostgreSQL database and S3 bucket. Native projects must also be built/tested in an Android/iOS host app.

## Server configuration

Set environment variables before starting the backend; `.env` files are not automatically loaded.

| Variable | Meaning |
| --- | --- |
| `NODE_ENV=production` | Requires PostgreSQL, S3 and a persistent token-signing secret; refuses memory fallback |
| `DATABASE_URL` | PostgreSQL connection string |
| `S3_BUCKET_NAME` | Existing private bucket for ciphertext |
| `AWS_REGION` | S3 region; defaults to `us-east-1` |
| `S3_ENDPOINT` | Optional S3-compatible endpoint; enables path-style requests |
| `TOKEN_SIGNING_SECRET` | Random secret of at least 32 bytes; persist across restarts; rotation invalidates existing tokens |
| `PROVISIONING_API_KEY` | Separate secret for organization creation; absent means onboarding is disabled |
| `CORS_ORIGINS` | Comma-separated browser app origins; cross-origin access is disabled by default |
| `PORT` | Defaults to `4000` |
| `MAX_UPLOAD_MB` / `MAX_VIDEO_MB` | Non-media/media upload limits; defaults to 50/100 MiB |

AWS credentials use the standard provider chain. Grant the backend bucket-scoped read/write/delete permissions. Keep database, AWS, provisioning and organization credentials on the trusted server.

```bash
npm run prisma:deploy --workspace=packages/backend
npm run build
npm run start --workspace=packages/backend
```

Without persistence settings in development, adapters store data in RAM and lose it on restart. There is no seeded organization, default API key or authentication fallback. Startup warnings identify memory mode. Production needs an existing bucket, database, TLS ingress and shared rate limiting at the ingress for multiple replicas. The built-in rate limit is per process (120 requests/minute/IP); it does not trust forwarded IP headers. Authenticated uploads are limited to two concurrent buffers per process; configure ingress body limits, timeouts and quotas too.

### Existing PostgreSQL installations

Back up first. If the database already has exactly the old published schema but no migration history, baseline it once:

```bash
npm exec --workspace=packages/backend -- prisma migrate resolve --applied 202610220001_legacy_baseline
npm run prisma:deploy --workspace=packages/backend
```

For a fresh database, run only `prisma:deploy`; it applies both migrations. The upgrade preserves old IDs, ciphertext, revoked status and legacy v1 AAD. It aborts on duplicate keys within a tenant or unsupported key encodings instead of silently changing bindings. Resolve such records explicitly before retrying. Do not baseline an empty or differently structured database. Previously in-memory data cannot be recovered after its process has stopped.

## Authentication and enrollment

There are three distinct credentials:

1. **Provisioning key**, sent as `x-provisioning-key` to `POST /v1/organizations`. It returns a new organization and its random API key.
2. **Organization API key**, sent as `x-api-key` by your trusted application server for device approval, document sealing and revocation. Never embed it in a browser/mobile app.
3. **Scoped bearer tokens**, used by client SDKs. An enrollment token expires after five minutes and approves one public-key fingerprint. Registration returns a device token valid for one hour. Device-token renewal via registration requires a still-active, unexpired token; otherwise ask the trusted application server for a new enrollment approval.

Your application server must authenticate its own user and authorize the requested device before issuing an enrollment token. DocBind does not supply your application's login system.

| Endpoint | Credential | Purpose |
| --- | --- | --- |
| `POST /v1/organizations` | Provisioning key | Create tenant; JSON `{ "name": "Company" }` |
| `POST /v1/devices/enrollment-tokens` | Organization key | Approve public key; JSON `{ "public_key": "PEM" }`; returns `enrollment_token` |
| `POST /v1/devices/register` | Enrollment/device bearer or organization key | Register immutable key; returns `registered_device_id`, `device_token`, `status`, `expires_in` |
| `GET /v1/devices/:id` | Organization key or matching device bearer | Device status and metadata; no hash |
| `POST /v1/devices/:id/revoke` | Organization key | Permanently revoke that key within its organization |
| `POST /v1/documents/seal` | Organization key | Multipart `file` + `target_device_id`, or JSON `file_base64` + `target_device_id` |
| `GET /v1/documents/:id/payload` | Matching active device bearer | Ciphertext and wrapped DEK; admin keys cannot fetch this endpoint |

New envelopes authenticate device ID, document ID and MIME type (AAD v2). Legacy v1 envelopes remain readable. Registration accepts `key_algorithm` (`RSA-OAEP-256` or Android's `RSA-OAEP-256-MGF1-SHA1`); this value is immutable after enrollment.

## Client SDK

```ts
import { DocumentSealer } from '@secure-doc/sdk';

DocumentSealer.configure({ apiUrl: 'https://docbind.example.com' });
// This creates/retrieves the local private key without contacting DocBind.
const local = await DocumentSealer.getDeviceToken({ skipBackendRegistration: true });

// Send local.publicKeyPem to YOUR authenticated application server. That server
// authorizes this user/device, calls /v1/devices/enrollment-tokens with its
// organization key, and returns only the scoped enrollment_token.
const enrollmentToken = await obtainApprovalFromYourApplication(local.publicKeyPem);
DocumentSealer.configure({ enrollmentToken });
const device = await DocumentSealer.getDeviceToken({ forceRefresh: true });

// Your application server seals a document for device.deviceId and supplies its URL.
const document = await DocumentSealer.fetchAndDecryptInMemory(
  'https://docbind.example.com/v1/documents/DOCUMENT_ID/payload'
);
try { useDocument(document.bytes); } finally { document.dispose(); }
```

Persist `device.deviceToken` only in suitable platform-protected storage if needed. Pass it back as `deviceToken` on subsequent app launches. Tokens are not private keys. Clearing IndexedDB or reinstalling an app may destroy the key; another key cannot recover prior envelopes.

For the React viewer, pass `deviceToken` rather than the old `apiKey` prop. The SDK never sends an organization key and refuses payload URLs on a different origin from configured `apiUrl`.

### React Native

The SDK includes a podspec, Android library/package and autolinking configuration. Install pods for the host iOS app. Register these adapters explicitly (the native module is not loaded automatically by the framework-neutral SDK):

```ts
import { NativeModules, NativeEventEmitter } from 'react-native';
import { DocumentSealer, createReactNativeKeystore, createReactNativeScreenGuard } from '@secure-doc/sdk';

const module = NativeModules.DocBindScreenGuard;
DocumentSealer.configure({
  apiUrl: 'https://docbind.example.com',
  nativeModules: {
    secureKeystore: createReactNativeKeystore(module),
    screenGuard: createReactNativeScreenGuard(module, new NativeEventEmitter(module)),
  },
});
```

On Android pass only `createReactNativeScreenGuard(module)`; capture event subscription is for iOS. Native constants select the matching OAEP variant. Android exports `getPublicKeyPem` for subsequent launches; iOS exports promise-based key and capture methods and emits boolean capture events. These modules require a compatible React Native host and device validation before release.
