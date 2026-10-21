# DocBind — Device-Bound Document Security API & SDK

Zero-Knowledge, Envelope-Encrypted File Security API (`@secure-doc/backend`) and Client SDK (`@secure-doc/sdk` for React Native & Web) that locks sensitive files of any type (PDF, Office documents, images, video, audio, text) to a specific target device's hardware fingerprint and decrypts them strictly in application RAM (`Uint8Array`) without ever writing plaintext bytes to disk.

---

## 1. Cryptographic Architecture (Envelope Encryption)

1. **Client-Side Key Generation (`DocumentSealer.getDeviceToken()`)**:
   - Generates an asymmetric `RSA-OAEP 2048` (`SHA-256`) key pair on the target device.
   - **Private Key Protection**:
     - **Web**: Stored in IndexedDB as a non-extractable WebCrypto `CryptoKey` (`extractable: false`), preventing raw private key export.
     - **Mobile (React Native)**: Stored inside the iOS Keychain / Secure Enclave or Android Keystore (`AndroidKeyStore`).
   - Computes a deterministic 64-character `SHA-256` `hardware_hash` from device hardware signals (`react-native-device-info` on Mobile or WebGL GPU / CPU / Screen traits on Web).
   - Registers `{ device_id, hardware_hash, public_key, metadata }` with `POST /v1/devices/register`.

2. **Document Sealing (`POST /v1/documents/seal`)**:
   - Generates a unique 256-bit `AES-256-GCM` Data Encryption Key (`DEK`) and 96-bit `IV` per document.
   - Accepts any file type and resolves its MIME type (magic bytes → declared type → file extension → `application/octet-stream`).
   - Encrypts the file in memory (`multer.memoryStorage()`) with `AES-256-GCM`, binding `target_device_id` as Additional Authenticated Data (`AAD`).
   - Wraps the `DEK` using the target device's `RSA-OAEP-256` Public Key.
   - Zeroes out the ephemeral `DEK` and plaintext upload buffer (`Buffer.fill(0)`) immediately after sealing.

3. **In-Memory Decryption & Secure Viewing (`<DocumentSealer.Viewer />`)**:
   - Fetches the encrypted payload from `GET /v1/documents/:id/payload`.
   - Unwraps the `encrypted_dek` into a non-extractable `AES-GCM` `CryptoKey` in RAM using `crypto.subtle.unwrapKey` (or native hardware keystore).
   - Decrypts the file into an in-memory `Uint8Array` and wipes the buffer (`bytes.fill(0)`) on component unmount.
   - Enforces anti-screenshot protections (`WindowManager.LayoutParams.FLAG_SECURE` on Android, `UIScreen.capturedDidChangeNotification` on iOS, focus/shortcut/print guards on Web) and renders a dynamic diagonal watermark grid.

### Supported File Types

| Category | Examples | Web rendering (`<DocumentSealer.Viewer />`) |
|---|---|---|
| PDF | `application/pdf` | Text layer or `<object>` (in-memory Blob URL) |
| Image | `image/png`, `image/jpeg`, `image/webp`, `image/gif` | `<img>` (drag & context menu disabled) |
| Video | `video/mp4`, `video/webm`, `video/quicktime` | `<video>` (`nodownload`, PiP disabled) |
| Audio | `audio/mpeg`, `audio/wav`, `audio/ogg` | `<audio>` (`nodownload`) |
| Text | `text/*`, `application/json`, `text/csv` | `<pre>` |
| Other | Office (`docx`, `xlsx`, `pptx`), archives, ... | Encrypted & delivered; supply a renderer via `renderNative` |

### Size Limits

Files are encrypted as a single AES-GCM block, so the whole file is decrypted in client RAM (peak usage is roughly **4–5× the file size**: base64 JSON + ciphertext + plaintext + Blob copy). Limits are therefore enforced on both sides:

| Layer | Video / Audio | Other files | Configure |
|---|---|---|---|
| Backend (`POST /v1/documents/seal`) | 100 MB | 50 MB | `MAX_VIDEO_MB`, `MAX_UPLOAD_MB` env vars |
| SDK (before decrypt) | 100 MB | 50 MB | `DocumentSealer.configure({ maxDecryptBytes })` |

- The backend returns **`413`** with `{ mime_type, max_bytes }` when a file exceeds its category limit.
- `GET /v1/documents/:id/payload` returns `size_bytes` and the `X-DocBind-Size-Bytes` / `X-DocBind-Mime-Type` headers, so the SDK rejects oversize payloads **before buffering the body** and throws `DocumentTooLargeError`.

```ts
DocumentSealer.configure({
  apiUrl: 'https://api.example.com',
  // number = single limit for all types, or per category:
  maxDecryptBytes: { media: 60 * 1024 * 1024, default: 30 * 1024 * 1024 }, // e.g. stricter on low-end phones
});
```

---

## 2. Project Structure

- [`packages/backend`](./packages/backend): Node.js + TypeScript + Express + Prisma API
  - [`src/crypto/envelope.ts`](./packages/backend/src/crypto/envelope.ts): `AES-256-GCM` + `RSA-OAEP-256` Envelope Encryption service
  - [`src/routes/devices.ts`](./packages/backend/src/routes/devices.ts): `POST /v1/devices/register`, `POST /v1/devices/:id/revoke`, `GET /v1/devices/:id`
  - [`src/routes/documents.ts`](./packages/backend/src/routes/documents.ts): `POST /v1/documents/seal`, `GET /v1/documents/:id/payload`
  - [`src/utils/mime.ts`](./packages/backend/src/utils/mime.ts): MIME detection (magic bytes / extension) & per-category size limits (`MAX_UPLOAD_MB`, `MAX_VIDEO_MB`)
  - [`prisma/schema.prisma`](./packages/backend/prisma/schema.prisma): `Organization`, `Device`, and `Document` models
- [`packages/sdk`](./packages/sdk): React & React Native Client SDK (`@secure-doc/sdk`)
  - [`src/DocumentSealer.ts`](./packages/sdk/src/DocumentSealer.ts): `DocumentSealer.getDeviceToken()`, `DocumentSealer.fetchAndDecryptInMemory()`
  - [`src/components/Viewer.tsx`](./packages/sdk/src/components/Viewer.tsx): `<DocumentSealer.Viewer />` component with MIME-aware rendering, RAM-only lifecycle & watermark overlay
  - [`src/media.ts`](./packages/sdk/src/media.ts): `getMediaCategory()` MIME → renderer category helper
  - [`src/crypto/KeyStore.ts`](./packages/sdk/src/crypto/KeyStore.ts): WebCrypto (`extractable: false`) & Mobile Hardware Keystore key management
  - [`src/fingerprint/HardwareFingerprint.ts`](./packages/sdk/src/fingerprint/HardwareFingerprint.ts): Deterministic SHA-256 device fingerprinting
  - [`src/security/ScreenCaptureGuard.ts`](./packages/sdk/src/security/ScreenCaptureGuard.ts): Cross-platform screenshot & screen recording countermeasures
  - [`native/android/DocBindModule.kt`](./packages/sdk/native/android/DocBindModule.kt) & [`native/ios/DocBindModule.swift`](./packages/sdk/native/ios/DocBindModule.swift): Native Mobile modules

---

## 3. Quick Start

```bash
# Install dependencies
npm install

# Build Backend & SDK packages
npm run build

# Run Cryptographic & E2E Test Suites
npm test

# Start Backend API Server (defaults to http://localhost:4000)
npm run dev:backend
```

### SDK Usage Example

```tsx
import React, { useEffect, useState } from 'react';
import { DocumentSealer } from '@secure-doc/sdk';

DocumentSealer.configure({
  apiUrl: 'http://localhost:4000',
  apiKey: 'docbind_dev_api_key_2026',
});

export function ConfidentialDocumentScreen({ documentId }: { documentId: string }) {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    DocumentSealer.getDeviceToken().then(( { deviceId }) => {
      console.log('Registered Hardware Device ID:', deviceId);
      setReady(true);
    });
  }, []);

  if (!ready) return <div>Initializing Hardware Enclave...</div>;

  return (
    <DocumentSealer.Viewer
      payloadUrl={`http://localhost:4000/v1/documents/${documentId}/payload`}
      preventScreenshot={true}
      watermark={{ text: 'user@192.168.1.10', color: 'rgba(0,0,0,0.1)' }}
    />
  );
}
```

### Sealing Files

```bash
# Multipart upload (any file type)
curl -X POST http://localhost:4000/v1/documents/seal \
  -H "x-api-key: docbind_dev_api_key_2026" \
  -F target_device_id=<DEVICE_ID> \
  -F file=@./training-video.mp4

# JSON / base64 upload (mime_type optional — detected from content/filename if omitted)
curl -X POST http://localhost:4000/v1/documents/seal \
  -H "x-api-key: docbind_dev_api_key_2026" -H "Content-Type: application/json" \
  -d '{"target_device_id":"<DEVICE_ID>","filename":"photo.png","mime_type":"image/png","file_base64":"..."}'
```

### Custom / Native Rendering

Use `renderNative` (React Native or unsupported formats such as Office files). It receives the decrypted data in RAM only:

```tsx
<DocumentSealer.Viewer
  payloadUrl={payloadUrl}
  renderNative={({ bytes, base64InMemory, mimeType, category }) =>
    category === 'video' ? <MyNativeVideo base64={base64InMemory} /> : <MyNativePdf base64={base64InMemory} />
  }
/>
```

> `renderNativePdf` is still accepted as a deprecated alias of `renderNative`.
