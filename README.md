# DocBind — Device-Bound Document Security API & SDK

Zero-Knowledge, Envelope-Encrypted PDF Security API (`@secure-doc/backend`) and Client SDK (`@secure-doc/sdk` for React Native & Web) that locks sensitive PDF documents to a specific target device's hardware fingerprint and decrypts them strictly in application RAM (`Uint8Array`) without ever writing plaintext bytes to disk.

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
   - Encrypts the PDF in memory (`multer.memoryStorage()`) with `AES-256-GCM`, binding `target_device_id` as Additional Authenticated Data (`AAD`).
   - Wraps the `DEK` using the target device's `RSA-OAEP-256` Public Key.
   - Zeroes out the ephemeral `DEK` and plaintext upload buffer (`Buffer.fill(0)`) immediately after sealing.

3. **In-Memory Decryption & Secure Viewing (`<DocumentSealer.Viewer />`)**:
   - Fetches the encrypted payload from `GET /v1/documents/:id/payload`.
   - Unwraps the `encrypted_dek` into a non-extractable `AES-GCM` `CryptoKey` in RAM using `crypto.subtle.unwrapKey` (or native hardware keystore).
   - Decrypts the PDF into an in-memory `Uint8Array` and wipes the buffer (`bytes.fill(0)`) on component unmount.
   - Enforces anti-screenshot protections (`WindowManager.LayoutParams.FLAG_SECURE` on Android, `UIScreen.capturedDidChangeNotification` on iOS, focus/shortcut/print guards on Web) and renders a dynamic diagonal watermark grid.

---

## 2. Project Structure

- [`packages/backend`](./packages/backend): Node.js + TypeScript + Express + Prisma API
  - [`src/crypto/envelope.ts`](./packages/backend/src/crypto/envelope.ts): `AES-256-GCM` + `RSA-OAEP-256` Envelope Encryption service
  - [`src/routes/devices.ts`](./packages/backend/src/routes/devices.ts): `POST /v1/devices/register`, `POST /v1/devices/:id/revoke`, `GET /v1/devices/:id`
  - [`src/routes/documents.ts`](./packages/backend/src/routes/documents.ts): `POST /v1/documents/seal`, `GET /v1/documents/:id/payload`
  - [`prisma/schema.prisma`](./packages/backend/prisma/schema.prisma): `Organization`, `Device`, and `Document` models
- [`packages/sdk`](./packages/sdk): React & React Native Client SDK (`@secure-doc/sdk`)
  - [`src/DocumentSealer.ts`](./packages/sdk/src/DocumentSealer.ts): `DocumentSealer.getDeviceToken()`, `DocumentSealer.fetchAndDecryptInMemory()`
  - [`src/components/Viewer.tsx`](./packages/sdk/src/components/Viewer.tsx): `<DocumentSealer.Viewer />` component with RAM-only lifecycle & watermark overlay
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
