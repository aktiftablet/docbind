\# \[PROJECT\_SPECIFICATION\] Device-Bound Document Security API & SDK (B2B SaaS)


\#\# 1. PROJECT OVERVIEW

\*\*Objective:\*\* Build a "Developer-First" API and Client SDK (React Native / Web) that enables B2B customers to encrypt files of any type (PDFs, Office documents, images, video, audio) and lock them to a specific target device's hardware fingerprint. The document must only be decryptable on the authorized device, entirely in-memory, without ever writing the plaintext file to the disk.


\*\*Target Audience:\*\* AI Coding Agent (Act as a Senior Cryptography Engineer and Full-Stack Developer).

\*\*Primary Stack:\*\* 

- Backend: Node.js (TypeScript, Express/NestJS), PostgreSQL, Redis.

- Client SDK: React Native (Mobile), React (WebAssembly for Web).

- Crypto Layer: Web Crypto API (Web), react-native-crypto / native modules (Mobile).


---


\#\# 2. CRYPTOGRAPHIC ARCHITECTURE (ENVELOPE ENCRYPTION)

The system must use Envelope Encryption to ensure zero-knowledge architecture where possible.


1. \*\*Client-Side Key Generation (Device Registration):\*\*

   - The Client SDK generates an asymmetric key pair (e.g., \`RSA-OAEP 2048\` or \`ECC P-256\`).

   - The \`Private Key\` is securely stored on the device (iOS Secure Enclave / Android Keystore / Web IndexedDB with extractable:false).

   - The \`Public Key\` and a generated \`hardware\_fingerprint\_hash\` are sent to the Backend.


2. \*\*Document Encryption (Backend/Sender Side):\*\*

   - A unique symmetric Data Encryption Key (DEK) is generated (e.g., \`AES-256-GCM\`).

   - The Document is encrypted using the DEK.

   - The DEK is encrypted using the target device's \`Public Key\`.

   - The API returns the \`encrypted\_document\` + \`encrypted\_DEK\`.


3. \*\*Document Decryption (Target Device):\*\*

   - The SDK receives the payload.

   - The SDK uses its hardware-secured \`Private Key\` to decrypt the \`encrypted\_DEK\`.

   - The SDK decrypts the document in RAM using the DEK.

   - The SDK renders the document inside a secure viewer.


---


\#\# 3. CORE COMPONENTS & REQUIREMENTS


\#\#\# A. Backend API (Node.js)

Must implement the following REST endpoints:

- \`POST /v1/devices/register\`: Registers a device fingerprint and stores its Public Key.

  - \*Request:\* \`\{ device\_id, public\_key, metadata \}\`

  - \*Response:\* \`\{ success, registered\_device\_id \}\`

- \`POST /v1/documents/seal\`: Encrypts a document for a specific device.

  - \*Request:\* \`multipart/form-data\` (file) + \`target\_device\_id\`

  - \*Logic:\* Generate AES key -\> Encrypt File -\> Encrypt AES Key with Device Public Key -\> Store/Return.

- \`GET /v1/documents/:id/payload\`: Fetches the encrypted payload.


\#\#\# B. Client SDK (React Native / React)

Must expose a simple, developer-friendly interface:

\`\`\`typescript

// SDK Interface Expectation

import \{ DocumentSealer \} from '@secure-doc/sdk';


// 1. Init & Get Device Token

const deviceToken = await DocumentSealer.getDeviceToken();


// 2. Secure Viewer Component

\<DocumentSealer.Viewer "rgba(0,0,0,0.1)" "user@ip", color: payloadUrl="https://api..." preventScreenshot="\{true\}" text: watermark="\{\{" \}\}/\>



**Critical SDK Security Constraints (DO NOT IGNORE):**

1. **No Disk Writes:** The decrypted file byte array MUST remain in application memory. Render by MIME type using in-memory sources (Blob URLs / Base64), e.g. an in-memory PDF renderer, `<img>`, `<video>`, `<audio>`.

2. **Screenshot Prevention:**

   - *Android:* Enforce `WindowManager.LayoutParams.FLAG_SECURE`.

   - *iOS:* Use `UIScreen.capturedDidChangeNotification` to blur/hide view.


model Organization \{

  id        String   @id @default(uuid())

  api\_key   String   @unique

  name      String

\}


model Device \{

  id               String   @id @default(uuid())

  org\_id           String

  hardware\_hash    String   // Hashed combination of MAC, CPU ID, etc.

  public\_key       String   // PEM format

  status           String   // ACTIVE, REVOKED

\}


model Document \{

  id               String   @id @default(uuid())

  org\_id           String

  target\_device\_id String

  encrypted\_dek    String   // AES key encrypted with Device Public Key

  storage\_url      String   // S3 path to AES-encrypted file

\}


## 4. EXECUTION PLAN (INSTRUCTIONS FOR AI)

**Phase 1: Foundation & Backend Setup**

- Initialize the Node.js TypeScript project.

- Setup Prisma schema and basic API routes for device registration and document sealing.

- Implement the cryptographic utility functions (`AES-256-GCM` for file, `RSA` for DEK).

**Phase 2: Client SDK Core Logic**

- Create the React Native SDK boilerplate.

- Implement hardware fingerprinting logic (using `react-native-device-info` or native modules) to create a deterministic device hash.

- Implement Secure Keystore/Keychain RSA key pair generation.

**Phase 3: Secure Viewer Integration**

- Implement the in-memory decryption flow.

- Integrate MIME-aware viewers (PDF, image, video, audio, text) that accept `ArrayBuffer` / `Base64` directly instead of a local file path.

- Implement anti-screenshot measures.

