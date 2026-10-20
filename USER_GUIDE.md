# DocBind API & Client SDK — Kullanıcı ve AI Entegrasyon Kılavuzu

Bu doküman, **DocBind (Device-Bound Document Security API & SDK)** sistemini kendi B2B SaaS, finans, hukuk, sağlık veya kurumsal projelerine entegre etmek isteyen **yazılım geliştiriciler** ve **AI kodlama ajanları (Cursor, Antigravity, Claude Code, Copilot vb.)** için hazırlanmıştır.

---

## 🤖 1. AI KODLAMA ARAÇLARI İÇİN SİSTEM ÖZETİ (`[AI_AGENT_CONTEXT]`)

> **AI Ajanları İçin Talimat:** Bu projeyi başka bir uygulamaya entegre ederken aşağıdaki kuralları, tip tanımlarını ve uç nokta sözleşmelerini birebir uygulayın. Varsayımda bulunmayın.

### 1.1. Kritik Güvenlik Değişmezleri (Security Invariants)
1. **Sıfır Disk Yazımı (Zero Disk Writes):** Şifresi çözülmüş PDF baytları (`Uint8Array`) **asla** yerel dosya sistemine (`fs.writeFile`, `RNFS`, `FileSystem` vb.) veya kalıcı depolamaya (`localStorage`) yazılmamalıdır. Yalnızca uygulama RAM'inde tutulmalı ve görüntüleyici kapandığında `doc.dispose()` (`bytes.fill(0)`) çağrılmalıdır.
2. **Dışa Aktarılamaz Özel Anahtar (`extractable: false`):** İstemci tarafında üretilen `RSA-OAEP-256 (2048-bit)` özel anahtarı Web'de `IndexedDB` içinde `extractable: false` olarak, mobilde ise `AndroidKeyStore` veya `iOS Keychain / Secure Enclave` içinde saklanır. Sunucuya yalnızca PEM (`SPKI`) formatındaki **Açık Anahtar (`public_key`)** gönderilir.
3. **AAD (Additional Authenticated Data) Cihaz Bağlama:** Sunucu `AES-256-GCM` ile belgeyi şifrelerken `target_device_id` değerini `AAD` olarak şifreli metne bağlar. Farklı bir `target_device_id` ile şifre çözme girişimi GCM kimlik doğrulama hatasıyla (`Authentication Tag mismatch`) reddedilir.
4. **Kimlik Doğrulama:** Tüm `/v1/devices/*` ve `/v1/documents/*` isteklerinde `x-api-key: <ORG_API_KEY>` veya `Authorization: Bearer <ORG_API_KEY>` başlığı gönderilmelidir (geliştirme ortamında varsayılan anahtar: `docbind_dev_api_key_2026`).

### 1.2. Hızlı Uç Nokta Sözleşmesi (Quick Endpoint Contract)

| Metod & Yol | İstek Gövdesi / Başlıklar | Başarılı Yanıt (`200` / `201`) | Açıklama |
| :--- | :--- | :--- | :--- |
| `GET /health` | Yok | `{ status: "ok", service: "docbind-api", crypto: { envelope: "AES-256-GCM + RSA-OAEP-256", zero_disk_writes: true } }` | Servis sağlık kontrolü |
| `POST /v1/organizations` | `JSON`: `{ "name": "Firma Adı" }` | `{ success: true, organization: { id, name, api_key, createdAt } }` | Yeni B2B tenant ve `api_key` oluşturur |
| `POST /v1/devices/register` | `JSON`: `{ "device_id": "...", "hardware_hash": "...", "public_key": "-----BEGIN PUBLIC KEY-----...", "metadata": {} }` | `{ success: true, registered_device_id: "<uuid>", hardware_hash: "<64-hex>", status: "ACTIVE" }` | Cihazın donanım parmak izini ve RSA açık anahtarını kaydeder |
| `GET /v1/devices/:id` | Header: `x-api-key` | `{ success: true, device: { id, hardware_hash, status, metadata, createdAt } }` | Cihaz durumunu sorgular |
| `POST /v1/devices/:id/revoke` | Header: `x-api-key` | `{ success: true, registered_device_id: "<uuid>", status: "REVOKED" }` | Cihazı iptal eder; belge mühürlemeyi ve açmayı engeller |
| `POST /v1/documents/seal` | `multipart/form-data`: `file` (PDF) + `target_device_id` **VEYA** `JSON`: `{ "target_device_id": "<uuid>", "file_base64": "...", "filename": "doc.pdf" }` | `{ success: true, document_id: "<uuid>", target_device_id: "<uuid>", encrypted_dek: "<b64>", iv: "<b64>", auth_tag: "<b64>", storage_url: "s3://...", payload_url: "/v1/documents/<id>/payload", encrypted_document: "<b64>" }` | PDF'i hedef cihaza özel zarf şifreleme ile RAM'de şifreler |
| `GET /v1/documents/:id/payload` | Header: `x-api-key`, `x-device-id: <uuid>`, `x-hardware-hash: <64-hex>` | `{ success: true, document_id, target_device_id, mime_type, original_name, encrypted_dek, iv, auth_tag, encrypted_document, algorithm }` | Hedef cihaz SDK'sı için şifreli belge yükünü döner |

---

## 🏗️ 2. MİMARİ VE ÇALIŞMA AKIŞI (ENVELOPE ENCRYPTION)

DocBind, **Sıfır Bilgi (Zero-Knowledge)** prensibine dayalı **Zarf Şifreleme (Envelope Encryption)** mimarisi kullanır. Sunucu dahi hedef cihazın özel anahtarına sahip olmadığı için mühürlenen bir PDF'in şifresini yalnızca hedef cihaz çözebilir.

```mermaid
sequenceDiagram
    autonumber
    participant SDK as İstemci SDK (Web / Mobil Cihaz)
    participant API as DocBind Backend API
    participant B2B as B2B Müşteri Sunucusu (Gönderici)

    Note over SDK: 1. Cihaz Kaydı (Device Registration)
    SDK->>SDK: RSA-OAEP 2048 Anahtar Çifti Üret (Private Key = extractable:false / Keystore)
    SDK->>SDK: Donanım Sinyallerinden SHA-256 hardware_hash Üret
    SDK->>API: POST /v1/devices/register { hardware_hash, public_key, metadata }
    API-->>SDK: { registered_device_id, hardware_hash, status: "ACTIVE" }
    SDK->>B2B: Kullanıcının registered_device_id bilgisini uygulama sunucusuna ilet

    Note over B2B,API: 2. Belge Mühürleme (Document Sealing)
    B2B->>API: POST /v1/documents/seal (PDF Dosyası + target_device_id)
    API->>API: Tek kullanımlık 256-bit AES-GCM DEK ve 12-byte IV üret
    API->>API: PDF'i AES-256-GCM ile RAM'de şifrele (AAD = target_device_id)
    API->>API: DEK'i cihazın RSA-OAEP Public Key'i ile şifrele (encrypted_dek)
    API->>API: Açık DEK ve PDF tamponunu RAM'den sıfırla (Buffer.fill(0))
    API-->>B2B: { document_id, payload_url: "/v1/documents/:id/payload" }

    Note over SDK,API: 3. Bellek İçi Şifre Çözme ve Görüntüleme (In-Memory Decryption)
    SDK->>API: GET /v1/documents/:id/payload (x-device-id, x-hardware-hash)
    API-->>SDK: { encrypted_document, encrypted_dek, iv, auth_tag, target_device_id }
    SDK->>SDK: Donanım Özel Anahtarı ile encrypted_dek'i RAM içinde çöz
    SDK->>SDK: AES-256-GCM ile PDF'i Uint8Array olarak RAM'de çöz (Diske yazılmaz!)
    SDK->>SDK: <DocumentSealer.Viewer /> ile filigranlı ve ekran görüntüsü korumalı göster
    SDK->>SDK: Bileşen kapandığında (unmount) RAM tamponunu sıfırla (bytes.fill(0))
```

---

## 🚀 3. KURULUM VE ÇALIŞTIRMA

### 3.1. Projeyi Derleme ve Sunucuyu Başlatma

```bash
# 1. Bağımlılıkları yükleyin
npm install

# 2. Backend ve SDK paketlerini derleyin
npm run build

# 3. Backend API sunucusunu başlatın (Varsayılan port: 4000)
npm run dev:backend
```

### 3.2. Ortam Değişkenleri (Environment Variables)

Backend servisi (`@secure-doc/backend`) sıfır yapılandırma ile bellek içi (in-memory) modda hemen çalışabilir veya üretim ortamında PostgreSQL / S3 ile yapılandırılabilir:

| Değişken | Varsayılan Değer | Açıklama |
| :--- | :--- | :--- |
| `PORT` | `4000` | HTTP sunucu portu |
| `DEFAULT_ORG_API_KEY` | `docbind_dev_api_key_2026` | Varsayılan geliştirme organizasyonu API anahtarı |
| `DATABASE_URL` | *(Opsiyonel)* | PostgreSQL bağlantı dizgesi (`postgresql://user:pass@host:5432/docbind`) |
| `S3_BUCKET_NAME` | `docbind-encrypted-vault` | Şifreli PDF bloblarının saklandığı bucket adı |

### 3.3. Backend'i Kendi Express/Node.js Uygulamanıza Gömme (Programatik Kullanım)

`@secure-doc/backend` paketini bağımsız bir mikroservis olarak çalıştırabileceğiniz gibi mevcut Node.js sunucunuza doğrudan dahil edebilirsiniz:

```typescript
import { createApp, PrismaRepository } from '@secure-doc/backend';
import { PrismaClient } from '@prisma/client';

// 1. Bellek içi (Hızlı başlangıç / Test)
const { app } = createApp({
  allowDefaultOrgFallback: false, // Üretimde zorunlu x-api-key kontrolü
});

app.listen(4000, () => {
  console.log('DocBind API 4000 portunda çalışıyor');
});

// 2. PostgreSQL (Prisma) ile Üretim Kurulumu
// const prisma = new PrismaClient();
// const { app } = createApp({ repository: new PrismaRepository(prisma), allowDefaultOrgFallback: false });
```

---

## 📡 4. REST API DETAYLI KULLANIM REHBERİ

### 4.1. Organizasyon (Tenant) Oluşturma — `POST /v1/organizations`

Her B2B müşterisi için benzersiz bir `api_key` üretir.

**İstek (`curl`):**
```bash
curl -X POST http://localhost:4000/v1/organizations \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Finans A.Ş."}'
```

**Yanıt (`201 Created`):**
```json
{
  "success": true,
  "organization": {
    "id": "8f14e45f-ceea-467a-a839-990011223344",
    "name": "Acme Finans A.Ş.",
    "api_key": "db_live_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f",
    "createdAt": "2026-10-20T06:00:00.000Z"
  }
}
```

---

### 4.2. Cihaz Kaydı — `POST /v1/devices/register`

Hedef cihazın `RSA-OAEP 2048` açık anahtarını (`PEM` formatında) ve donanım parmak izini kaydeder. Aynı `org_id` ve `hardware_hash` için tekrar çağrılırsa kaydı günceller (`upsert`).

> **Not:** Normal akışta bu uç nokta istemci tarafındaki `DocumentSealer.getDeviceToken()` metodu tarafından otomatik çağrılır.

**İstek (`curl`):**
```bash
curl -X POST http://localhost:4000/v1/devices/register \
  -H "Content-Type: application/json" \
  -H "x-api-key: docbind_dev_api_key_2026" \
  -d '{
    "device_id": "ios|iPhone16,2|A17Pro|unique-id-123",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
    "metadata": {
      "platform": "iOS",
      "model": "iPhone 16 Pro"
    }
  }'
```

**Yanıt (`201 Created`):**
```json
{
  "success": true,
  "registered_device_id": "c3947f5d-5d68-49a4-8c81-7090f45e1122",
  "hardware_hash": "4a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
  "status": "ACTIVE"
}
```

---

### 4.3. Belge Mühürleme (Şifreleme) — `POST /v1/documents/seal`

Bir PDF dosyasını belirli bir `target_device_id` için RAM üzerinde şifreler. İki farklı gönderim biçimini destekler:
1. **`multipart/form-data`**: `file` (PDF binary) ve `target_device_id` alanları ile.
2. **`application/json`**: `file_base64`, `filename` ve `target_device_id` alanları ile.

**Yöntem A — `multipart/form-data` ile Gönderim (`curl`):**
```bash
curl -X POST http://localhost:4000/v1/documents/seal \
  -H "x-api-key: docbind_dev_api_key_2026" \
  -F "target_device_id=c3947f5d-5d68-49a4-8c81-7090f45e1122" \
  -F "file=@./gizli-sozlesme.pdf"
```

**Yöntem B — Node.js / TypeScript Backend'den Gönderim (`fetch`):**
```typescript
import fs from 'node:fs/promises';

async function sealPdfForUserDevice(pdfPath: string, targetDeviceId: string) {
  const fileBuffer = await fs.readFile(pdfPath);

  const response = await fetch('http://localhost:4000/v1/documents/seal', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'docbind_dev_api_key_2026',
    },
    body: JSON.stringify({
      target_device_id: targetDeviceId,
      filename: 'gizli-sozlesme.pdf',
      file_base64: fileBuffer.toString('base64'),
    }),
  });

  if (!response.ok) {
    throw new Error(`Mühürleme hatası: ${await response.text()}`);
  }

  return await response.json();
  // Dönen değer: { document_id, payload_url, encrypted_dek, iv, auth_tag, ... }
}
```

**Yanıt (`201 Created`):**
```json
{
  "success": true,
  "document_id": "91b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  "target_device_id": "c3947f5d-5d68-49a4-8c81-7090f45e1122",
  "encrypted_dek": "base64_rsa_oaep_encrypted_aes_key...",
  "iv": "base64_12_byte_gcm_iv...",
  "auth_tag": "base64_16_byte_gcm_tag...",
  "storage_url": "s3://docbind-encrypted-vault/00000000-0000-4000-8000-000000000001/91b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d.enc",
  "payload_url": "/v1/documents/91b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d/payload",
  "encrypted_document": "base64_aes_256_gcm_ciphertext_with_tag..."
}
```

---

### 4.4. Şifreli Belge Yükünü Çekme — `GET /v1/documents/:id/payload`

İstemci SDK'sı (`<DocumentSealer.Viewer />` veya `DocumentSealer.fetchAndDecryptInMemory`) bu uç noktayı çağırarak şifreli belgeyi ve sarılmış DEK'i indirir.
- İstek başlığında `x-device-id` veya `x-hardware-hash` gönderildiğinde sunucu bunları hedef cihaz kaydıyla karşılaştırır; uyuşmazlık varsa `403 Forbidden` döner.
- Cihaz iptal edilmişse (`REVOKED`), `403 Forbidden` döner.

**İstek (`curl`):**
```bash
curl -X GET http://localhost:4000/v1/documents/91b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d/payload \
  -H "x-api-key: docbind_dev_api_key_2026" \
  -H "x-device-id: c3947f5d-5d68-49a4-8c81-7090f45e1122" \
  -H "x-hardware-hash: 4a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b"
```

---

### 4.5. Cihaz İptali (Uzaktan Yetki Kaldırma) — `POST /v1/devices/:id/revoke`

Bir çalışanın cihazı çalındığında veya kurumdaki görevi sona erdiğinde cihazı iptal eder. İptal edilen cihaz için yeni belge mühürlenemez ve mevcut belgelerin şifreli yükleri indirilemez.

```bash
curl -X POST http://localhost:4000/v1/devices/c3947f5d-5d68-49a4-8c81-7090f45e1122/revoke \
  -H "x-api-key: docbind_dev_api_key_2026"
```

---

## 📱 5. CLIENT SDK (`@secure-doc/sdk`) ENTEGRASYON REHBERİ

### 5.1. SDK Yapılandırması ve Cihaz Kaydı (`getDeviceToken`)

Uygulama başlangıcında `DocumentSealer.configure()` çağrılır ve ardından `DocumentSealer.getDeviceToken()` ile cihazın donanım anahtarı oluşturulup sunucuya kaydedilir:

```typescript
import { DocumentSealer } from '@secure-doc/sdk';

// 1. SDK'yı yapılandırın
DocumentSealer.configure({
  apiUrl: 'http://localhost:4000',
  apiKey: 'docbind_dev_api_key_2026',
});

// 2. Cihazı kaydedin ve kayıtlı Cihaz ID'sini alın
async function initializeDeviceSecurity() {
  const deviceInfo = await DocumentSealer.getDeviceToken();

  console.log('Kayıtlı Cihaz ID (Backend target_device_id):', deviceInfo.deviceId);
  console.log('Donanım Parmak İzi (SHA-256):', deviceInfo.hardwareHash);
  console.log('Taşınabilir Cihaz Tokenı:', deviceInfo.token);

  // deviceInfo.deviceId değerini kendi B2B backend'inize kaydedin.
  // Kullanıcıya özel PDF mühürlerken POST /v1/documents/seal isteğinde
  // target_device_id olarak bu değeri kullanacaksınız.
  return deviceInfo;
}
```

---

### 5.2. React (Web) Güvenli PDF Görüntüleyici (`<DocumentSealer.Viewer />`)

`<DocumentSealer.Viewer />` bileşeni şifreli yükü indirir, WebCrypto `unwrapKey` ile RAM'de çözer, dinamik filigran (`watermark`) basar ve ekran görüntüsü / yazdırma (`@media print`, `PrintScreen`, sekme gizlenmesi, pencere odağı kaybı) korumalarını etkinleştirir:

```tsx
import React from 'react';
import { DocumentSealer } from '@secure-doc/sdk';

interface ContractViewerProps {
  documentId: string;
  currentUserEmail: string;
  currentUserIp: string;
}

export const ConfidentialContractViewer: React.FC<ContractViewerProps> = ({
  documentId,
  currentUserEmail,
  currentUserIp,
}) => {
  return (
    <DocumentSealer.Viewer
      payloadUrl={`http://localhost:4000/v1/documents/${documentId}/payload`}
      preventScreenshot={true}
      watermark={{
        text: `${currentUserEmail} | ${currentUserIp}`,
        color: 'rgba(0, 0, 0, 0.12)',
        fontSize: 18,
        angle: -30,
      }}
      onDocumentLoaded={({ documentId, byteLength }) => {
        console.log(`Belge (${documentId}) RAM'de çözüldü: ${byteLength} bayt`);
      }}
      onSecurityViolation={(reason) => {
        console.warn('Güvenlik ihlali / ekran yakalama girişimi algılandı:', reason);
      }}
      onError={(err) => {
        console.error('Belge şifre çözme veya yetki hatası:', err.message);
      }}
    />
  );
};
```

---

### 5.3. React Native (iOS & Android) Entegrasyonu

React Native ortamında donanım tabanlı anahtar deposu (`AndroidKeyStore` / `iOS Keychain`) ve işletim sistemi seviyesinde ekran görüntüsü engelleme (`FLAG_SECURE` / `UIScreen.capturedDidChangeNotification`) köprülerini bağlamak için `createReactNativeKeystore` ve `createReactNativeScreenGuard` yardımcılarını kullanın:

```tsx
import React from 'react';
import { NativeModules, NativeEventEmitter } from 'react-native';
import DeviceInfo from 'react-native-device-info';
import {
  DocumentSealer,
  createReactNativeScreenGuard,
  createReactNativeKeystore,
} from '@secure-doc/sdk';

const { DocBindScreenGuard } = NativeModules;
const screenGuardEmitter = DocBindScreenGuard
  ? new NativeEventEmitter(DocBindScreenGuard)
  : null;

// 1. React Native Donanım Köprüleri ile SDK'yı Yapılandırın
DocumentSealer.configure({
  apiUrl: 'https://api.sirketiniz.com',
  apiKey: 'db_live_...',
  nativeModules: {
    deviceInfo: DeviceInfo,
    secureKeystore: createReactNativeKeystore(DocBindScreenGuard),
    screenGuard: createReactNativeScreenGuard({
      enableSecureFlag: () => DocBindScreenGuard?.enableSecureFlag(),
      disableSecureFlag: () => DocBindScreenGuard?.disableSecureFlag(),
      isScreenCaptured: async () => {
        const res = await DocBindScreenGuard?.isScreenCaptured();
        return Boolean(res?.isCaptured);
      },
      addCaptureListener: (cb) => {
        const sub = screenGuardEmitter?.addListener('onScreenCaptureChanged', cb);
        return { remove: () => sub?.remove() };
      },
    }),
  },
});

// 2. React Native İçinde Bellek İçi (Base64/Uint8Array) PDF Render Etme
export function MobileSecurePdfScreen({ payloadUrl }: { payloadUrl: string }) {
  return (
    <DocumentSealer.Viewer
      payloadUrl={payloadUrl}
      preventScreenshot={true}
      watermark={{ text: 'mobil-kullanici@sirket.com', color: 'rgba(255,0,0,0.12)' }}
      renderNativePdf={({ bytes, base64InMemory }) => (
        // Örn: react-native-pdf veya özel bellek içi PDF bileşenine dosya yolu YERİNE
        // doğrudan RAM'deki base64 veri akışını verin (cache: false):
        // <Pdf source={{ uri: `data:application/pdf;base64,${base64InMemory}`, cache: false }} />
        null
      )}
    />
  );
}
```

> **Yerel (Native) Modül Kaynak Kodları:**
> - **Android (`FLAG_SECURE` + `AndroidKeyStore`):** `packages/sdk/native/android/DocBindModule.kt`
> - **iOS (`UIScreen.capturedDidChangeNotification` + `Keychain`):** `packages/sdk/native/ios/DocBindModule.swift`

---

### 5.4. Düşük Seviyeli Programatik Şifre Çözme (`fetchAndDecryptInMemory`)

Kendi özel görüntüleyicinizi (örneğin özel bir Canvas/WebAssembly PDF motoru) kullanmak istiyorsanız, şifreli belgeyi doğrudan RAM'de `Uint8Array` olarak çözebilirsiniz:

```typescript
import { DocumentSealer } from '@secure-doc/sdk';

async function renderWithCustomEngine(payloadUrl: string) {
  const decryptedDoc = await DocumentSealer.fetchAndDecryptInMemory(payloadUrl);

  try {
    console.log('Belge ID:', decryptedDoc.documentId);
    console.log('RAM Byte Uzunluğu:', decryptedDoc.bytes.byteLength);

    // decryptedDoc.bytes (Uint8Array) doğrudan PDF.js veya WebAssembly motoruna verilir:
    // await pdfjsLib.getDocument({ data: decryptedDoc.bytes }).promise;
  } finally {
    // KRİTİK: İşlem bittiğinde veya sayfa kapandığında RAM tamponunu sıfırlayın!
    decryptedDoc.dispose();
  }
}
```

---

## 🛠️ 6. HATA KODLARI VE SORUN GİDERME (TROUBLESHOOTING)

| HTTP Kodu / Hata Mesajı | Nedeni | Çözümü |
| :--- | :--- | :--- |
| `401 Unauthorized` (`Missing API key` / `Invalid API key`) | `x-api-key` başlığı eksik veya geçersiz. | İstek başlığına geçerli organizasyon anahtarını (`x-api-key: docbind_dev_api_key_2026`) ekleyin. |
| `400 Bad Request` (`RSA key modulus length is below minimum 2048 bits`) | Cihaz kaydında 2048 bitten düşük veya bozuk bir PEM açık anahtarı gönderildi. | `DocumentSealer.getDeviceToken()` veya `DeviceKeyStore` kullanarak standart 2048-bit `RSA-OAEP` SPKI PEM anahtarı üretin. |
| `403 Forbidden` (`Target device is revoked or inactive`) | Hedef cihaz `/v1/devices/:id/revoke` ile iptal edilmiş. | Cihazı yeniden yetkilendirmek için `/v1/devices/register` ile tekrar kaydedin. |
| `403 Forbidden` (`Hardware fingerprint mismatch` / `Device ID mismatch`) | Belge başka bir cihaza mühürlenmiş ancak farklı bir cihazdan açılmaya çalışılıyor. | Belgeyi açmaya çalışan cihazın `deviceId` değeri ile mühürleme sırasında kullanılan `target_device_id` değerinin aynı olduğundan emin olun. |
| `OperationError` / `Unsupported state or unable to authenticate data` | WebCrypto `AES-GCM` şifre çözme hatası (AAD veya özel anahtar uyuşmazlığı). | Cihazın IndexedDB anahtar deposu sıfırlanmış olabilir; `DocumentSealer.getDeviceToken({ forceRefresh: true })` ile cihazı yeniden kaydedip belgeyi tekrar mühürleyin. |
