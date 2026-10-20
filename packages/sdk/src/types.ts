export interface WatermarkConfig {
  /** Watermark text to display across the document (e.g. "user@ip") */
  text: string;
  /** CSS/RGBA color string (e.g. "rgba(0,0,0,0.1)") */
  color?: string;
  /** Optional font size in pixels (default: 18) */
  fontSize?: number;
  /** Optional rotation angle in degrees (default: -30) */
  angle?: number;
}

export interface DocumentSealerConfig {
  /** Base URL of the DocBind Backend API (e.g. "http://localhost:4000") */
  apiUrl?: string;
  /** Organization API Key for authenticating device registration & payload requests */
  apiKey?: string;
  /** Optional custom fetch implementation */
  customFetch?: typeof fetch;
  /** Optional custom React Native native bridge modules */
  nativeModules?: {
    deviceInfo?: ReactNativeDeviceInfoLike;
    secureKeystore?: NativeHardwareKeystoreLike;
    screenGuard?: NativeScreenGuardLike;
  };
}

export interface DeviceTokenResult {
  /** Registered Device UUID returned by backend (or local deterministic token prior to registration) */
  deviceId: string;
  /** SHA-256 hardware fingerprint hash */
  hardwareHash: string;
  /** RSA-OAEP 2048 Public Key in PEM SPKI format */
  publicKeyPem: string;
  /** Encoded token string combining deviceId and hardwareHash for SDK transport */
  token: string;
}

export interface EncryptedDocumentPayload {
  document_id: string;
  target_device_id: string;
  mime_type?: string;
  original_name?: string | null;
  /** Base64-encoded AES-256 DEK encrypted with Device RSA-OAEP-256 Public Key */
  encrypted_dek: string;
  /** Base64-encoded 12-byte GCM IV */
  iv: string;
  /** Base64-encoded 16-byte GCM Auth Tag */
  auth_tag: string;
  /** Base64-encoded AES-256-GCM ciphertext (with 16-byte auth tag appended) */
  encrypted_document: string;
}

export interface DecryptedDocumentInMemory {
  documentId: string;
  targetDeviceId: string;
  mimeType: string;
  originalName?: string | null;
  /** In-memory decrypted PDF byte array. NEVER written to disk. */
  bytes: Uint8Array;
  /** Wipes the decrypted bytes from RAM when the viewer unmounts */
  dispose: () => void;
}

export interface SecureViewerProps {
  /** URL to fetch the encrypted document payload (`GET /v1/documents/:id/payload`) */
  payloadUrl: string;
  /** Enforces OS/Browser anti-screenshot & screen recording protections (default: true) */
  preventScreenshot?: boolean;
  /** Dynamic watermark overlay configuration */
  watermark?: WatermarkConfig;
  /** Optional API key override for fetching payloadUrl */
  apiKey?: string;
  /** Optional callback fired when document is decrypted in memory */
  onDocumentLoaded?: (meta: { documentId: string; byteLength: number }) => void;
  /** Optional callback fired on decryption or network error */
  onError?: (error: Error) => void;
  /** Optional callback fired when screenshot or screen capture is detected */
  onSecurityViolation?: (reason: string) => void;
  /** Custom render override for React Native in-memory PDF view (receives Uint8Array/Base64 in RAM) */
  renderNativePdf?: (data: { bytes: Uint8Array; base64InMemory: string }) => unknown;
}

export interface ReactNativeDeviceInfoLike {
  getUniqueId: () => Promise<string> | string;
  getDeviceId?: () => string;
  getBrand?: () => string;
  getSystemName?: () => string;
  getHardware?: () => Promise<string> | string;
  getTotalMemory?: () => Promise<number> | number;
}

export interface NativeHardwareKeystoreLike {
  hasKeyPair: (alias: string) => Promise<boolean>;
  generateRsaKeyPair: (alias: string) => Promise<{ publicKeyPem: string }>;
  getPublicKeyPem: (alias: string) => Promise<string>;
  rsaOaepDecrypt: (alias: string, encryptedDekBase64: string) => Promise<Uint8Array>;
}

export interface NativeScreenGuardLike {
  /** Android: WindowManager.LayoutParams.FLAG_SECURE */
  enableSecureFlag: () => Promise<void> | void;
  disableSecureFlag: () => Promise<void> | void;
  /** iOS: UIScreen.capturedDidChangeNotification & UIApplicationUserDidTakeScreenshotNotification */
  isScreenCaptured?: () => Promise<boolean> | boolean;
  addCaptureChangeListener?: (listener: (isCaptured: boolean) => void) => () => void;
}
