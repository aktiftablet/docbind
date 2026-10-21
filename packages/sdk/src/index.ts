import { DocumentSealer } from './DocumentSealer.js';
import { SecureDocumentViewer } from './components/Viewer.js';

// Ensure DocumentSealer.Viewer is always bound when importing from '@secure-doc/sdk'
DocumentSealer.Viewer = SecureDocumentViewer;

export { DocumentSealer, SecureDocumentViewer };
export * from './types.js';
export * from './media.js';
export * from './fingerprint/HardwareFingerprint.js';
export * from './crypto/KeyStore.js';
export * from './security/ScreenCaptureGuard.js';
export * from './security/ReactNativeBridge.js';
