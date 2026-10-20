import type { NativeHardwareKeystoreLike, NativeScreenGuardLike } from '../types.js';

export interface ReactNativeScreenGuardNativeModule {
  enableSecureFlag?: () => Promise<void> | void;
  disableSecureFlag?: () => Promise<void> | void;
  isScreenCaptured?: () => Promise<boolean> | boolean;
  addCaptureListener?: (cb: (captured: boolean) => void) => { remove: () => void };
}

export interface ReactNativeKeystoreNativeModule {
  hasKeyPair: (alias: string) => Promise<boolean>;
  generateRsaKeyPair: (alias: string) => Promise<{ publicKeyPem: string } | string>;
  getPublicKeyPem: (alias: string) => Promise<string>;
  rsaOaepDecrypt: (alias: string, encryptedDekBase64: string) => Promise<string | Uint8Array>;
}

/**
 * React Native NativeModule adapter for Android `WindowManager.LayoutParams.FLAG_SECURE`
 * and iOS `UIScreen.capturedDidChangeNotification`.
 *
 * Automatically connects to `NativeModules.DocBindScreenGuard` or custom native module
 * when running inside a React Native runtime.
 */
export function createReactNativeScreenGuard(
  nativeModuleOverride?: ReactNativeScreenGuardNativeModule
): NativeScreenGuardLike {
  return {
    async enableSecureFlag() {
      if (nativeModuleOverride?.enableSecureFlag) {
        await nativeModuleOverride.enableSecureFlag();
      }
    },
    async disableSecureFlag() {
      if (nativeModuleOverride?.disableSecureFlag) {
        await nativeModuleOverride.disableSecureFlag();
      }
    },
    async isScreenCaptured() {
      if (nativeModuleOverride?.isScreenCaptured) {
        return await nativeModuleOverride.isScreenCaptured();
      }
      return false;
    },
    addCaptureChangeListener(listener: (isCaptured: boolean) => void) {
      if (nativeModuleOverride?.addCaptureListener) {
        const sub = nativeModuleOverride.addCaptureListener(listener);
        return () => sub.remove();
      }
      return () => {};
    },
  };
}

/**
 * React Native NativeModule adapter for hardware-backed asymmetric key storage:
 * - Android Keystore (`KeyProperties.KEY_ALGORITHM_RSA`, `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`)
 * - iOS Keychain / Secure Enclave (`kSecKeyAlgorithmRSAEncryptionOAEPSHA256`)
 */
export function createReactNativeKeystore(
  nativeModule: ReactNativeKeystoreNativeModule
): NativeHardwareKeystoreLike {
  return {
    async hasKeyPair(alias: string): Promise<boolean> {
      return nativeModule.hasKeyPair(alias);
    },
    async generateRsaKeyPair(alias: string): Promise<{ publicKeyPem: string }> {
      const res = await nativeModule.generateRsaKeyPair(alias);
      if (typeof res === 'string') {
        return { publicKeyPem: res };
      }
      return res;
    },
    async getPublicKeyPem(alias: string): Promise<string> {
      return nativeModule.getPublicKeyPem(alias);
    },
    async rsaOaepDecrypt(alias: string, encryptedDekBase64: string): Promise<Uint8Array> {
      const decrypted = await nativeModule.rsaOaepDecrypt(alias, encryptedDekBase64);
      if (decrypted instanceof Uint8Array) {
        return decrypted;
      }
      if (typeof Buffer !== 'undefined') {
        return new Uint8Array(Buffer.from(decrypted, 'base64'));
      }
      const binary = atob(decrypted);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    },
  };
}
