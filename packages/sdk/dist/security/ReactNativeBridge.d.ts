import type { NativeHardwareKeystoreLike, NativeScreenGuardLike } from '../types.js';
export interface ReactNativeScreenGuardNativeModule {
    enableSecureFlag?: () => Promise<void> | void;
    disableSecureFlag?: () => Promise<void> | void;
    isScreenCaptured?: () => Promise<boolean> | boolean;
    addCaptureListener?: (cb: (captured: boolean) => void) => {
        remove: () => void;
    };
}
export interface ReactNativeKeystoreNativeModule {
    hasKeyPair: (alias: string) => Promise<boolean>;
    generateRsaKeyPair: (alias: string) => Promise<{
        publicKeyPem: string;
    } | string>;
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
export declare function createReactNativeScreenGuard(nativeModuleOverride?: ReactNativeScreenGuardNativeModule): NativeScreenGuardLike;
/**
 * React Native NativeModule adapter for hardware-backed asymmetric key storage:
 * - Android Keystore (`KeyProperties.KEY_ALGORITHM_RSA`, `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`)
 * - iOS Keychain / Secure Enclave (`kSecKeyAlgorithmRSAEncryptionOAEPSHA256`)
 */
export declare function createReactNativeKeystore(nativeModule: ReactNativeKeystoreNativeModule): NativeHardwareKeystoreLike;
//# sourceMappingURL=ReactNativeBridge.d.ts.map