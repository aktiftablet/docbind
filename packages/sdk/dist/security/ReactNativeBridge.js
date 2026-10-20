"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createReactNativeScreenGuard = createReactNativeScreenGuard;
exports.createReactNativeKeystore = createReactNativeKeystore;
/**
 * React Native NativeModule adapter for Android `WindowManager.LayoutParams.FLAG_SECURE`
 * and iOS `UIScreen.capturedDidChangeNotification`.
 *
 * Automatically connects to `NativeModules.DocBindScreenGuard` or custom native module
 * when running inside a React Native runtime.
 */
function createReactNativeScreenGuard(nativeModuleOverride) {
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
        addCaptureChangeListener(listener) {
            if (nativeModuleOverride?.addCaptureListener) {
                const sub = nativeModuleOverride.addCaptureListener(listener);
                return () => sub.remove();
            }
            return () => { };
        },
    };
}
/**
 * React Native NativeModule adapter for hardware-backed asymmetric key storage:
 * - Android Keystore (`KeyProperties.KEY_ALGORITHM_RSA`, `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`)
 * - iOS Keychain / Secure Enclave (`kSecKeyAlgorithmRSAEncryptionOAEPSHA256`)
 */
function createReactNativeKeystore(nativeModule) {
    return {
        async hasKeyPair(alias) {
            return nativeModule.hasKeyPair(alias);
        },
        async generateRsaKeyPair(alias) {
            const res = await nativeModule.generateRsaKeyPair(alias);
            if (typeof res === 'string') {
                return { publicKeyPem: res };
            }
            return res;
        },
        async getPublicKeyPem(alias) {
            return nativeModule.getPublicKeyPem(alias);
        },
        async rsaOaepDecrypt(alias, encryptedDekBase64) {
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
//# sourceMappingURL=ReactNativeBridge.js.map