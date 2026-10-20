import type { ReactNativeDeviceInfoLike } from '../types.js';
/**
 * Generates a deterministic SHA-256 hardware fingerprint hash (`hardware_hash`)
 * from device-specific hardware signals on React Native (`react-native-device-info`)
 * or Web (WebGL GPU renderer, CPU concurrency, memory, display geometry, platform).
 */
export declare class HardwareFingerprint {
    /**
     * Collects hardware attributes and returns a 64-character hex SHA-256 digest.
     */
    static generateHash(customDeviceInfo?: ReactNativeDeviceInfoLike): Promise<{
        hardwareHash: string;
        metadata: Record<string, unknown>;
    }>;
    private static tryLoadReactNativeDeviceInfo;
    private static collectWebHardwareTraits;
    static sha256Hex(input: string): Promise<string>;
}
//# sourceMappingURL=HardwareFingerprint.d.ts.map