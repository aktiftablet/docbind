import type { ReactNativeDeviceInfoLike } from '../types.js';

/**
 * Generates a deterministic SHA-256 hardware fingerprint hash (`hardware_hash`)
 * from device-specific hardware signals on React Native (`react-native-device-info`)
 * or Web (WebGL GPU renderer, CPU concurrency, memory, display geometry, platform).
 */
export class HardwareFingerprint {
  /**
   * Collects hardware attributes and returns a 64-character hex SHA-256 digest.
   */
  public static async generateHash(
    customDeviceInfo?: ReactNativeDeviceInfoLike
  ): Promise<{ hardwareHash: string; metadata: Record<string, unknown> }> {
    const rnDeviceInfo = customDeviceInfo ?? (await this.tryLoadReactNativeDeviceInfo());

    if (rnDeviceInfo) {
      const [uniqueId, hardware, totalMemory] = await Promise.all([
        Promise.resolve(rnDeviceInfo.getUniqueId()),
        Promise.resolve(rnDeviceInfo.getHardware ? rnDeviceInfo.getHardware() : 'unknown-hw'),
        Promise.resolve(rnDeviceInfo.getTotalMemory ? rnDeviceInfo.getTotalMemory() : 0),
      ]);
      const deviceId = rnDeviceInfo.getDeviceId ? rnDeviceInfo.getDeviceId() : 'unknown-model';
      const brand = rnDeviceInfo.getBrand ? rnDeviceInfo.getBrand() : 'unknown-brand';
      const systemName = rnDeviceInfo.getSystemName ? rnDeviceInfo.getSystemName() : 'ReactNative';

      const canonicalString = [
        `platform:${systemName}`,
        `brand:${brand}`,
        `deviceId:${deviceId}`,
        `hardware:${hardware}`,
        `memory:${totalMemory}`,
        `uniqueId:${uniqueId}`,
      ].join('|');

      const hardwareHash = await this.sha256Hex(canonicalString);
      return {
        hardwareHash,
        metadata: {
          platform: systemName,
          brand,
          deviceId,
          hardware,
          totalMemory,
        },
      };
    }

    // Browser / Web / Node environment hardware traits
    const webTraits = this.collectWebHardwareTraits();
    const canonicalString = [
      `platform:${webTraits.platform}`,
      `cores:${webTraits.hardwareConcurrency}`,
      `memory:${webTraits.deviceMemory}`,
      `screen:${webTraits.screenResolution}`,
      `colorDepth:${webTraits.colorDepth}`,
      `gpu:${webTraits.gpuRenderer}`,
      `timezone:${webTraits.timezone}`,
    ].join('|');

    const hardwareHash = await this.sha256Hex(canonicalString);
    return {
      hardwareHash,
      metadata: webTraits,
    };
  }

  private static async tryLoadReactNativeDeviceInfo(): Promise<ReactNativeDeviceInfoLike | null> {
    try {
      // Dynamic import for React Native environments where react-native-device-info is installed
      const moduleName = 'react-native-device-info';
      const mod = await import(/* webpackIgnore: true */ moduleName);
      const api = mod.default ?? mod;
      if (api && typeof api.getUniqueId === 'function') {
        return api as ReactNativeDeviceInfoLike;
      }
    } catch {
      // Not running in React Native or module not installed
    }
    return null;
  }

  private static collectWebHardwareTraits(): Record<string, unknown> {
    const isBrowser = typeof window !== 'undefined' && typeof navigator !== 'undefined';
    if (!isBrowser) {
      return {
        platform: `node-${process.platform}-${process.arch}`,
        hardwareConcurrency: 4,
        deviceMemory: 8,
        screenResolution: 'headless',
        colorDepth: 24,
        gpuRenderer: 'node-v8',
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
      };
    }

    const nav = navigator as Navigator & { deviceMemory?: number };
    const scr = window.screen;
    let gpuRenderer = 'unknown-gpu';

    try {
      if (typeof document !== 'undefined') {
        const canvas = document.createElement('canvas');
        const gl =
          (canvas.getContext('webgl') as WebGLRenderingContext | null) ||
          (canvas.getContext('experimental-webgl') as WebGLRenderingContext | null);
        if (gl) {
          const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
          if (debugInfo) {
            gpuRenderer =
              String(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)) || gpuRenderer;
          }
        }
      }
    } catch {
      // Ignore WebGL access errors
    }

    return {
      platform: nav.platform || 'web',
      hardwareConcurrency: nav.hardwareConcurrency || 1,
      deviceMemory: nav.deviceMemory || 0,
      screenResolution: scr ? `${scr.width}x${scr.height}@${window.devicePixelRatio || 1}` : '0x0',
      colorDepth: scr ? scr.colorDepth : 24,
      gpuRenderer,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
    };
  }

  public static async sha256Hex(input: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) {
      throw new Error('WebCrypto SubtleCrypto API is not available in this environment.');
    }
    const digestBuffer = await subtle.digest('SHA-256', data);
    const byteArray = new Uint8Array(digestBuffer);
    return Array.from(byteArray)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
}
