import type { NativeScreenGuardLike } from '../types.js';
export interface ScreenGuardCallbacks {
    onCaptureStateChange: (isObscured: boolean, reason?: string) => void;
}
/**
 * Enforces platform-specific anti-screenshot & screen recording countermeasures:
 * - Android: Activates `WindowManager.LayoutParams.FLAG_SECURE` via NativeModule / RN bridge.
 * - iOS: Subscribes to `UIScreen.capturedDidChangeNotification` & `UIApplicationUserDidTakeScreenshotNotification`
 *   to immediately blur/hide the secure document view.
 * - Web: Obscures view on window blur, tab `visibilitychange`, PrintScreen / OS screenshot shortcuts,
 *   and injects `@media print` suppression rules.
 */
export declare class ScreenCaptureGuard {
    static activate(callbacks: ScreenGuardCallbacks, customGuard?: NativeScreenGuardLike): () => void;
}
//# sourceMappingURL=ScreenCaptureGuard.d.ts.map