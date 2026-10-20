"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScreenCaptureGuard = void 0;
/**
 * Enforces platform-specific anti-screenshot & screen recording countermeasures:
 * - Android: Activates `WindowManager.LayoutParams.FLAG_SECURE` via NativeModule / RN bridge.
 * - iOS: Subscribes to `UIScreen.capturedDidChangeNotification` & `UIApplicationUserDidTakeScreenshotNotification`
 *   to immediately blur/hide the secure document view.
 * - Web: Obscures view on window blur, tab `visibilitychange`, PrintScreen / OS screenshot shortcuts,
 *   and injects `@media print` suppression rules.
 */
class ScreenCaptureGuard {
    static activate(callbacks, customGuard) {
        const cleanups = [];
        // 1. Mobile Native Screen Guard (Android FLAG_SECURE + iOS UIScreen.capturedDidChangeNotification)
        if (customGuard) {
            Promise.resolve(customGuard.enableSecureFlag()).catch(() => { });
            cleanups.push(() => {
                Promise.resolve(customGuard.disableSecureFlag()).catch(() => { });
            });
            if (customGuard.isScreenCaptured) {
                Promise.resolve(customGuard.isScreenCaptured())
                    .then((captured) => {
                    if (captured) {
                        callbacks.onCaptureStateChange(true, 'iOS UIScreen.isCaptured active (Screen Recording / AirPlay Mirroring detected)');
                    }
                })
                    .catch(() => { });
            }
            if (customGuard.addCaptureChangeListener) {
                const unsubscribe = customGuard.addCaptureChangeListener((isCaptured) => {
                    callbacks.onCaptureStateChange(isCaptured, isCaptured
                        ? 'UIScreen.capturedDidChangeNotification triggered'
                        : undefined);
                });
                cleanups.push(unsubscribe);
            }
        }
        // 2. Web / DOM Protections
        if (typeof window !== 'undefined' && typeof document !== 'undefined') {
            const handleVisibilityChange = () => {
                if (document.visibilityState !== 'visible') {
                    callbacks.onCaptureStateChange(true, 'Document tab hidden or backgrounded');
                }
                else {
                    callbacks.onCaptureStateChange(false);
                }
            };
            const handleWindowBlur = () => {
                callbacks.onCaptureStateChange(true, 'Window lost focus (potential snipping tool active)');
            };
            const handleWindowFocus = () => {
                callbacks.onCaptureStateChange(false);
            };
            const handleKeyDown = (e) => {
                const isPrintScreen = e.key === 'PrintScreen' || e.keyCode === 44;
                const isMacScreenshot = e.metaKey && e.shiftKey && ['3', '4', '5', 's', 'S'].includes(e.key);
                const isWinSnip = e.metaKey && e.shiftKey && (e.key === 's' || e.key === 'S');
                const isPrint = (e.ctrlKey || e.metaKey) && (e.key === 'p' || e.key === 'P');
                if (isPrintScreen || isMacScreenshot || isWinSnip || isPrint) {
                    e.preventDefault();
                    e.stopPropagation();
                    callbacks.onCaptureStateChange(true, `Screenshot or print shortcut intercepted (${e.key})`);
                }
            };
            document.addEventListener('visibilitychange', handleVisibilityChange);
            window.addEventListener('blur', handleWindowBlur);
            window.addEventListener('focus', handleWindowFocus);
            window.addEventListener('keydown', handleKeyDown, { capture: true });
            cleanups.push(() => {
                document.removeEventListener('visibilitychange', handleVisibilityChange);
                window.removeEventListener('blur', handleWindowBlur);
                window.removeEventListener('focus', handleWindowFocus);
                window.removeEventListener('keydown', handleKeyDown, { capture: true });
            });
        }
        return () => {
            for (const cleanup of cleanups) {
                cleanup();
            }
        };
    }
}
exports.ScreenCaptureGuard = ScreenCaptureGuard;
//# sourceMappingURL=ScreenCaptureGuard.js.map