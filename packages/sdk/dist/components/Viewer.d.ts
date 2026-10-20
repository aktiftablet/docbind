import React from 'react';
import type { SecureViewerProps } from '../types.js';
/**
 * `<DocumentSealer.Viewer />`
 *
 * Security guarantees:
 * 1. **Zero Disk Writes**: Fetches the encrypted payload, unwraps the AES-256-GCM DEK via the
 *    device's hardware/non-extractable RSA-OAEP private key, and holds the decrypted `Uint8Array`
 *    strictly in application memory (`RAM`), wiping (`bytes.fill(0)`) on unmount.
 * 2. **Anti-Screenshot & Screen Capture Protection**:
 *    - Android: Enforces `WindowManager.LayoutParams.FLAG_SECURE`.
 *    - iOS: Monitors `UIScreen.capturedDidChangeNotification` to immediately obscure the view.
 *    - Web: Intercepts PrintScreen / OS capture shortcuts, window blur, and `@media print`.
 * 3. **Dynamic Watermark Overlay**: Renders a non-interactive repeating diagonal watermark
 *    grid (`watermark.text`, `watermark.color`) across the entire viewport.
 */
export declare const SecureDocumentViewer: React.FC<SecureViewerProps>;
//# sourceMappingURL=Viewer.d.ts.map