"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecureDocumentViewer = exports.DocumentSealer = void 0;
const DocumentSealer_js_1 = require("./DocumentSealer.js");
Object.defineProperty(exports, "DocumentSealer", { enumerable: true, get: function () { return DocumentSealer_js_1.DocumentSealer; } });
const Viewer_js_1 = require("./components/Viewer.js");
Object.defineProperty(exports, "SecureDocumentViewer", { enumerable: true, get: function () { return Viewer_js_1.SecureDocumentViewer; } });
// Ensure DocumentSealer.Viewer is always bound when importing from '@secure-doc/sdk'
DocumentSealer_js_1.DocumentSealer.Viewer = Viewer_js_1.SecureDocumentViewer;
__exportStar(require("./types.js"), exports);
__exportStar(require("./media.js"), exports);
__exportStar(require("./fingerprint/HardwareFingerprint.js"), exports);
__exportStar(require("./crypto/KeyStore.js"), exports);
__exportStar(require("./security/ScreenCaptureGuard.js"), exports);
__exportStar(require("./security/ReactNativeBridge.js"), exports);
//# sourceMappingURL=index.js.map