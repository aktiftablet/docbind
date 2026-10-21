"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecureDocumentViewer = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const DocumentSealer_js_1 = require("../DocumentSealer.js");
const ScreenCaptureGuard_js_1 = require("../security/ScreenCaptureGuard.js");
const media_js_1 = require("../media.js");
function bytesToBase64(bytes) {
    if (typeof Buffer !== 'undefined') {
        return Buffer.from(bytes).toString('base64');
    }
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.byteLength; i += chunk) {
        binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
}
/**
 * Extracts readable text streams or metadata from an in-memory PDF byte array
 * for zero-disk-write canvas/DOM preview alongside the in-memory PDF stream.
 */
function extractInMemoryPdfSummary(bytes) {
    const decoder = new TextDecoder('latin1');
    const rawString = decoder.decode(bytes.subarray(0, Math.min(bytes.length, 65536)));
    const isValidPdfHeader = rawString.startsWith('%PDF-');
    const headerVersion = isValidPdfHeader ? rawString.slice(0, 8).trim() : 'Unknown';
    // Extract literal strings inside PDF text objects BT ... (text) Tj ... ET
    const extractedTextBlocks = [];
    const literalRegex = /\(([^()\\]*(?:\\.[^()\\]*)*)\)\s*Tj/g;
    let match;
    while ((match = literalRegex.exec(rawString)) !== null) {
        if (match[1].trim()) {
            extractedTextBlocks.push(match[1].trim());
        }
    }
    return {
        isValidPdfHeader,
        headerVersion,
        extractedTextBlocks,
    };
}
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
const SecureDocumentViewer = ({ payloadUrl, preventScreenshot = true, watermark, apiKey, onDocumentLoaded, onError, onSecurityViolation, renderNative, renderNativePdf, }) => {
    const nativeRenderer = renderNative ?? renderNativePdf;
    const [decryptedDoc, setDecryptedDoc] = (0, react_1.useState)(null);
    const [loading, setLoading] = (0, react_1.useState)(true);
    const [error, setError] = (0, react_1.useState)(null);
    const [isScreenObscured, setIsScreenObscured] = (0, react_1.useState)(false);
    const [violationReason, setViolationReason] = (0, react_1.useState)(null);
    // 1. Activate Anti-Screenshot & Screen Recording Guard
    (0, react_1.useEffect)(() => {
        if (!preventScreenshot) {
            setIsScreenObscured(false);
            return;
        }
        const customGuard = DocumentSealer_js_1.DocumentSealer.getConfig().nativeModules?.screenGuard;
        const cleanup = ScreenCaptureGuard_js_1.ScreenCaptureGuard.activate({
            onCaptureStateChange: (obscured, reason) => {
                setIsScreenObscured(obscured);
                if (obscured && reason) {
                    setViolationReason(reason);
                    onSecurityViolation?.(reason);
                }
            },
        }, customGuard);
        return cleanup;
    }, [preventScreenshot, onSecurityViolation]);
    // 2. Fetch & Decrypt Document Strictly in RAM (Zero Disk Writes)
    (0, react_1.useEffect)(() => {
        let active = true;
        let currentDoc = null;
        setLoading(true);
        setError(null);
        DocumentSealer_js_1.DocumentSealer.fetchAndDecryptInMemory(payloadUrl, apiKey)
            .then((doc) => {
            if (!active) {
                doc.dispose();
                return;
            }
            currentDoc = doc;
            setDecryptedDoc(doc);
            setLoading(false);
            onDocumentLoaded?.({
                documentId: doc.documentId,
                byteLength: doc.bytes.byteLength,
            });
        })
            .catch((err) => {
            if (!active)
                return;
            const normalizedErr = err instanceof Error ? err : new Error(String(err || 'Decryption failed'));
            setError(normalizedErr.message);
            setLoading(false);
            onError?.(normalizedErr);
        });
        return () => {
            active = false;
            if (currentDoc) {
                // Wipe decrypted bytes from RAM immediately when component unmounts
                currentDoc.dispose();
            }
        };
    }, [payloadUrl, apiKey]);
    const category = decryptedDoc
        ? (0, media_js_1.getMediaCategory)(decryptedDoc.mimeType)
        : null;
    const pdfMeta = (0, react_1.useMemo)(() => {
        if (!decryptedDoc || category !== 'pdf')
            return null;
        return extractInMemoryPdfSummary(decryptedDoc.bytes);
    }, [decryptedDoc, category]);
    const textContent = (0, react_1.useMemo)(() => {
        if (!decryptedDoc || category !== 'text')
            return null;
        return new TextDecoder('utf-8').decode(decryptedDoc.bytes);
    }, [decryptedDoc, category]);
    // Base64 is only materialised when a native renderer needs it (RN bridges).
    const base64InMemory = (0, react_1.useMemo)(() => {
        if (!decryptedDoc || !nativeRenderer)
            return null;
        return bytesToBase64(decryptedDoc.bytes);
    }, [decryptedDoc, nativeRenderer]);
    // In-memory object URL (Blob lives in RAM, never written to disk). Revoked on unmount.
    const [objectUrl, setObjectUrl] = (0, react_1.useState)(null);
    (0, react_1.useEffect)(() => {
        if (!decryptedDoc || nativeRenderer || category === 'text') {
            setObjectUrl(null);
            return;
        }
        let url;
        if (typeof URL !== 'undefined' && typeof URL.createObjectURL === 'function' && typeof Blob !== 'undefined') {
            url = URL.createObjectURL(new Blob([decryptedDoc.bytes], { type: decryptedDoc.mimeType }));
        }
        else {
            url = `data:${decryptedDoc.mimeType};base64,${bytesToBase64(decryptedDoc.bytes)}`;
        }
        setObjectUrl(url);
        return () => {
            if (url.startsWith('blob:'))
                URL.revokeObjectURL(url);
        };
    }, [decryptedDoc, nativeRenderer, category]);
    const blockContextMenu = (e) => e.preventDefault();
    const renderMedia = () => {
        if (!decryptedDoc)
            return null;
        switch (category) {
            case 'pdf':
                if (pdfMeta?.extractedTextBlocks && pdfMeta.extractedTextBlocks.length > 0) {
                    return ((0, jsx_runtime_1.jsx)("div", { "data-testid": "docbind-pdf-text-layer", style: { lineHeight: 1.6 }, children: pdfMeta.extractedTextBlocks.map((line, i) => ((0, jsx_runtime_1.jsx)("p", { style: { margin: '8px 0', fontSize: '15px' }, children: line }, i))) }));
                }
                return (objectUrl && ((0, jsx_runtime_1.jsx)("object", { "data-testid": "docbind-pdf-object", data: `${objectUrl}#toolbar=0&navpanes=0&scrollbar=0`, type: decryptedDoc.mimeType, width: "100%", height: "400px", children: (0, jsx_runtime_1.jsxs)("p", { children: ["In-Memory Decrypted PDF (", decryptedDoc.bytes.byteLength, " bytes)"] }) })));
            case 'image':
                return (objectUrl && ((0, jsx_runtime_1.jsx)("img", { "data-testid": "docbind-image", src: objectUrl, alt: decryptedDoc.originalName ?? 'Secure image', draggable: false, onContextMenu: blockContextMenu, style: { maxWidth: '100%', maxHeight: '600px', display: 'block', margin: '0 auto', userSelect: 'none' } })));
            case 'video':
                return (objectUrl && ((0, jsx_runtime_1.jsx)("video", { "data-testid": "docbind-video", src: objectUrl, controls: true, controlsList: "nodownload noremoteplayback", disablePictureInPicture: true, onContextMenu: blockContextMenu, style: { width: '100%', maxHeight: '600px', backgroundColor: '#000' } })));
            case 'audio':
                return (objectUrl && ((0, jsx_runtime_1.jsx)("audio", { "data-testid": "docbind-audio", src: objectUrl, controls: true, controlsList: "nodownload", onContextMenu: blockContextMenu, style: { width: '100%' } })));
            case 'text':
                return ((0, jsx_runtime_1.jsx)("pre", { "data-testid": "docbind-text", style: { whiteSpace: 'pre-wrap', fontSize: '14px', userSelect: 'none' }, children: textContent }));
            default:
                return ((0, jsx_runtime_1.jsxs)("div", { "data-testid": "docbind-unsupported", style: { padding: '24px', textAlign: 'center' }, children: [(0, jsx_runtime_1.jsxs)("p", { children: ["Preview is not available for ", (0, jsx_runtime_1.jsx)("code", { children: decryptedDoc.mimeType }), " in the browser."] }), (0, jsx_runtime_1.jsxs)("p", { style: { fontSize: '13px', color: '#64748b' }, children: ["Use the ", (0, jsx_runtime_1.jsx)("code", { children: "renderNative" }), " prop to supply a custom in-memory renderer."] })] }));
        }
    };
    const containerStyle = {
        position: 'relative',
        width: '100%',
        minHeight: '480px',
        backgroundColor: '#0f172a',
        color: '#f8fafc',
        borderRadius: '8px',
        overflow: 'hidden',
        userSelect: 'none',
        WebkitUserSelect: 'none',
        fontFamily: 'system-ui, -apple-system, sans-serif',
    };
    const watermarkCells = (0, react_1.useMemo)(() => {
        if (!watermark?.text)
            return [];
        return Array.from({ length: 24 }, (_, idx) => idx);
    }, [watermark?.text]);
    return ((0, jsx_runtime_1.jsxs)("div", { "data-testid": "docbind-secure-viewer", "data-prevent-screenshot": String(preventScreenshot), "data-obscured": String(isScreenObscured), style: containerStyle, onContextMenu: (e) => e.preventDefault(), onCopy: (e) => e.preventDefault(), onDragStart: (e) => e.preventDefault(), children: [preventScreenshot && ((0, jsx_runtime_1.jsx)("style", { children: `
          @media print {
            [data-testid="docbind-secure-viewer"] {
              display: none !important;
            }
          }
        ` })), loading && ((0, jsx_runtime_1.jsx)("div", { "data-testid": "docbind-viewer-loading", style: {
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    height: '480px',
                    color: '#94a3b8',
                }, children: "Decrypting device-bound document in memory (RAM)..." })), !loading && error && ((0, jsx_runtime_1.jsxs)("div", { "data-testid": "docbind-viewer-error", style: {
                    padding: '24px',
                    color: '#f87171',
                    backgroundColor: 'rgba(127, 29, 29, 0.25)',
                    border: '1px solid #ef4444',
                    margin: '16px',
                    borderRadius: '6px',
                }, children: [(0, jsx_runtime_1.jsx)("strong", { children: "Decryption / Hardware Authorization Error:" }), " ", error] })), isScreenObscured && ((0, jsx_runtime_1.jsxs)("div", { "data-testid": "docbind-viewer-obscured", style: {
                    position: 'absolute',
                    inset: 0,
                    zIndex: 50,
                    backgroundColor: 'rgba(15, 23, 42, 0.96)',
                    backdropFilter: 'blur(24px)',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: '24px',
                    textAlign: 'center',
                }, children: [(0, jsx_runtime_1.jsx)("div", { style: { fontSize: '20px', fontWeight: 700, color: '#f87171', marginBottom: '8px' }, children: "Protected Document Hidden" }), (0, jsx_runtime_1.jsxs)("div", { style: { fontSize: '14px', color: '#cbd5e1', maxWidth: '420px' }, children: ["Screen capture, recording, or window focus loss detected.", violationReason ? ` (${violationReason})` : ''] })] })), !loading && !error && decryptedDoc && !isScreenObscured && ((0, jsx_runtime_1.jsxs)("div", { "data-testid": "docbind-viewer-content", style: {
                    position: 'relative',
                    width: '100%',
                    height: '100%',
                    minHeight: '480px',
                    padding: '20px',
                    boxSizing: 'border-box',
                }, children: [nativeRenderer && base64InMemory !== null ? nativeRenderer({
                        bytes: decryptedDoc.bytes,
                        base64InMemory,
                        mimeType: decryptedDoc.mimeType,
                        category: category ?? 'other',
                    }) : ((0, jsx_runtime_1.jsxs)("div", { style: {
                            backgroundColor: '#ffffff',
                            color: '#0f172a',
                            borderRadius: '6px',
                            padding: '24px',
                            minHeight: '440px',
                            boxShadow: '0 4px 20px rgba(0,0,0,0.25)',
                        }, children: [(0, jsx_runtime_1.jsxs)("div", { style: {
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    borderBottom: '1px solid #e2e8f0',
                                    paddingBottom: '12px',
                                    marginBottom: '16px',
                                    fontSize: '12px',
                                    color: '#475569',
                                }, children: [(0, jsx_runtime_1.jsxs)("span", { children: [(0, jsx_runtime_1.jsx)("strong", { children: "Document ID:" }), " ", decryptedDoc.documentId] }), (0, jsx_runtime_1.jsxs)("span", { children: [(0, jsx_runtime_1.jsx)("strong", { children: "Bound Device:" }), " ", decryptedDoc.targetDeviceId] }), (0, jsx_runtime_1.jsxs)("span", { children: [(0, jsx_runtime_1.jsx)("strong", { children: "RAM Buffer:" }), " ", decryptedDoc.bytes.byteLength, " bytes (Zero Disk Write)"] })] }), renderMedia()] })), watermark?.text && ((0, jsx_runtime_1.jsx)("div", { "data-testid": "docbind-viewer-watermark", style: {
                            position: 'absolute',
                            inset: 0,
                            pointerEvents: 'none',
                            zIndex: 20,
                            display: 'grid',
                            gridTemplateColumns: 'repeat(3, 1fr)',
                            gridTemplateRows: 'repeat(8, 1fr)',
                            overflow: 'hidden',
                            alignItems: 'center',
                            justifyItems: 'center',
                        }, children: watermarkCells.map((cell) => ((0, jsx_runtime_1.jsx)("span", { style: {
                                color: watermark.color || 'rgba(0,0,0,0.1)',
                                fontSize: `${watermark.fontSize ?? 18}px`,
                                fontWeight: 700,
                                transform: `rotate(${watermark.angle ?? -30}deg)`,
                                whiteSpace: 'nowrap',
                                userSelect: 'none',
                            }, children: watermark.text }, cell))) }))] }))] }));
};
exports.SecureDocumentViewer = SecureDocumentViewer;
// Attach Viewer onto DocumentSealer class as required by specification
DocumentSealer_js_1.DocumentSealer.Viewer = exports.SecureDocumentViewer;
//# sourceMappingURL=Viewer.js.map