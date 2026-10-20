import React, { useEffect, useState, useMemo, type CSSProperties } from 'react';
import { DocumentSealer } from '../DocumentSealer.js';
import { ScreenCaptureGuard } from '../security/ScreenCaptureGuard.js';
import type { DecryptedDocumentInMemory, SecureViewerProps } from '../types.js';

/**
 * Extracts readable text streams or metadata from an in-memory PDF byte array
 * for zero-disk-write canvas/DOM preview alongside the in-memory PDF stream.
 */
function extractInMemoryPdfSummary(bytes: Uint8Array): {
  isValidPdfHeader: boolean;
  headerVersion: string;
  extractedTextBlocks: string[];
} {
  const decoder = new TextDecoder('latin1');
  const rawString = decoder.decode(bytes.subarray(0, Math.min(bytes.length, 65536)));
  const isValidPdfHeader = rawString.startsWith('%PDF-');
  const headerVersion = isValidPdfHeader ? rawString.slice(0, 8).trim() : 'Unknown';

  // Extract literal strings inside PDF text objects BT ... (text) Tj ... ET
  const extractedTextBlocks: string[] = [];
  const literalRegex = /\(([^()\\]*(?:\\.[^()\\]*)*)\)\s*Tj/g;
  let match: RegExpExecArray | null;
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
export const SecureDocumentViewer: React.FC<SecureViewerProps> = ({
  payloadUrl,
  preventScreenshot = true,
  watermark,
  apiKey,
  onDocumentLoaded,
  onError,
  onSecurityViolation,
  renderNativePdf,
}) => {
  const [decryptedDoc, setDecryptedDoc] = useState<DecryptedDocumentInMemory | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isScreenObscured, setIsScreenObscured] = useState<boolean>(false);
  const [violationReason, setViolationReason] = useState<string | null>(null);

  // 1. Activate Anti-Screenshot & Screen Recording Guard
  useEffect(() => {
    if (!preventScreenshot) {
      setIsScreenObscured(false);
      return;
    }

    const customGuard = DocumentSealer.getConfig().nativeModules?.screenGuard;
    const cleanup = ScreenCaptureGuard.activate(
      {
        onCaptureStateChange: (obscured, reason) => {
          setIsScreenObscured(obscured);
          if (obscured && reason) {
            setViolationReason(reason);
            onSecurityViolation?.(reason);
          }
        },
      },
      customGuard
    );

    return cleanup;
  }, [preventScreenshot, onSecurityViolation]);

  // 2. Fetch & Decrypt Document Strictly in RAM (Zero Disk Writes)
  useEffect(() => {
    let active = true;
    let currentDoc: DecryptedDocumentInMemory | null = null;

    setLoading(true);
    setError(null);

    DocumentSealer.fetchAndDecryptInMemory(payloadUrl, apiKey)
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
      .catch((err: unknown) => {
        if (!active) return;
        const normalizedErr =
          err instanceof Error ? err : new Error(String(err || 'Decryption failed'));
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

  const pdfMeta = useMemo(() => {
    if (!decryptedDoc) return null;
    return extractInMemoryPdfSummary(decryptedDoc.bytes);
  }, [decryptedDoc]);

  const inMemoryDataUri = useMemo(() => {
    if (!decryptedDoc) return null;
    let binary = '';
    const bytes = decryptedDoc.bytes;
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 =
      typeof Buffer !== 'undefined'
        ? Buffer.from(bytes).toString('base64')
        : btoa(binary);
    return {
      base64,
      dataUri: `data:${decryptedDoc.mimeType};base64,${base64}#toolbar=0&navpanes=0&scrollbar=0`,
    };
  }, [decryptedDoc]);

  const containerStyle: CSSProperties = {
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

  const watermarkCells = useMemo(() => {
    if (!watermark?.text) return [];
    return Array.from({ length: 24 }, (_, idx) => idx);
  }, [watermark?.text]);

  return (
    <div
      data-testid="docbind-secure-viewer"
      data-prevent-screenshot={String(preventScreenshot)}
      data-obscured={String(isScreenObscured)}
      style={containerStyle}
      onContextMenu={(e) => e.preventDefault()}
      onCopy={(e) => e.preventDefault()}
      onDragStart={(e) => e.preventDefault()}
    >
      {/* Print suppression style */}
      {preventScreenshot && (
        <style>{`
          @media print {
            [data-testid="docbind-secure-viewer"] {
              display: none !important;
            }
          }
        `}</style>
      )}

      {/* Loading State */}
      {loading && (
        <div
          data-testid="docbind-viewer-loading"
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            height: '480px',
            color: '#94a3b8',
          }}
        >
          Decrypting device-bound document in memory (RAM)...
        </div>
      )}

      {/* Error State */}
      {!loading && error && (
        <div
          data-testid="docbind-viewer-error"
          style={{
            padding: '24px',
            color: '#f87171',
            backgroundColor: 'rgba(127, 29, 29, 0.25)',
            border: '1px solid #ef4444',
            margin: '16px',
            borderRadius: '6px',
          }}
        >
          <strong>Decryption / Hardware Authorization Error:</strong> {error}
        </div>
      )}

      {/* Screen Capture / Screenshot Guard Obscured Overlay */}
      {isScreenObscured && (
        <div
          data-testid="docbind-viewer-obscured"
          style={{
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
          }}
        >
          <div style={{ fontSize: '20px', fontWeight: 700, color: '#f87171', marginBottom: '8px' }}>
            Protected Document Hidden
          </div>
          <div style={{ fontSize: '14px', color: '#cbd5e1', maxWidth: '420px' }}>
            Screen capture, recording, or window focus loss detected.
            {violationReason ? ` (${violationReason})` : ''}
          </div>
        </div>
      )}

      {/* Decrypted In-Memory Document Content */}
      {!loading && !error && decryptedDoc && !isScreenObscured && (
        <div
          data-testid="docbind-viewer-content"
          style={{
            position: 'relative',
            width: '100%',
            height: '100%',
            minHeight: '480px',
            padding: '20px',
            boxSizing: 'border-box',
          }}
        >
          {renderNativePdf && inMemoryDataUri ? (
            (renderNativePdf({
              bytes: decryptedDoc.bytes,
              base64InMemory: inMemoryDataUri.base64,
            }) as React.ReactNode)
          ) : (
            <div
              style={{
                backgroundColor: '#ffffff',
                color: '#0f172a',
                borderRadius: '6px',
                padding: '24px',
                minHeight: '440px',
                boxShadow: '0 4px 20px rgba(0,0,0,0.25)',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  borderBottom: '1px solid #e2e8f0',
                  paddingBottom: '12px',
                  marginBottom: '16px',
                  fontSize: '12px',
                  color: '#475569',
                }}
              >
                <span>
                  <strong>Document ID:</strong> {decryptedDoc.documentId}
                </span>
                <span>
                  <strong>Bound Device:</strong> {decryptedDoc.targetDeviceId}
                </span>
                <span>
                  <strong>RAM Buffer:</strong> {decryptedDoc.bytes.byteLength} bytes (Zero Disk Write)
                </span>
              </div>

              {pdfMeta?.extractedTextBlocks && pdfMeta.extractedTextBlocks.length > 0 ? (
                <div data-testid="docbind-pdf-text-layer" style={{ lineHeight: 1.6 }}>
                  {pdfMeta.extractedTextBlocks.map((line, i) => (
                    <p key={i} style={{ margin: '8px 0', fontSize: '15px' }}>
                      {line}
                    </p>
                  ))}
                </div>
              ) : (
                inMemoryDataUri && (
                  <object
                    data={inMemoryDataUri.dataUri}
                    type={decryptedDoc.mimeType}
                    width="100%"
                    height="400px"
                  >
                    <p>In-Memory Decrypted PDF ({decryptedDoc.bytes.byteLength} bytes)</p>
                  </object>
                )
              )}
            </div>
          )}

          {/* Dynamic Diagonal Watermark Overlay */}
          {watermark?.text && (
            <div
              data-testid="docbind-viewer-watermark"
              style={{
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
              }}
            >
              {watermarkCells.map((cell) => (
                <span
                  key={cell}
                  style={{
                    color: watermark.color || 'rgba(0,0,0,0.1)',
                    fontSize: `${watermark.fontSize ?? 18}px`,
                    fontWeight: 700,
                    transform: `rotate(${watermark.angle ?? -30}deg)`,
                    whiteSpace: 'nowrap',
                    userSelect: 'none',
                  }}
                >
                  {watermark.text}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Attach Viewer onto DocumentSealer class as required by specification
DocumentSealer.Viewer = SecureDocumentViewer;
