/**
 * Lightweight, dependency-free MIME detection from file signatures (magic bytes).
 * Used when the client does not provide a reliable MIME type (e.g. base64 JSON uploads
 * or generic `application/octet-stream` multipart parts).
 */
export declare const DEFAULT_MIME_TYPE = "application/octet-stream";
/** Detects MIME type from leading bytes. Returns `null` if unknown. */
export declare function sniffMimeType(buf: Buffer): string | null;
/** Looks up a MIME type from a filename extension. */
export declare function mimeFromFilename(filename: string | undefined | null): string | null;
/**
 * Resolves the most reliable MIME type: magic bytes > declared type > filename extension > octet-stream.
 * ZIP-based containers (docx/xlsx/pptx) share the same signature, so the declared/extension type wins for them.
 */
export declare function resolveMimeType(buf: Buffer, declared?: string | null, filename?: string | null): string;
/** Max upload size in bytes, configurable via `MAX_UPLOAD_MB` (default 500 MB). */
export declare function getMaxUploadBytes(): number;
//# sourceMappingURL=mime.d.ts.map