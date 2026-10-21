/**
 * Lightweight, dependency-free MIME detection from file signatures (magic bytes).
 * Used when the client does not provide a reliable MIME type (e.g. base64 JSON uploads
 * or generic `application/octet-stream` multipart parts).
 */
export const DEFAULT_MIME_TYPE = 'application/octet-stream';

const EXTENSION_MIME: Record<string, string> = {
  pdf: 'application/pdf',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  svg: 'image/svg+xml',
  bmp: 'image/bmp',
  heic: 'image/heic',
  mp4: 'video/mp4',
  m4v: 'video/mp4',
  mov: 'video/quicktime',
  webm: 'video/webm',
  mkv: 'video/x-matroska',
  avi: 'video/x-msvideo',
  mp3: 'audio/mpeg',
  m4a: 'audio/mp4',
  wav: 'audio/wav',
  ogg: 'audio/ogg',
  txt: 'text/plain',
  csv: 'text/csv',
  json: 'application/json',
  md: 'text/markdown',
  doc: 'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  zip: 'application/zip',
};

function startsWith(buf: Buffer, sig: number[], offset = 0): boolean {
  if (buf.length < offset + sig.length) return false;
  return sig.every((b, i) => buf[offset + i] === b);
}

/** Detects MIME type from leading bytes. Returns `null` if unknown. */
export function sniffMimeType(buf: Buffer): string | null {
  if (startsWith(buf, [0x25, 0x50, 0x44, 0x46, 0x2d])) return 'application/pdf';
  if (startsWith(buf, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'image/png';
  if (startsWith(buf, [0xff, 0xd8, 0xff])) return 'image/jpeg';
  if (startsWith(buf, [0x47, 0x49, 0x46, 0x38])) return 'image/gif';
  if (startsWith(buf, [0x42, 0x4d])) return 'image/bmp';
  if (startsWith(buf, [0x52, 0x49, 0x46, 0x46])) {
    const kind = buf.subarray(8, 12).toString('latin1');
    if (kind === 'WEBP') return 'image/webp';
    if (kind === 'WAVE') return 'audio/wav';
    if (kind === 'AVI ') return 'video/x-msvideo';
  }
  if (startsWith(buf, [0x1a, 0x45, 0xdf, 0xa3])) {
    return buf.subarray(0, 64).toString('latin1').includes('webm') ? 'video/webm' : 'video/x-matroska';
  }
  if (buf.length >= 12 && buf.subarray(4, 8).toString('latin1') === 'ftyp') {
    const brand = buf.subarray(8, 12).toString('latin1');
    if (brand === 'qt  ') return 'video/quicktime';
    if (brand.startsWith('M4A')) return 'audio/mp4';
    if (brand.startsWith('heic') || brand.startsWith('heix') || brand.startsWith('mif1')) return 'image/heic';
    return 'video/mp4';
  }
  if (startsWith(buf, [0x49, 0x44, 0x33]) || startsWith(buf, [0xff, 0xfb])) return 'audio/mpeg';
  if (startsWith(buf, [0x4f, 0x67, 0x67, 0x53])) return 'audio/ogg';
  return null;
}

/** Looks up a MIME type from a filename extension. */
export function mimeFromFilename(filename: string | undefined | null): string | null {
  if (!filename) return null;
  const ext = filename.toLowerCase().split('.').pop();
  return (ext && EXTENSION_MIME[ext]) || null;
}

/**
 * Resolves the most reliable MIME type: magic bytes > declared type > filename extension > octet-stream.
 * ZIP-based containers (docx/xlsx/pptx) share the same signature, so the declared/extension type wins for them.
 */
export function resolveMimeType(
  buf: Buffer,
  declared?: string | null,
  filename?: string | null
): string {
  const declaredClean =
    declared && declared.trim() && declared !== DEFAULT_MIME_TYPE ? declared.trim().toLowerCase() : null;
  return sniffMimeType(buf) ?? declaredClean ?? mimeFromFilename(filename) ?? DEFAULT_MIME_TYPE;
}

/** Max upload size in bytes, configurable via `MAX_UPLOAD_MB` (default 500 MB). */
export function getMaxUploadBytes(): number {
  const mb = Number(process.env.MAX_UPLOAD_MB);
  return (Number.isFinite(mb) && mb > 0 ? mb : 500) * 1024 * 1024;
}
