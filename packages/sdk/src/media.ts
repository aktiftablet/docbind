export type MediaCategory = 'pdf' | 'image' | 'video' | 'audio' | 'text' | 'other';

const TEXT_LIKE = new Set(['application/json', 'application/xml', 'text/xml', 'text/csv']);

/** Maps a MIME type to the renderer category used by `<DocumentSealer.Viewer />`. */
export function getMediaCategory(mimeType: string | null | undefined): MediaCategory {
  const mime = (mimeType ?? '').toLowerCase().split(';')[0].trim();
  if (mime === 'application/pdf') return 'pdf';
  if (mime.startsWith('image/')) return 'image';
  if (mime.startsWith('video/')) return 'video';
  if (mime.startsWith('audio/')) return 'audio';
  if (mime.startsWith('text/') || TEXT_LIKE.has(mime)) return 'text';
  return 'other';
}
