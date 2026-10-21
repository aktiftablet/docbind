export type MediaCategory = 'pdf' | 'image' | 'video' | 'audio' | 'text' | 'other';
/** Maps a MIME type to the renderer category used by `<DocumentSealer.Viewer />`. */
export declare function getMediaCategory(mimeType: string | null | undefined): MediaCategory;
//# sourceMappingURL=media.d.ts.map