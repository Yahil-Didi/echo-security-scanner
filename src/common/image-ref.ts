export interface ImageRef {
  name: string;
  tag: string;
}

/**
 * Splits "name:tag" into its parts (no tag means "latest"). A ":" before the last "/" belongs to a
 * registry port, like "localhost:5000/app".
 */
export const parseImageRef = (ref: string): ImageRef => {
  const trimmed = ref.trim();
  const lastSlash = trimmed.lastIndexOf('/');
  const lastColon = trimmed.lastIndexOf(':');
  if (lastColon > lastSlash) {
    return { name: trimmed.slice(0, lastColon), tag: trimmed.slice(lastColon + 1) || 'latest' };
  }
  return { name: trimmed, tag: 'latest' };
};

/** Joins an image ref back into "name:tag". */
export const formatImageRef = ({ name, tag }: ImageRef): string => `${name}:${tag}`;

/** Splits a comma-separated list like "nginx:1.19, alpine:3.12" into image refs. */
export const parseImageRefs = (csv: string): ImageRef[] =>
  csv
    .split(',')
    .filter((ref) => ref.trim())
    .map(parseImageRef);
