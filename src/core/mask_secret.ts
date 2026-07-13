/**
 * Masks a secret value so it is safe to embed in any report or log.
 * Keeps a few characters on each end (enough to recognize which secret it
 * is) and replaces everything else with asterisks. Never returns the raw
 * input untouched, even for short values.
 */
export function maskSecret(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0) return "";
  if (trimmed.length <= 8) {
    return "*".repeat(trimmed.length);
  }
  const start = trimmed.slice(0, 4);
  const end = trimmed.slice(-4);
  const middleLength = Math.max(trimmed.length - 8, 4);
  return `${start}${"*".repeat(middleLength)}${end}`;
}

/**
 * Replaces every occurrence of `secret` inside `text` with its masked form.
 * Used to sanitize surrounding code snippets / lines before they are stored
 * in a Finding.
 */
export function maskInText(text: string, secret: string): string {
  if (!secret) return text;
  return text.split(secret).join(maskSecret(secret));
}
