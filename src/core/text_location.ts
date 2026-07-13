/** Shared helpers so every scanner reports consistent file:line locations. */

export function lineNumberAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  return line;
}

export function lineTextAt(text: string, index: number): string {
  const start = text.lastIndexOf("\n", Math.max(index - 1, 0)) + 1;
  const end = text.indexOf("\n", index);
  return text.slice(start, end === -1 ? text.length : end).trim();
}
