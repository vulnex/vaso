export interface EntropyResult {
  line: number;
  entropy: number;
  snippet: string;
}

const HIGH_ENTROPY_THRESHOLD = 5.5;
const MIN_BLOCK_LENGTH = 40;

export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

export function findHighEntropyBlocks(
  code: string,
  threshold = HIGH_ENTROPY_THRESHOLD,
  minLength = MIN_BLOCK_LENGTH,
): EntropyResult[] {
  const results: EntropyResult[] = [];
  const lines = code.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Skip comments and short lines
    if (line.length < minLength) continue;
    if (line.startsWith('//') || line.startsWith('*') || line.startsWith('#')) continue;

    // Extract string literals for entropy analysis
    const strings = extractStrings(line);
    for (const str of strings) {
      if (str.length < minLength) continue;
      const entropy = shannonEntropy(str);
      if (entropy > threshold) {
        results.push({
          line: i + 1,
          entropy: Math.round(entropy * 100) / 100,
          snippet: str.slice(0, 80) + (str.length > 80 ? '...' : ''),
        });
      }
    }
  }

  return results;
}

function extractStrings(line: string): string[] {
  const strings: string[] = [];
  // Match double-quoted, single-quoted, and backtick strings separately
  const patterns = [
    /"([^"]{10,})"/g,
    /'([^']{10,})'/g,
    /`([^`]{10,})`/g,
  ];
  for (const regex of patterns) {
    let match;
    while ((match = regex.exec(line)) !== null) {
      strings.push(match[1]);
    }
  }
  return strings;
}
