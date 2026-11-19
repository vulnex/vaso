import { describe, it, expect } from 'vitest';
import { maskCredentialsInLine, maskCredentialsInText } from './serialize.js';

// dt24: bash $'…' / $"…" quoted secrets in command strings (hooks, MCP
// command lines) are masked like '…' and "…" ones; the probe disguises the
// same strings (probe/secret_scrub_ansi_test.go).
const A = 'Qw7rTy2uIo9pAs4dFg6hJk8l';
const B = 'Zx8cVb3nMq1wEr5tYu7iOp2a';

const COMMANDS = [
  `export ANTHROPIC_API_KEY=$'${A}'; run --api-key $'${B}'`,
  `export API_KEY=$"${A}"; run --api-key=$"${B}"`,
  `TOKEN=$'${A}' run --token $'${B}'`,
  `OPENAI_API_KEY="$'${A}'" run -k $'${B}'`,
  `curl -H $'Authorization: Bearer ${A}' x; run --password $'${B}'`,
];

/** The part reports never show (they keep a long key's first 8 / last 4). */
const hidden = (s: string): string => s.slice(8, -4);

describe('ANSI-C and locale quoted secrets in command strings', () => {
  it.each(COMMANDS)('masks %s as text', (cmd) => {
    const out = maskCredentialsInText(cmd);
    for (const s of [A, B]) expect(out).not.toContain(hidden(s));
  });

  it.each(COMMANDS)('masks %s inside a JSON string', (cmd) => {
    const out = maskCredentialsInLine(`"command": ${JSON.stringify(cmd)}`);
    for (const s of [A, B]) expect(out).not.toContain(hidden(s));
  });
});
