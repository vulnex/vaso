import { describe, it, expect } from 'vitest';
import { classifyPrefixPattern } from './cdx-010-broad-prefix-rules.js';

describe('CDX-010 classifyPrefixPattern (dt24)', () => {
  it('flags wrappers, versioned interpreters and every shell', () => {
    for (const p of [['env'], ['xargs'], ['nohup'], ['timeout'], ['fish', '-c'], ['pwsh'], ['pwsh', '-Command'],
      ['python3.12'], ['/usr/bin/python3'], ['curl'], ['bash', '-lc'], ['sudo'], ['npx']]) {
      expect(classifyPrefixPattern(p), p.join(' ')).toBeDefined();
    }
  });

  it('passes scoped prefixes', () => {
    for (const p of [['ls', '-la'], ['npm', 'test'], ['python3', 'manage.py', 'test'], ['bash', 'scripts/build.sh'], ['cargo', 'build']]) {
      expect(classifyPrefixPattern(p), p.join(' ')).toBeUndefined();
    }
  });
});
