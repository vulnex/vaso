import { describe, it, expect } from 'vitest';
import { shellCommandWrapper } from './shell-wrapper.js';

describe('shellCommandWrapper', () => {
  it('finds shell -c in all its spellings', () => {
    expect(shellCommandWrapper('bash', ['-c', 'npx x'])).toBe('bash');
    expect(shellCommandWrapper('/bin/bash', ['-lc', 'npx x'])).toBe('bash');
    expect(shellCommandWrapper('sh', ['-ec', 'x'])).toBe('sh');
    expect(shellCommandWrapper('/usr/bin/env', ['bash', '-c', 'x'])).toBe('bash');
    expect(shellCommandWrapper('env', ['-S', 'FOO=1', 'zsh', '-ic', 'x'])).toBe('zsh');
    expect(shellCommandWrapper('cmd.exe', ['/c', 'npx', 'x'])).toBe('cmd');
    expect(shellCommandWrapper('pwsh', ['-NoProfile', '-Command', 'x'])).toBe('pwsh');
  });

  it('leaves scripts and non-shells alone', () => {
    expect(shellCommandWrapper('bash', ['server.sh'])).toBeUndefined();
    expect(shellCommandWrapper('bash', ['server.sh', '-c', 'conf'])).toBeUndefined();
    expect(shellCommandWrapper('node', ['-c', 'x'])).toBeUndefined();
    expect(shellCommandWrapper('env', ['NODE_ENV=prod', 'node', 'x.js'])).toBeUndefined();
  });
});
