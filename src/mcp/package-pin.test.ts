import { describe, it, expect } from 'vitest';
import { runnerPackage, classifyNpm, classifyPypi } from './package-pin.js';

const pin = (cmd: string, ...args: string[]) => runnerPackage(cmd, args)?.pin;
const pkg = (cmd: string, ...args: string[]) => runnerPackage(cmd, args);

describe('runnerPackage', () => {
  it('reads the package each runner installs', () => {
    expect(pkg('npx', '-y', '@modelcontextprotocol/server-filesystem@2025.8.21', '/data')).toMatchObject({ runner: 'npx', name: '@modelcontextprotocol/server-filesystem', pin: 'exact' });
    expect(pkg('/usr/local/bin/npx', '--package=pkg@1.2.3', 'bin')).toMatchObject({ name: 'pkg', pin: 'exact' });
    expect(pkg('npx', '-p', 'pkg@^1', 'bin')).toMatchObject({ pin: 'range' });
    expect(pkg('pnpm', 'dlx', 'pkg@1.2.3')).toMatchObject({ runner: 'pnpm dlx', name: 'pkg', pin: 'exact' });
    expect(pkg('yarn', 'dlx', '-p', 'pkg@2.0.0', 'bin')).toMatchObject({ runner: 'yarn dlx', pin: 'exact' });
    expect(pkg('npm', 'exec', '--yes', '--package=pkg@1.0.0', '--', 'bin')).toMatchObject({ runner: 'npm exec', pin: 'exact' });
    expect(pkg('uvx', '--from', 'mcp-server-time==2025.9.25', 'mcp-server-time')).toMatchObject({ name: 'mcp-server-time', pin: 'exact' });
    expect(pkg('uvx', '--link-mode', 'copy', '--from', 'godot-ai==3.2.5', 'godot-ai', 'attach')).toMatchObject({ name: 'godot-ai', pin: 'exact' });
    expect(pkg('uvx', 'mcp-server-fetch@2025.4.7')).toMatchObject({ pin: 'exact' });
    expect(pkg('uv', 'tool', 'run', 'mcp-server-git==1.0.0')).toMatchObject({ runner: 'uv tool run', pin: 'exact' });
    expect(pkg('pipx', 'run', '--spec', 'pkg==1.0', 'pkg')).toMatchObject({ runner: 'pipx run', pin: 'exact' });
    expect(pkg('pipx', 'run', 'pkg')).toMatchObject({ pin: 'none' });
  });

  it('is not fooled by subcommands, local scripts or other commands', () => {
    expect(pkg('uv', 'run', 'server.py')).toBeUndefined();
    expect(pkg('pnpm', 'install')).toBeUndefined();
    expect(pkg('npm', 'start')).toBeUndefined();
    expect(pkg('node', 'server.js')).toBeUndefined();
    expect(pkg('npx', './local/bin.js')).toMatchObject({ pin: 'local' });
    expect(pkg('npx', '-y')).toBeUndefined();
  });

  it('classifies npm specs', () => {
    expect(classifyNpm('pkg').pin).toBe('none');
    expect(classifyNpm('pkg@latest').pin).toBe('tag');
    expect(classifyNpm('pkg@next').pin).toBe('tag');
    expect(classifyNpm('pkg@*').pin).toBe('range');
    expect(classifyNpm('pkg@~1.2.0').pin).toBe('range');
    expect(classifyNpm('pkg@1.x').pin).toBe('range');
    expect(classifyNpm('pkg@1').pin).toBe('range');
    expect(classifyNpm('@s/p@1.2.3-beta.1').pin).toBe('exact');
    expect(classifyNpm('github:owner/repo#0a1b2c3d').pin).toBe('exact');
    expect(classifyNpm('github:owner/repo').pin).toBe('none');
  });

  it('classifies PyPI specs', () => {
    expect(classifyPypi('pkg').pin).toBe('none');
    expect(classifyPypi('pkg==1.2.3').pin).toBe('exact');
    expect(classifyPypi('pkg[extra]==1.2').pin).toBe('exact');
    expect(classifyPypi('pkg>=1.0').pin).toBe('range');
    expect(classifyPypi('pkg~=1.4').pin).toBe('range');
    expect(classifyPypi('pkg==1.*').pin).toBe('range');
    expect(classifyPypi('pkg@latest').pin).toBe('tag');
    expect(classifyPypi('pkg @ git+https://github.com/o/r@0123456789abcdef').pin).toBe('exact');
  });
});
