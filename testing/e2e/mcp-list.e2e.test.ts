import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { join } from 'node:path';
import { mkdtemp, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { generateMCPConfig } from './helpers/mcp-config.js';
import { runVasoCLI } from './helpers/cli-runner.js';

describe('E2E: vaso mcp list', () => {
  let tempDir: string;
  let configPath: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-e2e-mcp-'));
    configPath = join(tempDir, 'claude_desktop_config.json');

    await generateMCPConfig(configPath);

    // Create .vaso dirs to suppress warnings
    await mkdir(join(tempDir, '.vaso/ioc'), { recursive: true });
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('should list all 4 servers in terminal output', async () => {
    const result = await runVasoCLI(
      ['mcp', 'list', '--path', configPath],
      { HOME: tempDir },
    );

    const output = result.stdout;
    expect(output).toContain('filesystem');
    expect(output).toContain('memory');
    expect(output).toContain('everything');
    expect(output).toContain('sequential-thinking');
  });

  it('should show totalServers = 4 in JSON output', async () => {
    const result = await runVasoCLI(
      ['mcp', 'list', '--format', 'json', '--path', configPath],
      { HOME: tempDir },
    );

    const output = result.stdout + result.stderr;
    const jsonStart = output.indexOf('{');
    expect(jsonStart).not.toBe(-1);

    const parsed = JSON.parse(output.slice(jsonStart));
    expect(parsed.totalServers).toBe(4);
  });
});
