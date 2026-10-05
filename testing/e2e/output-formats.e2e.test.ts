import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createE2EEnvironment, type E2EEnvironment } from './helpers/setup.js';
import { runVasoCLI } from './helpers/cli-runner.js';

describe('E2E: output formats', () => {
  let env: E2EEnvironment;

  beforeAll(async () => {
    env = await createE2EEnvironment({
      agents: ['openclaw'],
      scenario: 'insecure',
    });
  });

  afterAll(async () => {
    await env.cleanup();
  });

  it('--format json should produce valid JSON with agents and totalScore', async () => {
    const result = await runVasoCLI(
      ['scan', '--format', 'json'],
      { HOME: env.tempHome },
    );

    // stdout is the report alone (banner goes to stderr), so it pipes to jq
    const parsed = JSON.parse(result.stdout);
    expect(parsed).toHaveProperty('agents');
    expect(parsed).toHaveProperty('totalScore');
    expect(parsed).toHaveProperty('totalGrade');
    expect(Array.isArray(parsed.agents)).toBe(true);
  });

  it('--format json lists config files by path only — no raw contents or parsed data', async () => {
    const result = await runVasoCLI(['scan', '--format', 'json'], { HOME: env.tempHome });
    const parsed = JSON.parse(result.stdout);
    const configFiles = parsed.agents.flatMap((a: { installation: { configFiles: unknown[] } }) => a.installation.configFiles);
    expect(configFiles.length).toBeGreaterThan(0);
    for (const c of configFiles) expect(Object.keys(c as object).sort()).toEqual(['filePath', 'format']);
  });

  it('rejects an unknown --format with exit 2 before scanning', async () => {
    const result = await runVasoCLI(['scan', '--format', 'xml'], { HOME: env.tempHome });
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain('Invalid --format "xml"');
    expect(result.stdout).toBe('');
  });

  it('--format sarif should produce valid SARIF output', async () => {
    const result = await runVasoCLI(
      ['scan', '--format', 'sarif'],
      { HOME: env.tempHome },
    );

    // stdout is the report alone (banner goes to stderr), so it pipes to jq
    const parsed = JSON.parse(result.stdout);
    expect(parsed).toHaveProperty('$schema');
    expect(parsed).toHaveProperty('runs');
    expect(parsed.$schema).toContain('sarif');
  });

  it('--format markdown should contain headers and VASO', async () => {
    const result = await runVasoCLI(
      ['scan', '--format', 'markdown'],
      { HOME: env.tempHome },
    );

    const output = result.stdout;
    expect(output).toContain('#');
    expect(output.toLowerCase()).toContain('vaso');
  });

  it('--format html should contain html tags', async () => {
    const result = await runVasoCLI(
      ['scan', '--format', 'html'],
      { HOME: env.tempHome },
    );

    const output = result.stdout;
    expect(output).toContain('<html');
    expect(output).toContain('</html>');
  });

  it('default (terminal) should contain check IDs', async () => {
    const result = await runVasoCLI(
      ['scan'],
      { HOME: env.tempHome },
    );

    const output = result.stdout;
    expect(output).toMatch(/CFG-\d{3}/);
  });
});
