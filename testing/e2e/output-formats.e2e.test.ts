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

    const output = result.stdout + result.stderr;
    const jsonStart = output.indexOf('{');
    expect(jsonStart).not.toBe(-1);

    const parsed = JSON.parse(output.slice(jsonStart));
    expect(parsed).toHaveProperty('agents');
    expect(parsed).toHaveProperty('totalScore');
    expect(parsed).toHaveProperty('totalGrade');
    expect(Array.isArray(parsed.agents)).toBe(true);
  });

  it('--format sarif should produce valid SARIF output', async () => {
    const result = await runVasoCLI(
      ['scan', '--format', 'sarif'],
      { HOME: env.tempHome },
    );

    const output = result.stdout + result.stderr;
    const jsonStart = output.indexOf('{');
    expect(jsonStart).not.toBe(-1);

    const parsed = JSON.parse(output.slice(jsonStart));
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
