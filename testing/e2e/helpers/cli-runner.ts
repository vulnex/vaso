import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import type { ScanResult } from '../../../src/core/types.js';

const PROJECT_ROOT = resolve(import.meta.dirname, '../../..');
const CLI_PATH = resolve(PROJECT_ROOT, 'dist/cli.js');

export interface CLIResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Spawn `node dist/cli.js <args>` as a child process with a custom HOME.
 * Each invocation is fully isolated — no global state mutation.
 */
export async function runVasoCLI(
  args: string[],
  env: Record<string, string> = {},
): Promise<CLIResult> {
  return new Promise((resolve, reject) => {
    const child = spawn('node', [CLI_PATH, ...args], {
      cwd: PROJECT_ROOT,
      env: {
        ...process.env,
        NO_COLOR: '1',
        // Prevent the IOC update check from running during tests
        VASO_SKIP_IOC_UPDATE: '1',
        ...env,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (data: Buffer) => {
      stdout += data.toString();
    });

    child.stderr.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    child.on('error', reject);

    child.on('close', (code) => {
      resolve({
        stdout,
        stderr,
        exitCode: code ?? 1,
      });
    });
  });
}

/**
 * Run VASO CLI with `--format json` and return the parsed ScanResult.
 */
export async function runVasoJSON(
  args: string[],
  env: Record<string, string> = {},
): Promise<ScanResult> {
  const result = await runVasoCLI([...args, '--format', 'json'], env);
  const output = result.stdout + result.stderr;

  const jsonStart = output.indexOf('{');
  if (jsonStart === -1) {
    throw new Error(
      `No JSON object found in CLI output (exit code ${result.exitCode}):\n${output}`
    );
  }

  const jsonStr = extractJson(output, jsonStart);
  return JSON.parse(jsonStr) as ScanResult;
}

/**
 * Run VASO CLI expecting a JSON array result (e.g., `vaso detect --format json`).
 */
export async function runVasoJSONArray(
  args: string[],
  env: Record<string, string> = {},
): Promise<unknown[]> {
  const result = await runVasoCLI([...args, '--format', 'json'], env);
  const output = result.stdout + result.stderr;

  const arrayStart = output.indexOf('[');
  if (arrayStart === -1) {
    throw new Error(
      `No JSON array found in CLI output (exit code ${result.exitCode}):\n${output}`
    );
  }

  const jsonStr = extractJsonArray(output, arrayStart);
  return JSON.parse(jsonStr) as unknown[];
}

/**
 * Extract a JSON object string from text, handling nested braces and string escapes.
 * Reused from testing/integration/helpers.ts.
 */
function extractJson(text: string, start: number): string {
  let depth = 0;
  let inString = false;
  let escape = false;

  for (let i = start; i < text.length; i++) {
    const ch = text[i];

    if (escape) {
      escape = false;
      continue;
    }

    if (ch === '\\' && inString) {
      escape = true;
      continue;
    }

    if (ch === '"' && !escape) {
      inString = !inString;
      continue;
    }

    if (inString) continue;

    if (ch === '{') depth++;
    if (ch === '}') {
      depth--;
      if (depth === 0) {
        return text.slice(start, i + 1);
      }
    }
  }

  return text.slice(start);
}

/**
 * Extract a JSON array string from text, handling nested brackets and string escapes.
 */
function extractJsonArray(text: string, start: number): string {
  let depth = 0;
  let inString = false;
  let escape = false;

  for (let i = start; i < text.length; i++) {
    const ch = text[i];

    if (escape) {
      escape = false;
      continue;
    }

    if (ch === '\\' && inString) {
      escape = true;
      continue;
    }

    if (ch === '"' && !escape) {
      inString = !inString;
      continue;
    }

    if (inString) continue;

    if (ch === '[') depth++;
    if (ch === ']') {
      depth--;
      if (depth === 0) {
        return text.slice(start, i + 1);
      }
    }
  }

  return text.slice(start);
}
