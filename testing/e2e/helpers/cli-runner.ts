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
  // stdout carries only the report (banner/warnings go to stderr)
  try {
    return JSON.parse(result.stdout) as ScanResult;
  } catch {
    throw new Error(
      `stdout is not a JSON document (exit code ${result.exitCode}):\n${result.stdout}\n--- stderr ---\n${result.stderr}`
    );
  }
}

/**
 * Run VASO CLI expecting a JSON array result (e.g., `vaso detect --format json`).
 */
export async function runVasoJSONArray(
  args: string[],
  env: Record<string, string> = {},
): Promise<unknown[]> {
  const result = await runVasoCLI([...args, '--format', 'json'], env);
  try {
    return JSON.parse(result.stdout) as unknown[];
  } catch {
    throw new Error(
      `stdout is not a JSON array (exit code ${result.exitCode}):\n${result.stdout}\n--- stderr ---\n${result.stderr}`
    );
  }
}
