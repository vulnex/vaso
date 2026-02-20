import { GenericContainer, type StartedTestContainer } from 'testcontainers';
import { resolve } from 'node:path';
import type { ScanResult, CheckResult, AgentScanResult } from '../../src/core/types.js';

const PROJECT_ROOT = resolve(import.meta.dirname, '../..');

/** Tag used for the base VASO test image */
const BASE_IMAGE_TAG = 'vaso-test-base:latest';

let baseImageBuilt = false;

/**
 * Build the base VASO Docker image (multi-stage build).
 * Only builds once per test process — subsequent calls are no-ops.
 */
export async function buildBaseImage(): Promise<void> {
  if (baseImageBuilt) return;

  await GenericContainer
    .fromDockerfile(PROJECT_ROOT, 'testing/docker/base.Dockerfile')
    .build(BASE_IMAGE_TAG, { deleteOnExit: false });

  baseImageBuilt = true;
}

export interface VasoScanOptions {
  /** Path to the agent Dockerfile relative to project root */
  dockerfile: string;
  /** Docker build args */
  buildArgs?: Record<string, string>;
  /** Extra environment variables for the container */
  env?: Record<string, string>;
  /** Extra CLI args to append to the VASO scan command */
  cliArgs?: string[];
}

/**
 * Build an agent-specific Docker image, run VASO inside it,
 * and return the parsed JSON scan result.
 *
 * The container stays alive (overridden CMD), VASO is invoked via exec(),
 * and the JSON output is captured from the exec result.
 */
export async function runVasoScan(options: VasoScanOptions): Promise<ScanResult> {
  // Ensure base image exists
  await buildBaseImage();

  // Build the agent-specific image
  const builtImage = await GenericContainer
    .fromDockerfile(PROJECT_ROOT, options.dockerfile)
    .withBuildArgs({
      BASE_IMAGE: BASE_IMAGE_TAG,
      ...options.buildArgs,
    })
    .build(`vaso-test-${Date.now()}`, { deleteOnExit: false });

  // Start container with a keep-alive command so it doesn't exit immediately
  let started: StartedTestContainer | undefined;
  try {
    let builder = new GenericContainer(builtImage.imageName.string)
      .withCommand(['tail', '-f', '/dev/null'])
      .withStartupTimeout(60_000);

    if (options.env) {
      builder = builder.withEnvironment(options.env);
    }

    started = await builder.start();

    // Execute VASO scan inside the running container
    const cmd = ['node', 'dist/cli.js', 'scan', '--format', 'json'];
    if (options.cliArgs) {
      cmd.push(...options.cliArgs);
    }

    const execResult = await started.exec(cmd);
    const output = execResult.output;

    // Parse the JSON output from stdout
    const jsonStart = output.indexOf('{');
    if (jsonStart === -1) {
      throw new Error(
        `No JSON output found in container exec output (exit code ${execResult.exitCode}):\n${output}`
      );
    }

    const jsonStr = extractJson(output, jsonStart);
    return JSON.parse(jsonStr) as ScanResult;
  } finally {
    if (started) {
      await started.stop();
    }
  }
}

/**
 * Extract a JSON object string starting from the given position,
 * handling nested braces and string escapes.
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

  // Fallback: return from start to end
  return text.slice(start);
}

/**
 * Find a specific check result by ID across all agents in the scan result.
 */
export function findCheck(result: ScanResult, checkId: string): CheckResult | undefined {
  for (const agent of result.agents) {
    const check = agent.results.find(r => r.id === checkId);
    if (check) return check;
  }
  return undefined;
}

/**
 * Find all check results with a given ID across all agents.
 */
export function findAllChecks(result: ScanResult, checkId: string): CheckResult[] {
  return result.agents.flatMap(a => a.results.filter(r => r.id === checkId));
}

/**
 * Get the scan result for a specific agent.
 */
export function getAgentResult(result: ScanResult, agent: string): AgentScanResult | undefined {
  return result.agents.find(a => a.agent === agent);
}

/**
 * Assert that a check failed (was detected as a security issue).
 */
export function expectCheckFailed(result: ScanResult, checkId: string): CheckResult {
  const check = findCheck(result, checkId);
  if (!check) {
    throw new Error(`Check ${checkId} not found in scan results. Available: ${
      result.agents.flatMap(a => a.results.map(r => r.id)).join(', ')
    }`);
  }
  if (check.passed) {
    throw new Error(`Expected check ${checkId} to fail but it passed: ${check.message}`);
  }
  return check;
}

/**
 * Assert that a check passed.
 */
export function expectCheckPassed(result: ScanResult, checkId: string): CheckResult {
  const check = findCheck(result, checkId);
  if (!check) {
    throw new Error(`Check ${checkId} not found in scan results. Available: ${
      result.agents.flatMap(a => a.results.map(r => r.id)).join(', ')
    }`);
  }
  if (!check.passed) {
    throw new Error(`Expected check ${checkId} to pass but it failed: ${check.message}`);
  }
  return check;
}
