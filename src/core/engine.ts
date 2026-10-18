import { VERSION } from '../version.js';
import { dirname } from 'node:path';
import type { ScanOptions, ScanResult, ScanContext, AgentScanResult, AgentInstallation, CheckResult, CheckModule } from './types.js';
import type { CheckRegistry } from './check-registry.js';
import type { AdapterConfigLoadError, AdapterDetectionError, AdapterRegistry } from '../adapters/registry.js';
import type { MCPConfig, MCPServerSource } from '../mcp/types.js';
import type { FSProvider } from './fs-provider.js';
import { LocalFSProvider } from './local-fs-provider.js';
import { computeScore, scoreToGrade, summarizeResults, aggregateScore, meanScore } from './scoring.js';
import { dedupeInheritedFindings } from './inherited-findings.js';
import { dedupePermissionFindings } from './duplicate-findings.js';
import { getAllSkillsDirs, getSkillFiles } from './utils.js';
import { mapSourceEvidence } from '../mcp/source-locations.js';
import { extractToolDefinitions } from '../mcp/tool-baseline.js';
import { credentialPathsFor } from '../adapters/adapter.js';

/** How long one check may run before it is reported as errored (default 5 min). */
export const DEFAULT_CHECK_TIMEOUT_MS = 300_000;

/** `$VASO_CHECK_TIMEOUT` (seconds) when set to a positive number, else the default. */
export function checkTimeoutFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const s = Number(env.VASO_CHECK_TIMEOUT);
  return Number.isFinite(s) && s > 0 ? s * 1000 : DEFAULT_CHECK_TIMEOUT_MS;
}

/**
 * Run one check, turning every way it can fail to produce a result into a
 * rejection: a throw, a value that isn't a CheckResult (a plugin returning
 * undefined used to crash the agent's scoring and drop the whole agent from
 * the report), or a promise that never settles (the process used to exit 0
 * with no report once nothing else kept it alive).
 */
export function runCheck(check: CheckModule, ctx: ScanContext, timeoutMs: number): Promise<CheckResult> {
  return new Promise<CheckResult>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`did not finish within ${Math.round(timeoutMs / 1000)}s`)), timeoutMs);
    Promise.resolve()
      .then(() => check.run(ctx))
      .then((r: unknown) => {
        const v = r as Partial<CheckResult> | null | undefined;
        if (!v || typeof v !== 'object' || typeof v.passed !== 'boolean' || typeof v.id !== 'string') {
          throw new Error(`returned ${v === undefined ? 'undefined' : v === null ? 'null' : typeof v !== 'object' ? typeof v : 'an object that is not a check result'} instead of a check result`);
        }
        return v as CheckResult;
      })
      .then(resolve, reject)
      .finally(() => clearTimeout(timer));
  });
}

/** The errored result standing in for a check that produced none. */
function erroredResult(check: Pick<CheckModule, 'id' | 'name' | 'category'>, reason: unknown): CheckResult {
  return {
    id: check.id,
    name: check.name,
    category: check.category,
    severity: 'warning',
    passed: false,
    errored: true,
    message: `Check errored and was not completed: ${reason instanceof Error ? reason.message : String(reason)}`,
  };
}

export class ScanEngine {
  private fs: FSProvider;
  private checkTimeoutMs: number;

  constructor(
    private adapters: AdapterRegistry,
    private checks: CheckRegistry,
    fs?: FSProvider,
    options?: { checkTimeoutMs?: number },
  ) {
    this.fs = fs ?? new LocalFSProvider();
    this.checkTimeoutMs = options?.checkTimeoutMs ?? checkTimeoutFromEnv();
  }

  async scan(options: ScanOptions): Promise<ScanResult> {
    // 1. Detect installed agents
    const detection = await this.adapters.detectAllDetailed({
      allUsers: options.allUsers,
      fs: this.fs,
    });
    const installations = detection.installations;

    // Filter by agent if specified
    const filtered = options.agentFilter
      ? installations.filter(i => i.agent === options.agentFilter)
      : installations;
    const detectionErrors = options.agentFilter
      ? detection.errors.filter(e => e.agent === options.agentFilter)
      : detection.errors;
    const configLoadErrors = options.agentFilter
      ? detection.configLoadErrors.filter(e => e.agent === options.agentFilter)
      : detection.configLoadErrors;

    if (filtered.length === 0 && detectionErrors.length === 0 && configLoadErrors.length === 0) {
      return this.emptyResult(options.agentFilter);
    }

    // 2. Scan each agent
    const agentResults = await Promise.allSettled(
      filtered.map(installation => this.scanAgent(installation))
    );

    const agents: AgentScanResult[] = [];
    agentResults.forEach((result, index) => {
      // An agent whose scan failed outside its checks is reported, not dropped
      agents.push(result.status === 'fulfilled' ? result.value : this.agentErrorResult(filtered[index], result.reason));
    });
    agents.push(...detectionErrors.map(e => this.adapterErrorResult(e)));
    this.foldConfigLoadErrors(agents, configLoadErrors);
    dedupeInheritedFindings(agents);

    // 3. Compute overall results
    const allResults = agents.flatMap(a => a.results);
    const scores = agents.map(a => a.score);
    // Headline is worst-case (gated by the weakest agent), not a mean — see
    // aggregateScore. The mean is kept as a secondary fleet-health metric.
    const totalScore = aggregateScore(scores);
    const summary = summarizeResults(allResults);

    return {
      timestamp: new Date().toISOString(),
      vasoVersion: VERSION,
      agents,
      totalScore,
      totalGrade: scoreToGrade(totalScore),
      fleetAverage: meanScore(scores),
      summary,
    };
  }

  private async scanAgent(installation: AgentInstallation): Promise<AgentScanResult> {
    const skillsDirs = getAllSkillsDirs(installation);
    const skillFiles = skillsDirs.length > 0
      ? (await Promise.all(skillsDirs.map(d => getSkillFiles(d, this.fs)))).flat()
      : undefined;

    const adapter = this.adapters.getAdapter(installation.agent);
    const credentialPaths = credentialPathsFor(adapter, installation, this.fs);

    const context: ScanContext = {
      installation,
      configs: installation.configFiles,
      platform: this.fs.platform,
      fs: this.fs,
      skillFiles,
      credentialPaths,
    };

    // Get applicable checks for the scanned filesystem, not the scanner host.
    const applicable = this.checks.getApplicable(installation.agent, this.fs.platform);

    // Run all checks concurrently
    const settled = await Promise.allSettled(
      applicable.map(check => runCheck(check, context, this.checkTimeoutMs))
    );

    const results = dedupePermissionFindings(settled.map((r, index) =>
      r.status === 'fulfilled' ? r.value : erroredResult(applicable[index], r.reason)));

    const score = computeScore(results);

    return {
      agent: installation.agent,
      version: installation.version,
      installation,
      results,
      score,
      grade: scoreToGrade(score),
    };
  }

  /** Surface config files that exist but could not be read/parsed during
   *  detection. Adapters swallow those failures (a broken file must not abort
   *  detection), which used to make a corrupted config indistinguishable from
   *  a clean or absent one. Each failure becomes an `errored` result — the
   *  same partial-scan channel as thrown checks — attached to the agent it
   *  belongs to, or to a synthetic entry when the broken config prevented the
   *  agent from being detected at all. */
  private foldConfigLoadErrors(agents: AgentScanResult[], loadErrors: AdapterConfigLoadError[]): void {
    for (const error of loadErrors) {
      const result: CheckResult = {
        id: 'CONFIG-LOAD',
        name: `${error.displayName} Config Load Error`,
        category: 'config',
        severity: 'warning',
        passed: false,
        errored: true,
        message: error.directory
          ? `Config directory could not be read: ${error.filePath} — ${error.message}. Its config files were not checked; findings for this agent may be incomplete.`
          : `Config file could not be ${error.stage === 'read' ? 'read' : 'parsed'}: ${error.filePath} — ${error.message}. Findings for this agent may be incomplete.`,
        evidence: [{ file: error.filePath, detail: error.message }],
      };

      const agent = agents.find(a => a.agent === error.agent);
      if (agent) {
        agent.results.push(result);
        agent.score = computeScore(agent.results);
        agent.grade = scoreToGrade(agent.score);
      } else {
        const score = computeScore([result]);
        agents.push({
          agent: error.agent,
          // The unreadable config's directory is the best location we have
          installation: { agent: error.agent, installDir: error.directory ? error.filePath : dirname(error.filePath), configFiles: [] },
          results: [result],
          score,
          grade: scoreToGrade(score),
        });
      }
    }
  }

  /** An installation whose scan failed outside any one check (an internal error). */
  private agentErrorResult(installation: AgentInstallation, reason: unknown): AgentScanResult {
    const result: CheckResult = {
      id: 'AGENT-SCAN',
      name: 'Agent Scan Error',
      category: 'config',
      severity: 'warning',
      passed: false,
      errored: true,
      message: `The scan of this installation failed and its checks were not completed: ${reason instanceof Error ? reason.message : String(reason)}`,
    };
    const score = computeScore([result]);
    return { agent: installation.agent, version: installation.version, installation, results: [result], score, grade: scoreToGrade(score) };
  }

  private adapterErrorResult(error: AdapterDetectionError): AgentScanResult {
    const result = {
      id: 'ADAPTER-DETECT',
      name: `${error.displayName} Detection Error`,
      category: 'config' as const,
      severity: 'warning' as const,
      passed: false,
      errored: true,
      message: `Adapter detection failed: ${error.message}`,
    };
    const score = computeScore([result]);

    return {
      agent: error.agent,
      installation: {
        agent: error.agent,
        installDir: '',
        configFiles: [],
      },
      results: [result],
      score,
      grade: scoreToGrade(score),
    };
  }

  async scanMCP(
    mcpConfigs: MCPConfig[],
    serverSources: MCPServerSource[],
    options: ScanOptions,
  ): Promise<ScanResult> {
    // Extract tool definitions once so the tool-layer checks (MCP-020/024/025)
    // share a single parse of each server's source instead of re-extracting.
    const sourcesWithTools: MCPServerSource[] = serverSources.map((source) => ({
      ...source,
      tools:
        source.tools ??
        (source.sourceCode ? extractToolDefinitions(source.sourceCode) : undefined),
    }));

    const context: ScanContext = {
      installation: {
        agent: 'mcp',
        installDir: process.cwd(),
        configFiles: [],
      },
      configs: [],
      platform: this.fs.platform,
      fs: this.fs,
      mcpConfigs,
      mcpServerSources: sourcesWithTools,
    };

    // Get only MCP-category checks
    const mcpChecks = this.checks.getByCategory('mcp');

    const settled = await Promise.allSettled(
      mcpChecks.map(check => runCheck(check, context, this.checkTimeoutMs))
    );

    const results = settled.map((r, index) =>
      r.status === 'fulfilled' ? r.value : erroredResult(mcpChecks[index], r.reason));

    // Evidence lines in a multi-file server's joined source → file + line
    mapSourceEvidence(results, sourcesWithTools);

    const score = computeScore(results);

    const agentResult: AgentScanResult = {
      agent: 'mcp',
      installation: context.installation,
      results,
      score,
      grade: scoreToGrade(score),
    };

    const summary = summarizeResults(results);

    return {
      timestamp: new Date().toISOString(),
      vasoVersion: VERSION,
      agents: [agentResult],
      totalScore: score,
      totalGrade: scoreToGrade(score),
      fleetAverage: score,
      summary,
    };
  }

  async scanSkill(
    skillPath: string,
    skillFiles: string[],
    options: ScanOptions,
  ): Promise<ScanResult> {
    const context: ScanContext = {
      installation: {
        agent: 'skill-audit',
        installDir: skillPath,
        skillsDir: skillPath,
        configFiles: [],
      },
      configs: [],
      platform: this.fs.platform,
      fs: this.fs,
      skillFiles,
    };

    // Run skill + IOC checks only
    const skillChecks = [
      ...this.checks.getByCategory('skills'),
      ...this.checks.getByCategory('ioc'),
    ];

    const settled = await Promise.allSettled(
      skillChecks.map(check => runCheck(check, context, this.checkTimeoutMs))
    );

    const results = settled.map((r, index) =>
      r.status === 'fulfilled' ? r.value : erroredResult(skillChecks[index], r.reason));

    const score = computeScore(results);

    const agentResult: AgentScanResult = {
      agent: 'skill-audit',
      installation: context.installation,
      results,
      score,
      grade: scoreToGrade(score),
    };

    const summary = summarizeResults(results);

    return {
      timestamp: new Date().toISOString(),
      vasoVersion: VERSION,
      agents: [agentResult],
      totalScore: score,
      totalGrade: scoreToGrade(score),
      fleetAverage: score,
      summary,
    };
  }

  private emptyResult(agentFilter?: string): ScanResult {
    return {
      timestamp: new Date().toISOString(),
      vasoVersion: VERSION,
      agents: [],
      totalScore: 100,
      totalGrade: 'A',
      fleetAverage: 100,
      summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
    };
  }
}
