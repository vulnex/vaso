import { VERSION } from '../version.js';
import { dirname } from 'node:path';
import type { ScanOptions, ScanResult, ScanContext, AgentScanResult, AgentInstallation, CheckResult, CheckModule, McpServerItem } from './types.js';
import type { CheckRegistry } from './check-registry.js';
import type { AdapterConfigLoadError, AdapterDetectionError, AdapterRegistry } from '../adapters/registry.js';
import type { MCPConfig, MCPConfigLoadError, MCPServerSource } from '../mcp/types.js';
import type { FSProvider } from './fs-provider.js';
import { LocalFSProvider } from './local-fs-provider.js';
import { computeScore, scoreToGrade, summarizeResults, aggregateScore, meanScore } from './scoring.js';
import { dedupeInheritedFindings } from './inherited-findings.js';
import { dedupePermissionFindings } from './duplicate-findings.js';
import { collectSkillInventory } from '../inventory/skills.js';
import { MAX_SNIPPET, truncateSnippet } from './patterns.js';
import { discoverMcpAssignment, type McpAssignment } from '../inventory/mcp.js';
import { linkInventoryFindings } from '../inventory/findings.js';
import { buildHostInventory, isEmptyHostInventory } from '../inventory/host.js';
import { mapSourceEvidence } from '../mcp/source-locations.js';
import { describeFetchFailure } from '../mcp/package-fetcher.js';
import { extractToolDefinitions } from '../mcp/tool-baseline.js';
import { credentialPathsFor } from '../adapters/adapter.js';
import { captureConfigLoadErrors } from './config-loader.js';
import { parseErrorMessage } from './parse-error.js';
import { fixBoundaryOf, markRefusedFix } from '../remediation/fix-refusal.js';

/** How long one check may run before it is reported as errored (default 5 min). */
export const DEFAULT_CHECK_TIMEOUT_MS = 300_000;

/** Longest accepted `$VASO_CHECK_TIMEOUT`: 24 h (Node timers overflow past ~24.8 days and fire at once). */
export const MAX_CHECK_TIMEOUT_SEC = 86_400;

/**
 * `$VASO_CHECK_TIMEOUT` (seconds, 1–86400), else the default. An unusable
 * value is named on stderr rather than silently replaced — a huge one used to
 * overflow the timer and error every check.
 */
let timeoutWarned = false;
const warnOnce = (m: string) => {
  if (timeoutWarned) return;
  timeoutWarned = true;
  process.stderr.write(`${m}\n`);
};

export function checkTimeoutFromEnv(env: NodeJS.ProcessEnv = process.env, warn: (m: string) => void = warnOnce): number {
  const raw = env.VASO_CHECK_TIMEOUT;
  if (raw === undefined || raw.trim() === '') return DEFAULT_CHECK_TIMEOUT_MS;
  const s = Number(raw);
  if (!Number.isFinite(s) || s <= 0) {
    warn(`Warning: VASO_CHECK_TIMEOUT=${JSON.stringify(raw).slice(0, 40)} is not a positive number of seconds — using ${DEFAULT_CHECK_TIMEOUT_MS / 1000}`);
    return DEFAULT_CHECK_TIMEOUT_MS;
  }
  if (s > MAX_CHECK_TIMEOUT_SEC) {
    warn(`Warning: VASO_CHECK_TIMEOUT=${raw} exceeds ${MAX_CHECK_TIMEOUT_SEC} (24 hours) — using ${MAX_CHECK_TIMEOUT_SEC}`);
    return MAX_CHECK_TIMEOUT_SEC * 1000;
  }
  return s * 1000;
}

/**
 * Run one check, turning every way it can fail to produce a result into a
 * rejection: a throw, a value that isn't a CheckResult (a plugin returning
 * undefined used to crash the agent's scoring and drop the whole agent from
 * the report), or a promise that never settles (the process used to exit 0
 * with no report once nothing else kept it alive).
 */
function hostInventory(installations: AgentInstallation[], mcp: McpAssignment, agentFilter: boolean): Pick<ScanResult, 'hostInventory'> {
  const host = buildHostInventory(installations, { mcpServers: mcp.host, incomplete: mcp.incomplete }, { agentFilter });
  return isEmptyHostInventory(host) ? {} : { hostInventory: host };
}

/** Longest evidence snippet a result keeps. */
export { MAX_SNIPPET };
/** Most evidence items a result keeps; the rest are counted in one closing item. */
export const MAX_EVIDENCE = 200;

/**
 * Evidence bounded in size: snippets cut to MAX_SNIPPET (a check quoting "the
 * line" of a minified file would otherwise copy the whole file into every
 * item — a 100 MB report), and at most MAX_EVIDENCE items (one IOC per line
 * of 150k-line files made a 0.5 GB JSON report and crashed SARIF). The
 * result's message keeps the full count.
 */
export function capSnippets(result: CheckResult): CheckResult {
  const evidence = result.evidence;
  if (!evidence) return result;
  const long = evidence.some(e => typeof e.snippet === 'string' && e.snippet.length > MAX_SNIPPET);
  if (!long && evidence.length <= MAX_EVIDENCE) return result;
  // Which items are kept must not depend on walk order (a local walk and a
  // snapshot list files differently): sort before cutting — live exposures
  // before mitigated ones (a cut must not drop what the verdict rests on),
  // then by file, then line
  const ordered = evidence.length > MAX_EVIDENCE
    ? [...evidence].sort((a, b) => (Number(!!a.mitigated) - Number(!!b.mitigated))
      || (a.file < b.file ? -1 : a.file > b.file ? 1 : (a.line ?? 0) - (b.line ?? 0)))
    : evidence;
  const kept = (evidence.length > MAX_EVIDENCE ? ordered.slice(0, MAX_EVIDENCE - 1) : evidence)
    .map(e => (typeof e.snippet === 'string' && e.snippet.length > MAX_SNIPPET
      ? { ...e, snippet: truncateSnippet(e.snippet, MAX_SNIPPET) }
      : e));
  if (evidence.length > MAX_EVIDENCE) {
    const rest = ordered.slice(MAX_EVIDENCE - 1);
    kept.push({
      file: rest[0].file,
      detail: `… and ${rest.length} more evidence item(s) not listed (${new Set(rest.map(e => e.file)).size} file(s))`,
      ...(rest.every(e => e.mitigated) ? { mitigated: true } : {}),
    });
  }
  return { ...result, evidence: kept };
}

export function runCheck(check: CheckModule, ctx: ScanContext, timeoutMs: number): Promise<CheckResult> {
  return runCheckUncapped(check, ctx, timeoutMs).then(capSnippets);
}

/** runCheck without the evidence bounds — for callers that read all evidence first (inventory links). */
function runCheckUncapped(check: CheckModule, ctx: ScanContext, timeoutMs: number): Promise<CheckResult> {
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

/**
 * A finding offered to `vaso fix` whose fix would be refused for every file
 * it changes (outside the home, a symlink, …) is not fixable — a second
 * `vaso fix` would otherwise fail on it forever. Judged on the full evidence,
 * before it is capped for reports.
 */
async function markRefusedFixes(checks: CheckModule[], ctx: ScanContext, results: CheckResult[]): Promise<CheckResult[]> {
  if (!results.some(r => r.fixable)) return results;
  const byId = new Map(checks.map(c => [c.id, c]));
  const boundary = await fixBoundaryOf(ctx.installation.installDir, ctx.fs);
  return Promise.all(results.map(r => (r.fixable && (!r.passed || r.foldedInto)
    ? markRefusedFix(byId.get(r.id), ctx, r, boundary)
    : r)));
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
    message: `Check errored and was not completed: ${parseErrorMessage(reason)}`,
  };
}

/** The CONFIG-LOAD result for a config file that exists but could not be read or parsed. */
function configLoadResult(error: AdapterConfigLoadError): CheckResult {
  return {
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
}

/**
 * `--resolve-packages` servers whose source could not be downloaded, as one
 * errored result: the source checks never saw them, so the scan is
 * incomplete — and why (`npm not found on PATH`) is in the report, not only
 * on stderr. Info severity: the host is not worse for it.
 */
export function packageResolveResult(sources: readonly MCPServerSource[]): CheckResult | undefined {
  const failed = sources.filter((s) => s.resolveFailure && !s.sourceCode);
  if (failed.length === 0) return undefined;
  const reasons = [...new Set(failed.map((s) => describeFetchFailure(s.resolveFailure!)))];
  return {
    id: 'PACKAGE-RESOLVE',
    name: 'Package Source Resolution',
    category: 'mcp',
    severity: 'info',
    passed: false,
    errored: true,
    message: `Source of ${failed.length} packaged server(s) could not be downloaded (${reasons.join('; ')}) — their code was not analyzed; findings may be missing`,
    evidence: failed.map((s) => ({
      file: s.packageName ?? s.serverName,
      detail: `Server "${s.serverName}": ${describeFetchFailure(s.resolveFailure!)}`,
    })),
  };
}

/**
 * One CONFIG-LOAD per file and agent: installations of one agent read shared
 * files (an OpenClaw profile's OC-005 reads the default config, Abacus
 * projects the user trust file), and each used to report the same unreadable
 * file again. The first installation keeps it.
 */
function dedupeConfigLoadFindings(agents: AgentScanResult[]): void {
  const seen = new Set<string>();
  for (const a of agents) {
    const before = a.results.length;
    a.results = a.results.filter(r => {
      if (r.id !== 'CONFIG-LOAD') return true;
      const key = `${a.agent}\u0000${a.installation.user ?? ''}\u0000${r.evidence?.[0]?.file ?? r.message}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    if (a.results.length !== before) {
      a.score = computeScore(a.results);
      a.grade = scoreToGrade(a.score);
    }
  }
}

/**
 * Local servers whose source is there but could not be read (EACCES), as one
 * errored result — the counterpart of PACKAGE-RESOLVE: the source checks
 * passed them without seeing their code, so the scan is incomplete. Also a
 * server read only in part (an unreadable helper module).
 */
export function sourceReadResult(sources: readonly MCPServerSource[]): CheckResult | undefined {
  const failed = sources.filter((s) => s.readFailure);
  if (failed.length === 0) return undefined;
  const partial = failed.filter((s) => s.sourceCode).length;
  return {
    id: 'SOURCE-READ',
    name: 'Server Source Read',
    category: 'mcp',
    severity: 'info',
    passed: false,
    errored: true,
    message: `Source of ${failed.length} local server(s) could not be read${partial > 0 ? ` (${partial} only in part)` : ''} — their code was not analyzed; findings may be missing`,
    evidence: failed.map((s) => ({
      file: s.localPath ?? s.serverName,
      detail: `Server "${s.serverName}": ${s.readFailure}`,
    })),
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

    // MCP servers per installation for the inventory: one discovery per host
    const mcp = await discoverMcpAssignment(filtered, this.fs);

    // 2. Scan each agent
    const agentResults = await Promise.allSettled(
      filtered.map(installation => this.scanAgent(installation, mcp.byInstallation.get(installation)))
    );

    const agents: AgentScanResult[] = [];
    agentResults.forEach((result, index) => {
      // An agent whose scan failed outside its checks is reported, not dropped
      agents.push(result.status === 'fulfilled' ? result.value : this.agentErrorResult(filtered[index], result.reason));
    });
    agents.push(...detectionErrors.map(e => this.adapterErrorResult(e)));
    this.foldConfigLoadErrors(agents, configLoadErrors);
    dedupeConfigLoadFindings(agents);
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
      // Servers no detected agent owns belong to the host, not to one agent
      ...hostInventory(filtered, mcp, Boolean(options.agentFilter)),
    };
  }

  private async scanAgent(installation: AgentInstallation, mcpServers?: McpServerItem[]): Promise<AgentScanResult> {
    // One walk per skills directory: the files the checks read, and the
    // inventory reports carry
    const { files: skillFiles, inventory } = await collectSkillInventory(installation, this.fs);
    installation.inventory = mcpServers ? { ...inventory, mcpServers } : inventory;

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

    // Run all checks concurrently. Files a check reads itself (memory, rules
    // and trust files) that exist but can't be read are captured as they are
    // during detection, and reported as CONFIG-LOAD like unreadable configs.
    const { result: settled, loadErrors } = await captureConfigLoadErrors(() => Promise.allSettled(
      applicable.map(check => runCheckUncapped(check, context, this.checkTimeoutMs))
    ));

    const uncapped = await markRefusedFixes(applicable, context, dedupePermissionFindings(settled.map((r, index) =>
      r.status === 'fulfilled' ? r.value : erroredResult(applicable[index], r.reason))));
    const displayName = adapter?.displayName ?? installation.agent;
    for (const error of loadErrors) {
      if (uncapped.some(r => r.id === 'CONFIG-LOAD' && r.evidence?.[0]?.file === error.filePath)) continue;
      uncapped.push(configLoadResult({ ...error, agent: installation.agent, displayName }));
    }

    // links read every evidence item; reports get the bounded evidence
    linkInventoryFindings(installation.inventory, uncapped);
    const results = uncapped.map(capSnippets);
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
      const result = configLoadResult(error);

      const agent = agents.find(a => a.agent === error.agent);
      if (agent) {
        // Already reported by a check that read the same file
        if (agent.results.some(r => r.id === 'CONFIG-LOAD' && r.evidence?.[0]?.file === error.filePath)) continue;
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
      message: `The scan of this installation failed and its checks were not completed: ${parseErrorMessage(reason)}`,
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
      message: `Adapter detection failed: ${parseErrorMessage(error.message)}`,
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
    /** Discovered MCP config files that could not be read or parsed. */
    loadErrors: readonly MCPConfigLoadError[] = [],
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

    const unresolved = packageResolveResult(serverSources);
    if (unresolved) results.push(unresolved);
    const unread = sourceReadResult(serverSources);
    if (unread) results.push(unread);
    // One CONFIG-LOAD per such file, as for an agent's config: the servers
    // it declares were not scanned
    results.push(...loadErrors.map((e) => configLoadResult({ ...e, agent: 'mcp', displayName: `${e.source} MCP` })));

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
