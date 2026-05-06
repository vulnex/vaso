import type { ScanOptions, ScanResult, ScanContext, AgentScanResult, AgentInstallation } from './types.js';
import type { CheckRegistry } from './check-registry.js';
import type { AdapterDetectionError, AdapterRegistry } from '../adapters/registry.js';
import type { MCPConfig, MCPServerSource } from '../mcp/types.js';
import type { FSProvider } from './fs-provider.js';
import { LocalFSProvider } from './local-fs-provider.js';
import { computeScore, scoreToGrade, summarizeResults } from './scoring.js';
import { getSkillFiles } from './utils.js';

export class ScanEngine {
  private fs: FSProvider;

  constructor(
    private adapters: AdapterRegistry,
    private checks: CheckRegistry,
    fs?: FSProvider,
  ) {
    this.fs = fs ?? new LocalFSProvider();
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

    if (filtered.length === 0 && detectionErrors.length === 0) {
      return this.emptyResult(options.agentFilter);
    }

    // 2. Scan each agent
    const agentResults = await Promise.allSettled(
      filtered.map(installation => this.scanAgent(installation))
    );

    const agents: AgentScanResult[] = [];
    for (const result of agentResults) {
      if (result.status === 'fulfilled') {
        agents.push(result.value);
      }
    }
    agents.push(...detectionErrors.map(e => this.adapterErrorResult(e)));

    // 3. Compute overall results
    const allResults = agents.flatMap(a => a.results);
    const totalScore = agents.length > 0
      ? Math.round(agents.reduce((sum, a) => sum + a.score, 0) / agents.length)
      : 100;
    const summary = summarizeResults(allResults);

    return {
      timestamp: new Date().toISOString(),
      agents,
      totalScore,
      totalGrade: scoreToGrade(totalScore),
      summary,
    };
  }

  private async scanAgent(installation: AgentInstallation): Promise<AgentScanResult> {
    const skillFiles = installation.skillsDir
      ? await getSkillFiles(installation.skillsDir, this.fs)
      : undefined;

    const context: ScanContext = {
      installation,
      configs: installation.configFiles,
      platform: this.fs.platform,
      fs: this.fs,
      skillFiles,
    };

    // Get applicable checks for the scanned filesystem, not the scanner host.
    const applicable = this.checks.getApplicable(installation.agent, this.fs.platform);

    // Run all checks concurrently
    const settled = await Promise.allSettled(
      applicable.map(check => check.run(context))
    );

    const results = settled.map((r, index) => {
      if (r.status === 'fulfilled') return r.value;
      const check = applicable[index];
      return {
        id: check.id,
        name: check.name,
        category: check.category,
        severity: 'warning' as const,
        passed: false,
        message: `Check errored and was not completed: ${r.reason instanceof Error ? r.reason.message : String(r.reason)}`,
      };
    });

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

  private adapterErrorResult(error: AdapterDetectionError): AgentScanResult {
    const result = {
      id: 'ADAPTER-DETECT',
      name: `${error.displayName} Detection Error`,
      category: 'config' as const,
      severity: 'warning' as const,
      passed: false,
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
      mcpServerSources: serverSources,
    };

    // Get only MCP-category checks
    const mcpChecks = this.checks.getByCategory('mcp');

    const settled = await Promise.allSettled(
      mcpChecks.map(check => check.run(context))
    );

    const results = settled.map((r, index) => {
      if (r.status === 'fulfilled') return r.value;
      const check = mcpChecks[index];
      return {
        id: check.id,
        name: check.name,
        category: check.category,
        severity: 'warning' as const,
        passed: false,
        message: `Check errored and was not completed: ${r.reason instanceof Error ? r.reason.message : String(r.reason)}`,
      };
    });

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
      agents: [agentResult],
      totalScore: score,
      totalGrade: scoreToGrade(score),
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
      skillChecks.map(check => check.run(context))
    );

    const results = settled.map((r, index) => {
      if (r.status === 'fulfilled') return r.value;
      const check = skillChecks[index];
      return {
        id: check.id,
        name: check.name,
        category: check.category,
        severity: 'warning' as const,
        passed: false,
        message: `Check errored and was not completed: ${r.reason instanceof Error ? r.reason.message : String(r.reason)}`,
      };
    });

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
      agents: [agentResult],
      totalScore: score,
      totalGrade: scoreToGrade(score),
      summary,
    };
  }

  private emptyResult(agentFilter?: string): ScanResult {
    return {
      timestamp: new Date().toISOString(),
      agents: [],
      totalScore: 100,
      totalGrade: 'A',
      summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
    };
  }
}
