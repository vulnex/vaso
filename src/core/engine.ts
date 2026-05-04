import type { ScanOptions, ScanResult, ScanContext, AgentScanResult, AgentInstallation } from './types.js';
import type { CheckRegistry } from './check-registry.js';
import type { AdapterRegistry } from '../adapters/registry.js';
import type { MCPConfig, MCPServerSource } from '../mcp/types.js';
import type { FSProvider } from './fs-provider.js';
import { LocalFSProvider } from './local-fs-provider.js';
import { computeScore, scoreToGrade, summarizeResults } from './scoring.js';

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
    const installations = await this.adapters.detectAll({
      allUsers: options.allUsers,
      fs: this.fs,
    });

    // Filter by agent if specified
    const filtered = options.agentFilter
      ? installations.filter(i => i.agent === options.agentFilter)
      : installations;

    if (filtered.length === 0) {
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
    const context: ScanContext = {
      installation,
      configs: installation.configFiles,
      platform: this.fs.platform,
      fs: this.fs,
    };

    // Get applicable checks
    const applicable = this.checks.getApplicable(installation.agent, process.platform);

    // Run all checks concurrently
    const settled = await Promise.allSettled(
      applicable.map(check => check.run(context))
    );

    const results = settled
      .filter((r): r is PromiseFulfilledResult<Awaited<ReturnType<typeof applicable[0]['run']>>> =>
        r.status === 'fulfilled'
      )
      .map(r => r.value);

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

    const results = settled
      .filter((r): r is PromiseFulfilledResult<Awaited<ReturnType<typeof mcpChecks[0]['run']>>> =>
        r.status === 'fulfilled'
      )
      .map(r => r.value);

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

    const results = settled
      .filter((r): r is PromiseFulfilledResult<Awaited<ReturnType<typeof skillChecks[0]['run']>>> =>
        r.status === 'fulfilled'
      )
      .map(r => r.value);

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
