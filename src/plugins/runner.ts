import type { ScanResult } from '../core/types.js';
import type { PluginAgentType, PluginConfig, PreStartScanResult } from './types.js';
import { DEFAULT_PLUGIN_CONFIG } from './types.js';

let _initialized = false;

async function ensureInitialized(): Promise<void> {
  if (_initialized) return;

  const { adapterRegistry } = await import('../adapters/registry.js');
  const { openclawAdapter } = await import('../adapters/openclaw.js');
  const { nanoclawAdapter } = await import('../adapters/nanoclaw.js');
  const { picoclawAdapter } = await import('../adapters/picoclaw.js');
  const { registerAllChecks } = await import('../checks/index.js');
  const { initIOCDatabase } = await import('../ioc/database.js');

  adapterRegistry.register(openclawAdapter);
  adapterRegistry.register(nanoclawAdapter);
  adapterRegistry.register(picoclawAdapter);
  registerAllChecks();
  await initIOCDatabase();

  _initialized = true;
}

export function evaluateScanResult(
  scanResult: ScanResult,
  config: PluginConfig,
  elapsedMs: number,
): PreStartScanResult {
  const allResults = scanResult.agents.flatMap(a => a.results);

  const filtered = allResults.filter(r => !config.excludeChecks.includes(r.id));

  const criticalFindings = filtered
    .filter(r => r.severity === 'critical' && !r.passed)
    .map(r => ({ id: r.id, name: r.name, message: r.message }));

  const warningFindings = filtered
    .filter(r => r.severity === 'warning' && !r.passed)
    .map(r => ({ id: r.id, name: r.name, message: r.message }));

  let blocked = false;
  let blockReason: string | undefined;

  if (config.blockOnCritical && criticalFindings.length > 0) {
    blocked = true;
    blockReason = `${criticalFindings.length} critical finding(s) detected`;
  } else if (config.blockOnWarning && warningFindings.length > 0) {
    blocked = true;
    blockReason = `${warningFindings.length} warning finding(s) detected`;
  }

  return {
    passed: !blocked,
    blocked,
    blockReason,
    score: scanResult.totalScore,
    grade: scanResult.totalGrade,
    summary: scanResult.summary,
    criticalFindings,
    warningFindings,
    elapsedMs,
  };
}

export async function runPreStartScan(
  agent: PluginAgentType,
  config?: Partial<PluginConfig>,
): Promise<PreStartScanResult> {
  const mergedConfig: PluginConfig = { ...DEFAULT_PLUGIN_CONFIG, ...config };
  const start = Date.now();

  try {
    await ensureInitialized();

    const { ScanEngine } = await import('../core/engine.js');
    const { adapterRegistry } = await import('../adapters/registry.js');
    const { checkRegistry } = await import('../core/check-registry.js');

    const engine = new ScanEngine(adapterRegistry, checkRegistry);

    const scanPromise = engine.scan({ agentFilter: agent });
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Scan timed out')), mergedConfig.timeout),
    );

    const scanResult = await Promise.race([scanPromise, timeoutPromise]);
    const elapsed = Date.now() - start;

    return evaluateScanResult(scanResult, mergedConfig, elapsed);
  } catch (err) {
    const elapsed = Date.now() - start;
    console.error(`[vaso] Pre-start scan error: ${(err as Error).message}`);
    return {
      passed: true,
      blocked: false,
      blockReason: undefined,
      score: 0,
      grade: 'F',
      summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
      criticalFindings: [],
      warningFindings: [],
      elapsedMs: elapsed,
    };
  }
}

export function _resetForTesting(): void {
  _initialized = false;
}
