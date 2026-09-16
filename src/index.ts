/**
 * VASO library entry point — the programmatic API for embedding the scanner.
 *
 * The CLI (`src/cli.ts`) is one consumer of these seams; downstream tools
 * (custom scanners, CI integrations, backends that embed the engine) are the
 * other. Everything exported here is the supported surface: additions are
 * fine, renames/removals are breaking.
 *
 * Minimal embedding:
 *
 *   import { adapterRegistry, checkRegistry, registerAllAdapters,
 *            registerAllChecks, initIOCDatabase, initAdvisoryDatabase,
 *            ScanEngine } from 'vaso';
 *   registerAllAdapters();
 *   registerAllChecks();
 *   initIOCDatabase();
 *   initAdvisoryDatabase();
 *   const result = await new ScanEngine(adapterRegistry, checkRegistry).scan({});
 */

// Core contract: agent/check/scan types (AgentType, CheckModule, ScanContext,
// CheckResult, ScanResult, ParsedConfig, ZoneGraph, AGENT_TYPES, CODING_AGENTS, …)
export * from './core/types.js';

// Filesystem provider contract + implementations
export type {
  FSProvider,
  DirentInfo,
  ExecResult,
  ExecOptions,
  PermissionFacts,
  PermissionQuery,
} from './core/fs-provider.js';
export { LocalFSProvider } from './core/local-fs-provider.js';
export { SnapshotFSProvider } from './core/snapshot-fs-provider.js';
export {
  queryPermissions,
  posixPermissionFacts,
  readableByOthers,
  writableByOthers,
  accessibleByOthers,
} from './core/permissions.js';

// Engine + scoring
export { ScanEngine } from './core/engine.js';
export {
  computeScore,
  aggregateScore,
  meanScore,
  scoreToGrade,
  summarizeResults,
} from './core/scoring.js';

// Config loading
export { loadConfig } from './core/config-loader.js';

// Adapter seam
export type { AgentAdapter, DetectOptions } from './adapters/adapter.js';
export { adapterRegistry, AdapterRegistry } from './adapters/registry.js';
export type {
  AdapterDetectionError,
  AdapterConfigLoadError,
  AdapterDetectionResult,
} from './adapters/registry.js';
export { allAdapters, registerAllAdapters } from './adapters/index.js';

// Check seam
export { checkRegistry, CheckRegistry } from './core/check-registry.js';
export { registerAllChecks } from './checks/index.js';
export { defineCheck } from './core/check-builder.js';

// Bundled threat data (must be initialized before IOC/advisory checks run)
export { initIOCDatabase } from './ioc/database.js';
export { initAdvisoryDatabase } from './advisory/database.js';

// Reporting seam
export type { Reporter } from './reporting/reporter.js';
export { getReporter, registerReporter } from './reporting/index.js';

export { VERSION } from './version.js';
