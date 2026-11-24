import type { DataFlowResult } from './ast-analyzer.js';

/**
 * A command running a file of the script's own folder that the same code
 * writes (downloaded, decoded, copied in) runs code chosen at runtime:
 * dynamic, not the fixed helper its `<skill>/…` text suggests. Shared by the
 * JavaScript and Python analyzers.
 */
export function markWrittenHelpers(results: DataFlowResult[]): DataFlowResult[] {
  const written = new Set(results
    .filter((r) => r.type === 'own-write' && r.resolvedPath?.startsWith('<skill>/'))
    .map((r) => r.resolvedPath!.slice('<skill>/'.length)));
  if (written.size === 0) return results;
  return results.map((r) => r.type === 'eval-exec' && r.ownHelpers?.some((h) => written.has(h) || written.has('*'))
    ? { ...r, dynamic: true } : r);
}
