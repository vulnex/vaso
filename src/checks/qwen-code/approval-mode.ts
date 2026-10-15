import type { ParsedConfig } from '../../core/types.js';

/**
 * The configured approval mode and the key it came from. Current Qwen
 * settings keep it at `tools.approvalMode` (settings.md, and the v1→v2
 * migration maps the old top-level `approvalMode` there); the top-level key
 * is read as a fallback for unmigrated configs.
 */
export function approvalMode(config: ParsedConfig): { mode: string; key: string } | undefined {
  const tools = config.data.tools as Record<string, unknown> | undefined;
  if (tools && typeof tools === 'object' && typeof tools.approvalMode === 'string') {
    return { mode: tools.approvalMode, key: 'tools.approvalMode' };
  }
  const legacy = config.data.approvalMode;
  return typeof legacy === 'string' ? { mode: legacy, key: 'approvalMode' } : undefined;
}
