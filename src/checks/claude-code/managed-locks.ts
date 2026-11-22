import type { ScanContext } from '../../core/types.js';
import { parseJsonLenient } from '../../core/jsonc.js';
import { claudeManagedSettingsPaths } from '../../adapters/claude-code.js';

/**
 * Managed-settings locks that switch off what user, project and local
 * settings define (code.claude.com/docs/en/settings-reference):
 * `allowManagedPermissionRulesOnly` (only managed allow/ask/deny rules apply),
 * `allowManagedHooksOnly` (user, project, local and plugin hooks are
 * blocked) and a managed `disableAllHooks` (no hook runs). Each names the
 * managed file that sets it. Honoured only from managed settings.
 */
export interface ManagedLocks {
  permissionRulesOnly?: string;
  hooksOnly?: string;
  allHooksOff?: string;
  /** The managed settings files (a config in one of them is not locked out). */
  managedFiles: Set<string>;
}

export async function claudeManagedLocks(ctx: ScanContext): Promise<ManagedLocks> {
  const paths = await claudeManagedSettingsPaths(ctx.fs);
  const locks: ManagedLocks = { managedFiles: new Set(paths) };
  for (const file of paths) {
    let data: unknown = ctx.configs.find(c => c.filePath === file)?.data;
    if (data === undefined) {
      try {
        data = parseJsonLenient(await ctx.fs.readFile(file));
      } catch {
        continue; // absent or unreadable
      }
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) continue;
    const d = data as Record<string, unknown>;
    if (d.allowManagedPermissionRulesOnly === true) locks.permissionRulesOnly ??= file;
    if (d.allowManagedHooksOnly === true) locks.hooksOnly ??= file;
    if (d.disableAllHooks === true) locks.allHooksOff ??= file;
  }
  return locks;
}
