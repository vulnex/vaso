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

/**
 * Why `disableAllHooks` stops what `file` defines, or undefined. A managed
 * `disableAllHooks` stops everything; one in a user, project or local file
 * stops what those scopes define, not what managed settings define. Claude
 * Code's settings schema: "Disable all hooks and statusLine execution".
 */
export function allHooksOffReason(ctx: ScanContext, locks: ManagedLocks, file: string): string | undefined {
  if (locks.allHooksOff) return `${locks.allHooksOff} sets disableAllHooks`;
  if (locks.managedFiles.has(file)) return undefined;
  const scoped = ctx.configs.find(c => !locks.managedFiles.has(c.filePath) && (c.data as Record<string, unknown> | undefined)?.disableAllHooks === true);
  return scoped ? `${scoped.filePath} sets disableAllHooks` : undefined;
}
