import type { CheckRegistry } from '../core/check-registry.js';
import { loadRules, type LoadResult } from './loader.js';
import { compileRule, RuleTimeBudget } from './compiler.js';
import type { CheckModule } from '../core/types.js';

export type { DeclarativeRule, ValidationError } from './schema.js';
export type { LoadResult, RuleFileResult } from './loader.js';
export { loadRules, TRUSTED_PROJECTS_FILE } from './loader.js';
export { compileRule, RuleTimeBudget } from './compiler.js';
export { validateRuleFile } from './schema.js';

export interface RegisterResult {
  registered: CheckModule[];
  skipped: Array<{ id: string; reason: string }>;
  loadResult: LoadResult;
}

/**
 * Load declarative YAML rules, compile them into CheckModules, and register them.
 * Skips rules whose ID conflicts with already-registered checks (with a warning).
 */
export async function loadAndRegisterRules(
  registry: CheckRegistry,
  options?: {
    extraPaths?: string[];
    skipGlobal?: boolean;
    skipProject?: boolean;
    /** Trust the working directory's project rules (`--project-rules`). */
    projectRules?: boolean;
  },
): Promise<RegisterResult> {
  const loadResult = await loadRules(options);
  const registered: CheckModule[] = [];
  const skipped: Array<{ id: string; reason: string }> = [];
  // one matching-time pool for all of them (per host scanned)
  const budget = new RuleTimeBudget();

  for (const rule of loadResult.allRules) {
    try {
      const check = compileRule(rule, budget);

      // Check for ID collision with existing checks
      const existing = registry.getAll().find(c => c.id === check.id);
      if (existing) {
        skipped.push({ id: rule.id, reason: `ID "${rule.id}" conflicts with existing check` });
        continue;
      }

      registry.register(check);
      registered.push(check);
    } catch (err) {
      skipped.push({
        id: rule.id,
        reason: `Compile error: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  return { registered, skipped, loadResult };
}
