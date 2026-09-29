import { normalize } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, expandHome, isBroadPath } from '../../analyzers/broad-paths.js';
import { envString, expandHomeRef, isConfigured, lyrieEnvConfigs } from './env.js';

/**
 * packages/core/src/skills/builtin-executors.ts: the code-execution and
 * file-management skill executors confine themselves to
 * LYRIE_FS_ROOT (default ~/.lyrie/sandbox). Pointing it at / or $HOME turns
 * the sandbox into the whole filesystem / home directory — Lyrie's
 * equivalent of a workspace restriction.
 */
export const ly019 = defineCheck({
  id: 'LY-019',
  name: 'Skill Sandbox Root Over-Broad',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect LYRIE_FS_ROOT set to the filesystem root, the home directory, an ancestor of it, or a shared/system directory (/tmp, /etc, ...). Lyrie\'s built-in code-execution and file-management skills confine reads/writes to this root (default ~/.lyrie/sandbox); a broad root lets them touch SSH keys, shell profiles and other credentials.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const home = ctx.fs.homedir();
    const broad = buildBroadPaths(home);
    const evidence: Evidence[] = [];

    for (const config of lyrieEnvConfigs(ctx.configs)) {
      const raw = envString(config, 'LYRIE_FS_ROOT');
      if (!raw || !isConfigured(raw)) continue;
      const root = expandHomeRef(raw, home);
      // Other ${VAR} references can't be resolved statically
      if (/\$\{?[A-Za-z_]/.test(root)) continue;

      const hit = isBroadPath(root, broad, home);
      const abs = normalize(expandHome(root, home)).replace(/(.)\/+$/, '$1');
      const ancestorOfHome = !hit && abs !== home && (abs === '/' || home.startsWith(`${abs}/`));
      if (!hit && !ancestorOfHome) continue;

      evidence.push({
        file: config.filePath,
        snippet: `LYRIE_FS_ROOT=${raw}`,
        detail: `Skill sandbox root ${hit ? hit.reason : 'contains the home directory'} — built-in code/file skills are not confined`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'Skill sandbox root is unset (~/.lyrie/sandbox) or narrowly scoped',
      failed: () => 'LYRIE_FS_ROOT gives Lyrie\'s file/code skills broad filesystem access',
      fixDescription: 'Unset LYRIE_FS_ROOT (default ~/.lyrie/sandbox) or point it at a dedicated project directory',
    });
  },
});
