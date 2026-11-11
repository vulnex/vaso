import { dirname, join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { truncateSnippet } from '../../core/patterns.js';

/** `// turbo` / `// turbo-all` alone on a line (list markers and CR line ends allowed). */
const TURBO_DIRECTIVE = /^\s*(?:[-*]\s+)?\/\/\s*turbo(-all)?\s*$/;

const WORKSPACE_WORKFLOW_DIRS = [join('.devin', 'workflows'), join('.windsurf', 'workflows')];

/** Workflow dirs from cwd up to the git root (cwd alone outside a repo). */
async function workspaceWorkflowDirs(cwd: string, ctx: ScanContext): Promise<string[]> {
  const chain: string[] = [];
  for (let dir = cwd; ; dir = dirname(dir)) {
    chain.push(dir);
    if (await ctx.fs.access(join(dir, '.git'))) break;
    if (dirname(dir) === dir) {
      chain.splice(1);
      break;
    }
  }
  return chain.flatMap(dir => WORKSPACE_WORKFLOW_DIRS.map(rel => join(dir, rel)));
}

export const ws006 = defineCheck({
  id: 'WS-006',
  name: 'Windsurf Turbo Directive in Workflows',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect // turbo and // turbo-all directives in global and workspace (.devin/workflows, .windsurf/workflows) workflow files, which auto-run commands without approval',
  supportedAgents: ['windsurf'],

  async run(ctx, h) {
    const home = ctx.fs.homedir();
    const dirs = [join(home, '.codeium', 'windsurf', 'global_workflows')];
    // Workspace workflows: .devin/workflows (preferred) and legacy
    // .windsurf/workflows, discovered in the workspace and up to its git root
    // (Devin Docs, "Cascade workflows"). Only the scanning user's install
    // looks at the cwd workspace.
    if (ctx.installation.installDir.startsWith(home)) dirs.push(...await workspaceWorkflowDirs(process.cwd(), ctx));

    const evidence: Evidence[] = [];
    let found = false;
    for (const workflowsDir of dirs) {
      let files: string[];
      try {
        if (!(await ctx.fs.access(workflowsDir))) continue;
        files = await ctx.fs.readdir(workflowsDir);
      } catch {
        continue;
      }
      found = true;
      for (const name of files) {
        if (!name.endsWith('.md')) continue;
        const filePath = join(workflowsDir, name);
        let content: string;
        try {
          content = await ctx.fs.readFile(filePath);
        } catch {
          continue;
        }

        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          // The directive is a line of its own (`// turbo` above a step,
          // `// turbo-all` anywhere); `// turbocharged build` is prose
          const directive = TURBO_DIRECTIVE.exec(line);
          if (!directive) continue;
          const isTurboAll = directive[1] === '-all';
          evidence.push({
            file: filePath,
            line: i + 1,
            snippet: truncateSnippet(line.trim()),
            detail: isTurboAll
              ? "'// turbo-all' auto-runs EVERY command in this workflow without approval"
              : "'// turbo' auto-runs the annotated command without approval",
          });
        }
      }
    }
    if (!found) return h.passed('No Windsurf workflow directories present');

    return h.fromEvidence(evidence, {
      passed: 'No turbo auto-execution directives in Windsurf workflows',
      failed: (n) => `Found ${n} turbo directive(s) in Windsurf workflows`,
      fixDescription: 'Remove // turbo and // turbo-all lines from workflow files so commands require approval',
    });
  },
});
