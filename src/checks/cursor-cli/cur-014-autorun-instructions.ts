import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { redactProseSecrets } from '../../core/patterns.js';
import { maskCredentialsInLine } from '../../reporting/serialize.js';
import { maskProseSecrets } from '../../mcp/source-snippet.js';

// permissions.json (global ~/.cursor/ + project .cursor/, merged) drives
// Auto-run: allow_instructions are natural-language/pattern grants the agent
// applies without prompting. Blanket grants defeat the approval gate the way
// bare Shell() allows do in cli-config.json (CUR-003).
const BLANKET_RE = /^\s*(\*|all|everything|any(thing| command| commands)?|run (everything|anything|any command))\s*$/i;
const DANGEROUS_WORD_RE = /\b(curl|wget|bash|sh|zsh|perl|python3?|node|npx|uvx|ssh|scp|sudo|chmod|rm|eval)\b/i;
const BROAD_VERB_RE = /\b(allow|run|execute|permit)\b.*\b(all|any|every)\b|\b(all|any|every)\b.*\b(command|shell|terminal)s?\b/i;

export const cur014 = defineCheck({
  id: 'CUR-014',
  name: 'Cursor Auto-Run Instructions Too Broad',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect permissions.json autoRun allow_instructions that grant blanket or dangerous-command execution without prompts',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('permissions.json')) continue;
      const autoRun = config.data.autoRun as Record<string, unknown> | undefined;
      if (!autoRun || typeof autoRun !== 'object') continue;

      const allow = Array.isArray(autoRun.allow_instructions) ? autoRun.allow_instructions : [];
      const block = Array.isArray(autoRun.block_instructions) ? autoRun.block_instructions : [];

      for (const entry of allow) {
        if (typeof entry !== 'string') continue;
        if (BLANKET_RE.test(entry) || BROAD_VERB_RE.test(entry)) {
          evidence.push({
            file: config.filePath,
            snippet: maskCredentialsInLine(redactProseSecrets(maskProseSecrets(entry))),
            detail: 'Blanket auto-run grant — the agent executes matching commands with no prompt',
          });
        } else if (DANGEROUS_WORD_RE.test(entry)) {
          evidence.push({
            file: config.filePath,
            snippet: maskCredentialsInLine(redactProseSecrets(maskProseSecrets(entry))),
            detail: 'Auto-run grant covers a command that provides network access or arbitrary execution',
          });
        }
      }

      if (allow.length > 0 && block.length === 0) {
        evidence.push({
          file: config.filePath,
          snippet: `${allow.length} allow instruction(s), no block instructions`,
          detail: 'Auto-run allows are configured with no block list backstop',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Cursor auto-run instructions are scoped',
      failed: (n) => `Found ${n} over-broad auto-run instruction(s) in permissions.json`,
      fixDescription: 'Scope allow_instructions to specific safe commands and add block_instructions for network/exec/deletion commands',
    });
  },
});
