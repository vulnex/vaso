import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { chmodFile } from '../../remediation/config-writer.js';

const CREDENTIAL_FILE = 'credentials.json';

export const cfg020 = defineCheck({
  id: 'CFG-020',
  name: 'NemoClaw API Key Exposure',
  category: 'config',
  severity: 'critical',
  description: 'Check if NemoClaw credentials.json stores API keys in plaintext with unsafe file permissions',
  supportedAgents: ['openclaw', 'nemoclaw'],

  async run(ctx, h) {
    const credPath = join(ctx.fs.homedir(), '.nemoclaw', CREDENTIAL_FILE);

    if (!(await ctx.fs.access(credPath))) {
      return h.passed('No NemoClaw credentials file found');
    }

    const evidence: Evidence[] = [];
    let hasPlaintextKey = false;
    let hasLoosePerms = false;

    // Check file permissions (unix only)
    if (ctx.fs.platform === 'darwin' || ctx.fs.platform === 'linux') {
      try {
        const stats = await ctx.fs.stat(credPath);
        const mode = stats.mode & 0o777;
        if (mode & 0o077) {
          hasLoosePerms = true;
          evidence.push({
            file: credPath,
            detail: `Permissions: ${mode.toString(8)} — group/other can read credentials (should be 600)`,
          });
        }
      } catch {}
    }

    // Check for plaintext API keys
    try {
      const raw = await ctx.fs.readFile(credPath);
      const creds = JSON.parse(raw) as Record<string, unknown>;

      for (const [key, value] of Object.entries(creds)) {
        if (typeof value === 'string' && value.length > 0) {
          // Detect common API key patterns
          const isApiKey = /api[_-]?key|token|secret|password/i.test(key);
          const looksLikeKey = /^(nvapi-|sk-|key-|ghp_|ghs_|glpat-)/.test(value) ||
            (value.length >= 32 && /^[A-Za-z0-9+/=_-]+$/.test(value));

          if (isApiKey || looksLikeKey) {
            hasPlaintextKey = true;
            const redacted = value.slice(0, 8) + '...' + value.slice(-4);
            evidence.push({
              file: credPath,
              detail: `Plaintext key "${key}": ${redacted} (${value.length} chars)`,
            });
          }
        }
      }
    } catch {
      evidence.push({ file: credPath, detail: 'Credentials file exists but could not be parsed' });
    }

    const passed = !hasPlaintextKey && !hasLoosePerms;

    return h.result({
      passed,
      message: passed
        ? 'NemoClaw credentials are properly secured'
        : `NemoClaw credentials at risk: ${[
            hasPlaintextKey && 'plaintext API keys',
            hasLoosePerms && 'overly permissive file permissions',
          ].filter(Boolean).join(', ')}`,
      evidence,
      fixable: hasLoosePerms,
      fixDescription: hasLoosePerms ? 'Set credentials.json permissions to 600 (owner read/write only)' : undefined,
    });
  },

  async fix(ctx) {
    const credPath = join(ctx.fs.homedir(), '.nemoclaw', CREDENTIAL_FILE);
    if (!(await ctx.fs.access(credPath))) {
      return { checkId: 'CFG-020', applied: false, message: 'Credentials file not found' };
    }

    try {
      await chmodFile(credPath, 0o600);
      return {
        checkId: 'CFG-020',
        applied: true,
        message: 'Set credentials.json permissions to 600 (owner read/write only)',
      };
    } catch (err) {
      return {
        checkId: 'CFG-020',
        applied: false,
        message: `Failed to fix permissions: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  },
});
