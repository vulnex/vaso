import { describe, it, expect } from 'vitest';
import { policyEvidence } from './policy-rules.js';

const policy = (toolName: string) => ({
  raw: '', format: 'toml' as const, filePath: '/home/test/.gemini/policies/p.toml',
  data: { rule: [{ toolName, decision: 'allow' }] },
});

describe('Gemini policy mcp_<server>_* wording', () => {
  it('names both readings when the server part holds an underscore', () => {
    expect(policyEvidence(policy('mcp_github_get_*'))[0].detail)
      .toBe('Every tool of MCP server "github_get" (or the "get_*" tools of server "github") runs without confirmation');
    expect(policyEvidence(policy('mcp_github_*'))[0].detail).toBe('Every tool of MCP server "github" runs without confirmation');
  });
});
