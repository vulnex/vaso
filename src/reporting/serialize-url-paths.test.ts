import { describe, it, expect } from 'vitest';
import { maskCredentialsInText } from './serialize.js';

// dt20 g3-F6: `mcp list` and reports printed path credentials (Zapier MCP) in full
describe('maskCredentialsInText: credentials in URL paths', () => {
  it.each([
    ['URL: https://actions.zapier.com/mcp/sk-ak-Zq7XyR9kLmN3pQ8sT2vW5bC6dF1gH4jK/sse', 'URL: https://actions.zapier.com/mcp/***/sse'],
    ['URL: https://mcp.zapier.com/api/mcp/s/NjQ4ZTk2YmUtZmY3Ny00ZDQ5LWE1ZjMtYjc2ZTkzN2E2NTRhOjE2MzQ1Njc4OQ==/mcp', 'URL: https://mcp.zapier.com/api/mcp/s/***/mcp'],
    ['see https://mcp.example.com/v1/Qm8xR2vN7pL4tW9yB3dF6hJ1kZ5n/sse.', 'see https://mcp.example.com/v1/***/sse.'],
  ])('%s', (text, expected) => {
    expect(maskCredentialsInText(text)).toBe(expected);
  });

  it('keeps ordinary paths readable', () => {
    const text = 'URL: https://mcp.example.com/v1/projects/3f9a1c7e-2b8d-4f6a-0c5e-9b1d7f3a8c2e/mcp';
    expect(maskCredentialsInText(text)).toBe(text);
  });
});
