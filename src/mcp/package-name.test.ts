import { describe, it, expect } from 'vitest';
import { bareName, serviceCore } from './package-name.js';

describe('bareName', () => {
  it.each([
    ['@modelcontextprotocol/server-github@1.0.0', '@modelcontextprotocol/server-github'],
    ['@scope/pkg', '@scope/pkg'],
    ['mcp-remote@latest', 'mcp-remote'],
    ['mcp-server-git==0.6.2', 'mcp-server-git'],
    ['mcp-server-fetch[cli]>=1.0', 'mcp-server-fetch'],
  ])('%s → %s', (spec, name) => {
    expect(bareName(spec)).toBe(name);
  });
});

describe('serviceCore', () => {
  it.each([
    ['twittter-mcp', 'twittter'],
    ['@modelcontextprotocol/server-github@1.0.0', 'github'],
    ['mcp-server-brave-search', 'bravesearch'],
    ['@notionhq/notion-mcp-server', 'notion'],
    ['mcp-server', ''],
  ])('%s → %s', (name, core) => {
    expect(serviceCore(name)).toBe(core);
  });
});
