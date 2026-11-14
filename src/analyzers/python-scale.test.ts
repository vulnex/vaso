import { describe, it, expect } from 'vitest';
import { findExternalContentFlows } from './tool-result-flow.js';
import { analyzePythonSinks } from './python-sinks.js';

// Many module-level functions: lookups per def/statement must not scan the
// whole file (a backward scan per def made 60k defs take minutes).
function manyDefs(n: number, body: (i: number) => string): string {
  const out = ['import subprocess, httpx', 'from mcp.server.fastmcp import FastMCP', 'mcp = FastMCP("x")'];
  for (let i = 0; i < n; i++) out.push(`def f${i}(x):`, `    ${body(i)}`);
  return out.join('\n');
}

describe('Python analysis scales linearly with module size', () => {
  it('result flow over 20k functions with HTTP clients', () => {
    const code = manyDefs(20000, (i) => `return client.get("https://example.com/${i}").text`) +
      '\n@mcp.tool()\ndef fetch(url: str) -> str:\n    return httpx.get(url).text\n';
    const t = Date.now();
    const flows = findExternalContentFlows(code, 'python');
    expect(Date.now() - t).toBeLessThan(8000);
    expect(flows.some((f) => f.callerChosenUrl)).toBe(true);
  });

  it('sinks over 20k functions that run commands', () => {
    const code = manyDefs(20000, () => 'return subprocess.run("ls " + x, shell=True)');
    const t = Date.now();
    const findings = analyzePythonSinks(code);
    expect(Date.now() - t).toBeLessThan(8000);
    expect(findings.filter((f) => f.kind === 'exec')).toHaveLength(20000);
  });

  it('a method still knows its class after the stack rewrite', () => {
    const code = [
      'import httpx',
      'from mcp.server.fastmcp import FastMCP',
      'mcp = FastMCP("x")',
      'class Fetcher:',
      '    BASE = "https://en.wikipedia.org/wiki/"',
      '    def get(self, title):',
      '        return httpx.get(self.BASE + title).text',
      'fetcher = Fetcher()',
      '@mcp.tool()',
      'def page(title: str) -> str:',
      '    return fetcher.get(title)',
    ].join('\n');
    const [flow] = findExternalContentFlows(code, 'python');
    expect(flow?.host).toBe('en.wikipedia.org');
  });
});
