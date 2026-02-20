import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import type { Node } from '@babel/types';

// Handle ESM/CJS interop
const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as { default: typeof _traverse }).default;

export interface DataFlowResult {
  type: 'source-to-sink' | 'eval-exec' | 'suspicious-network' | 'fs-access';
  source?: string;
  sink?: string;
  line: number;
  snippet: string;
  description: string;
}

const SOURCES = new Set([
  'readFile', 'readFileSync', 'readdir', 'readdirSync',
  'createReadStream',
]);

const ENV_SOURCES = new Set(['env']);

const SINKS = new Set([
  'fetch', 'request', 'get', 'post', 'put', 'patch',
  'send', 'write', 'emit',
]);

const NETWORK_MODULES = new Set([
  'http', 'https', 'net', 'dgram', 'axios', 'got',
  'node-fetch', 'undici', 'request',
]);

const EXEC_FUNCTIONS = new Set([
  'eval', 'Function',
  'exec', 'execSync', 'spawn', 'spawnSync',
  'execFile', 'execFileSync', 'fork',
]);

const SENSITIVE_PATHS = [
  /\/\.ssh\//i,
  /\/\.aws\//i,
  /\/\.gnupg\//i,
  /\/\.kube\//i,
  /\/\.env/i,
  /\/etc\/(?:passwd|shadow|hosts)/i,
  /\/\.docker\/config/i,
  /credentials/i,
  /secret/i,
];

export function analyzeCode(code: string, filename = 'unknown.js'): DataFlowResult[] {
  const results: DataFlowResult[] = [];
  let ast: ReturnType<typeof parse>;

  try {
    ast = parse(code, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx', 'decorators'],
      errorRecovery: true,
    });
  } catch {
    return results;
  }

  const sourceVars = new Set<string>();
  const networkImports = new Set<string>();

  try {
    traverse(ast, {
      ImportDeclaration(path) {
        const source = path.node.source.value;
        if (NETWORK_MODULES.has(source)) {
          for (const spec of path.node.specifiers) {
            networkImports.add(spec.local.name);
          }
        }
        if (source === 'child_process') {
          for (const spec of path.node.specifiers) {
            networkImports.add(spec.local.name);
          }
        }
      },

      CallExpression(path) {
        const node = path.node;
        const line = node.loc?.start.line ?? 0;
        const snippet = code.split('\n')[line - 1]?.trim() ?? '';

        // Detect eval/exec
        if (node.callee.type === 'Identifier' && EXEC_FUNCTIONS.has(node.callee.name)) {
          results.push({
            type: 'eval-exec',
            line,
            snippet: snippet.slice(0, 120),
            description: `${node.callee.name}() call detected`,
          });
        }

        // Detect require('child_process')
        if (
          node.callee.type === 'Identifier' &&
          node.callee.name === 'require' &&
          node.arguments[0]?.type === 'StringLiteral'
        ) {
          const mod = node.arguments[0].value;
          if (NETWORK_MODULES.has(mod) || mod === 'child_process') {
            networkImports.add(mod);
          }
        }

        // Detect standalone readFile('sensitive-path') calls (from named imports)
        if (node.callee.type === 'Identifier' && SOURCES.has(node.callee.name)) {
          const firstArg = node.arguments[0];
          if (firstArg?.type === 'StringLiteral') {
            for (const pattern of SENSITIVE_PATHS) {
              if (pattern.test(firstArg.value)) {
                results.push({
                  type: 'fs-access',
                  source: firstArg.value,
                  line,
                  snippet: snippet.slice(0, 120),
                  description: `Reading sensitive path: ${firstArg.value}`,
                });
              }
            }
          }
          // Track variable assignment for data-flow
          const parent = path.parent;
          if (parent?.type === 'VariableDeclarator' && parent.id.type === 'Identifier') {
            sourceVars.add(parent.id.name);
          }
        }

        // Detect member call expressions: obj.method()
        if (node.callee.type === 'MemberExpression') {
          const prop = node.callee.property;
          const propName = prop.type === 'Identifier' ? prop.name : '';

          // Source detection: fs.readFile, fs.readFileSync, etc.
          if (SOURCES.has(propName)) {
            // Check if reading sensitive paths
            const firstArg = node.arguments[0];
            if (firstArg?.type === 'StringLiteral') {
              for (const pattern of SENSITIVE_PATHS) {
                if (pattern.test(firstArg.value)) {
                  results.push({
                    type: 'fs-access',
                    source: firstArg.value,
                    line,
                    snippet: snippet.slice(0, 120),
                    description: `Reading sensitive path: ${firstArg.value}`,
                  });
                }
              }
            }

            // Track variable assignment for data-flow
            const parent = path.parent;
            if (parent?.type === 'VariableDeclarator' && parent.id.type === 'Identifier') {
              sourceVars.add(parent.id.name);
            }
          }

          // Sink detection: fetch(), http.request(), ws.send()
          if (SINKS.has(propName) || networkImports.has(propName)) {
            // Check if any source variables flow into this call
            const argStr = code.slice(node.arguments[0]?.start ?? 0, node.arguments[node.arguments.length - 1]?.end ?? 0);
            for (const sourceVar of sourceVars) {
              if (argStr.includes(sourceVar)) {
                results.push({
                  type: 'source-to-sink',
                  source: sourceVar,
                  sink: propName,
                  line,
                  snippet: snippet.slice(0, 120),
                  description: `Data flows from "${sourceVar}" to network sink "${propName}"`,
                });
              }
            }
          }

          // process.env access
          if (
            propName === 'env' &&
            node.callee.object.type === 'Identifier' &&
            (node.callee.object as { name: string }).name === 'process'
          ) {
            sourceVars.add('process.env');
          }

          // Detect child_process methods
          if (EXEC_FUNCTIONS.has(propName)) {
            const obj = node.callee.object;
            if (obj.type === 'Identifier' && (networkImports.has(obj.name) || obj.name === 'child_process')) {
              results.push({
                type: 'eval-exec',
                line,
                snippet: snippet.slice(0, 120),
                description: `${obj.name}.${propName}() — command execution`,
              });
            }
          }
        }

        // Detect standalone fetch/network calls
        if (node.callee.type === 'Identifier') {
          if (node.callee.name === 'fetch') {
            const firstArg = node.arguments[0];
            if (firstArg?.type === 'StringLiteral') {
              const url = firstArg.value;
              if (!url.startsWith('http://localhost') &&
                  !url.startsWith('http://127.0.0.1') &&
                  !url.startsWith('https://')) {
                results.push({
                  type: 'suspicious-network',
                  sink: url,
                  line,
                  snippet: snippet.slice(0, 120),
                  description: `Non-localhost HTTP or non-HTTPS fetch: ${url}`,
                });
              }
            }

            // Check data-flow into fetch
            for (const sourceVar of sourceVars) {
              const argStr = code.slice(
                node.arguments[0]?.start ?? 0,
                node.arguments[node.arguments.length - 1]?.end ?? 0,
              );
              if (argStr.includes(sourceVar)) {
                results.push({
                  type: 'source-to-sink',
                  source: sourceVar,
                  sink: 'fetch',
                  line,
                  snippet: snippet.slice(0, 120),
                  description: `Data flows from "${sourceVar}" to fetch()`,
                });
              }
            }
          }
        }
      },

      // Track variable assignments from sources
      VariableDeclarator(path) {
        const init = path.node.init;
        if (!init) return;
        const id = path.node.id;
        if (id.type !== 'Identifier') return;

        // Track process.env.X assignments
        if (
          init.type === 'MemberExpression' &&
          init.object.type === 'MemberExpression' &&
          init.object.object.type === 'Identifier' &&
          (init.object.object as { name: string }).name === 'process' &&
          init.object.property.type === 'Identifier' &&
          init.object.property.name === 'env'
        ) {
          sourceVars.add(id.name);
        }
      },

      // Detect new Function() and new WebSocket()
      NewExpression(path) {
        const node = path.node;
        if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
          const line = node.loc?.start.line ?? 0;
          const snippet = code.split('\n')[line - 1]?.trim() ?? '';
          results.push({
            type: 'eval-exec',
            line,
            snippet: snippet.slice(0, 120),
            description: 'new Function() constructor — dynamic code execution',
          });
        }
        if (node.callee.type === 'Identifier' && node.callee.name === 'WebSocket') {
          const line = node.loc?.start.line ?? 0;
          const snippet = code.split('\n')[line - 1]?.trim() ?? '';
          results.push({
            type: 'suspicious-network',
            sink: 'WebSocket',
            line,
            snippet: snippet.slice(0, 120),
            description: 'WebSocket connection created',
          });
        }
      },
    });
  } catch {
    // Traverse errors shouldn't crash the analysis
  }

  return results;
}
