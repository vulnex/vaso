import { createHash } from 'node:crypto';
import _traverse from '@babel/traverse';
import type { Node } from '@babel/types';
import { parseLenient, sourceChunks, type JsAst } from './js-parse.js';
import { sinkCallee } from './tool-input-taint.js';

// Handle ESM/CJS interop
const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as { default: typeof _traverse }).default;

export interface DataFlowResult {
  type: 'source-to-sink' | 'eval-exec' | 'suspicious-network' | 'fs-access';
  source?: string;
  /** source-to-sink: what the source variable holds — file contents or environment values. */
  sourceKind?: 'file' | 'env';
  sink?: string;
  /** source-to-sink: the receiver of a member-call sink (`axios` in `axios.post`, `res` in `res.send`). */
  sinkObject?: string;
  /**
   * eval-exec: the call's static command/code text — string and template
   * parts, `${…}` for interpolations; absent when the argument is computed.
   */
  command?: string;
  /** eval-exec: the argument is (or contains) a runtime-computed value. */
  dynamic?: boolean;
  /** eval-exec: the argument is decoded at runtime (atob, base64 Buffer, fromCharCode). */
  decoded?: boolean;
  /**
   * eval-exec: a process started directly (no shell, not an interpreter
   * given code) — what runs is a program with arguments, not code built at
   * runtime.
   */
  noShell?: boolean;
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
  // credential stores by file name — not any path containing the word
  // (`docs/secretary-notes.md`, `credentials-guide.md`)
  /(?:^|[\/])\.?credentials(?:\.(?:json|toml|ya?ml|csv|ini|db))?$/i,
  /(?:^|[\/])\.?secrets?(?:\.(?:json|toml|ya?ml|env|txt))?$/i,
  /client_secret[\w.-]*\.json$/i,
  /(?:^|[\/])\.(?:git-credentials|netrc|pgpass)$/i,
];

// Several checks (SKL-001/003/006/008/010, MCP-004/006) analyze the same
// files in one scan; parse each distinct file once. Keyed by a content hash so
// the cache never holds file contents.
const MAX_CACHED_ANALYSES = 10_000;
const analysisCache = new Map<string, DataFlowResult[]>();

export function analyzeCode(code: string, filename = 'unknown.js'): DataFlowResult[] {
  const key = `${filename}\0${createHash('sha1').update(code).digest('base64')}`;
  const cached = analysisCache.get(key);
  if (cached) return cached.map(r => ({ ...r }));
  // Per file: resolved npm packages are several modules joined with headers,
  // which don't parse as one program.
  const results = sourceChunks(code).flatMap((chunk) =>
    analyzeUncached(chunk.code).map((r) => ({ ...r, line: r.line + chunk.startLine - 1 })));
  if (analysisCache.size >= MAX_CACHED_ANALYSES) {
    analysisCache.delete(analysisCache.keys().next().value!);
  }
  analysisCache.set(key, results);
  return results.map(r => ({ ...r }));
}

function analyzeUncached(code: string): DataFlowResult[] {
  const results: DataFlowResult[] = [];
  let ast: JsAst;
  // Split once: re-splitting the file per call expression made analysis
  // quadratic in file size.
  let lines: string[] | undefined;
  const lineText = (line: number): string => (lines ??= code.split('\n'))[line - 1]?.trim() ?? '';

  const parsed = parseLenient(code);
  if (!parsed) return results;
  ast = parsed;

  // Variable → what it holds. Matched in sink arguments as a whole identifier:
  // a substring test made a minified `o` match every `output`.
  const sourceVars = new Map<string, 'file' | 'env'>();
  const mentions = (argStr: string, name: string): boolean =>
    new RegExp(`(?<![\\w$.])${name.replace(/[.$]/g, '\\$&')}(?![\\w$])`).test(argStr);
  const networkImports = new Set<string>();
  // Subset of sinks that spawn processes (child_process) rather than open connections
  const processImports = new Set<string>();

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
          // Still a sink (spawned commands can exfiltrate), but a process one
          for (const spec of path.node.specifiers) {
            networkImports.add(spec.local.name);
            processImports.add(spec.local.name);
          }
        }
      },

      CallExpression(path) {
        const node = path.node;
        const line = node.loc?.start.line ?? 0;
        const snippet = lineText(line);

        // Detect eval/exec — aliased, destructured, required inline or
        // dynamically imported child_process, execa/shelljs, indirect eval —
        // and any bare call named like one.
        const sink = sinkCallee(path);
        if (sink || (node.callee.type === 'Identifier' && EXEC_FUNCTIONS.has(node.callee.name))) {
          const name = sink?.display ?? (node.callee as { name: string }).name;
          results.push({
            type: 'eval-exec',
            line,
            snippet: snippet.slice(0, 120),
            description: sink && node.callee.type === 'MemberExpression' && sink.kind === 'process'
              ? `${name}() — command execution`
              : `${name}() call detected`,
            ...commandText(node.arguments),
            ...(runsDirectly(name, node.arguments) ? { noShell: true } : {}),
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
            sourceVars.set(parent.id.name, 'file');
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
              sourceVars.set(parent.id.name, 'file');
            }
          }

          // Sink detection: fetch(), http.request(), ws.send()
          if (SINKS.has(propName) || networkImports.has(propName)) {
            // Check if any source variables flow into this call
            const argStr = code.slice(node.arguments[0]?.start ?? 0, node.arguments[node.arguments.length - 1]?.end ?? 0);
            const receiver = node.callee.object;
            const sinkObject = receiver.type === 'Identifier'
              ? receiver.name
              : receiver.type === 'MemberExpression' && receiver.property.type === 'Identifier' ? receiver.property.name : undefined;
            for (const [sourceVar, sourceKind] of sourceVars) {
              if (mentions(argStr, sourceVar)) {
                results.push({
                  type: 'source-to-sink',
                  source: sourceVar,
                  sourceKind,
                  sink: propName,
                  ...(sinkObject ? { sinkObject } : {}),
                  line,
                  snippet: snippet.slice(0, 120),
                  description: processImports.has(propName) || EXEC_FUNCTIONS.has(propName)
                    ? `Data flows from "${sourceVar}" into process execution "${propName}"`
                    : `Data flows from "${sourceVar}" to network sink "${propName}"`,
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
            sourceVars.set('process.env', 'env');
          }

          // Detect child_process methods (sinkCallee above covers resolvable ones)
          if (EXEC_FUNCTIONS.has(propName) && !sink) {
            const obj = node.callee.object;
            if (obj.type === 'Identifier' && (networkImports.has(obj.name) || obj.name === 'child_process')) {
              results.push({
                type: 'eval-exec',
                line,
                snippet: snippet.slice(0, 120),
                description: `${obj.name}.${propName}() — command execution`,
                ...commandText(node.arguments),
                ...(runsDirectly(propName, node.arguments) ? { noShell: true } : {}),
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
              // A relative URL (`/api/items`, `./data.json`) stays on the
              // page's own origin; `//host/…` is protocol-relative and leaves it.
              const relative = /^(?:\/(?!\/)|\.\.?\/)/.test(url);
              if (!relative &&
                  !url.startsWith('http://localhost') &&
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
            for (const [sourceVar, sourceKind] of sourceVars) {
              const argStr = code.slice(
                node.arguments[0]?.start ?? 0,
                node.arguments[node.arguments.length - 1]?.end ?? 0,
              );
              if (mentions(argStr, sourceVar)) {
                results.push({
                  type: 'source-to-sink',
                  source: sourceVar,
                  sourceKind,
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
          sourceVars.set(id.name, 'env');
        }
      },

      // Detect new Function() and new WebSocket()
      NewExpression(path) {
        const node = path.node;
        if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
          const line = node.loc?.start.line ?? 0;
          const snippet = lineText(line);
          results.push({
            type: 'eval-exec',
            line,
            snippet: snippet.slice(0, 120),
            description: 'new Function() constructor — dynamic code execution',
            ...commandText(node.arguments),
          });
        }
        if (node.callee.type === 'Identifier' && node.callee.name === 'WebSocket') {
          const line = node.loc?.start.line ?? 0;
          const snippet = lineText(line);
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

type ArgNode = Node | { type: string };

/**
 * Static text of a command/code argument list: string literals and template
 * quasis as written, `${…}` for interpolations, array elements (spawn argv)
 * joined with spaces. Flags computed values and runtime decoding.
 */
/** child_process calls that start a program without a shell (unless `shell: true`). */
const DIRECT_EXEC_FUNCTIONS = new Set(['execFile', 'execFileSync', 'spawn', 'spawnSync']);
const SHELL_OR_INTERPRETER = /^(?:.*\/)?(?:sh|bash|zsh|dash|ksh|fish|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|node|deno|bun|python[\d.]*|perl|ruby|php|osascript)$/i;

/**
 * A program started directly — `execFileSync('git', [...])`, `spawn('ffmpeg', args)`:
 * the program is a literal that is neither a shell nor an interpreter (which
 * would run code given as an argument), and no `shell: true` option. What it
 * runs is a known program with runtime arguments, not code built at runtime
 * (same rule as the Python analyzer's subprocess without shell=True).
 */
function runsDirectly(name: string, args: ArgNode[]): boolean {
  if (!DIRECT_EXEC_FUNCTIONS.has(name.slice(name.lastIndexOf('.') + 1))) return false;
  const program = args[0] as Node | undefined;
  if (program?.type !== 'StringLiteral' || SHELL_OR_INTERPRETER.test(program.value.trim())) return false;
  return !args.some(a => {
    const n = a as Node;
    return n.type === 'ObjectExpression' && n.properties.some(p =>
      p.type === 'ObjectProperty'
      && ((p.key.type === 'Identifier' && p.key.name === 'shell') || (p.key.type === 'StringLiteral' && p.key.value === 'shell'))
      && !(p.value.type === 'BooleanLiteral' && !p.value.value));
  });
}

function commandText(args: ArgNode[]): Pick<DataFlowResult, 'command' | 'dynamic' | 'decoded'> {
  let dynamic = false;
  let decoded = false;
  const text = (node: ArgNode | null | undefined, depth = 0): string => {
    if (!node || depth > 6) return '';
    const n = node as Node;
    switch (n.type) {
      case 'StringLiteral':
        return n.value;
      case 'TemplateLiteral':
        return n.quasis.map((q, i) => (q.value.cooked ?? '') + (i < n.expressions.length ? (dynamic = true, '${…}') : '')).join('');
      case 'ArrayExpression':
        return n.elements.map((e) => text(e as ArgNode, depth + 1)).join(' ');
      case 'BinaryExpression':
        return n.operator === '+' ? text(n.left, depth + 1) + text(n.right, depth + 1) : ((dynamic = true), '');
      case 'CallExpression': {
        const src = calleeText(n.callee);
        const bufferToString = src === '.toString' && n.callee.type === 'MemberExpression' &&
          n.callee.object.type === 'CallExpression' && calleeText(n.callee.object.callee) === 'Buffer.from';
        if (bufferToString || /^(?:atob|String\.fromCharCode|unescape)$/.test(src)) decoded = true;
        if (n.callee.type === 'MemberExpression' && n.callee.object.type === 'CallExpression') text(n.callee.object, depth + 1);
        dynamic = true;
        return '${…}';
      }
      case 'ObjectExpression':
        return ''; // spawn/exec options
      default:
        dynamic = true;
        return '${…}';
    }
  };
  const command = args.slice(0, 2).map((a) => text(a)).filter(Boolean).join(' ').trim();
  return { ...(command && command !== '${…}' ? { command } : {}), ...(dynamic ? { dynamic } : {}), ...(decoded ? { decoded } : {}) };
}

function calleeText(callee: Node): string {
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') {
    const obj = callee.object.type === 'Identifier' ? callee.object.name : '';
    return obj ? `${obj}.${callee.property.name}` : `.${callee.property.name}`;
  }
  return '';
}
