import { createHash } from 'node:crypto';
import _traverse from '@babel/traverse';
import type { Node } from '@babel/types';
import type { NodePath } from '@babel/traverse';
import { mayBeJavaScript, parseLenientReport, recordedEvasion, sourceChunks, type JsAst } from './js-parse.js';
import { bindingModule, memberName, sinkCallee } from './tool-input-taint.js';
import { analyzeFlows, type SourcePath, type Taint } from './js-flow.js';

// Handle ESM/CJS interop
const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as { default: typeof _traverse }).default;

export interface DataFlowResult {
  /**
   * module-call / param-sink: a value read from a file or the environment
   * passed to a helper module of the skill, and a helper module's exported
   * parameter that reaches a send — joined across the skill's files by SKL-001.
   */
  type: 'source-to-sink' | 'eval-exec' | 'suspicious-network' | 'fs-access' | 'module-call' | 'param-sink';
  source?: string;
  /** source-to-sink: what the source variable holds — file contents or environment values. */
  sourceKind?: 'file' | 'env';
  sink?: string;
  /** source-to-sink: the receiver of a member-call sink (`axios` in `axios.post`, `res` in `res.send`). */
  sinkObject?: string;
  /** source-to-sink: the sink is `send` on a client socket the code opened (`new WebSocket(url)`). */
  socketClient?: boolean;
  /** source-to-sink: the source is the whole environment (`process.env`, or a variable holding it). */
  wholeEnv?: boolean;
  /**
   * source-to-sink (file): where the file read lives, when its path could be
   * worked out — a credential store, outside the skill and workspace, the
   * skill's own file, a workspace file, or chosen at runtime. Absent: unknown
   * (Python and line-scan flows), judged as before.
   */
  sourcePath?: SourcePath;
  /** source-to-sink (file): the path as resolved (`~/.ssh/id_rsa`). */
  resolvedPath?: string;
  /** source-to-sink: found by following the value (await, callbacks, transforms, helpers), not by name. */
  derived?: boolean;
  /** source-to-sink: the data leaves in a DNS query name. */
  dns?: boolean;
  /** module-call / param-sink: the relative module (`./lib/upload`), export and argument position. */
  module?: string;
  exportName?: string;
  argIndex?: number;
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
  /**
   * eval-exec: an interpreter or shell started directly with literal code
   * (`python -c "import sys; …"`, or a constant holding the script) — the
   * code is fixed; what follows it is the code's argv.
   */
  fixedCode?: boolean;
  line: number;
  snippet: string;
  description: string;
}

const SOURCES = new Set([
  'readFile', 'readFileSync', 'readdir', 'readdirSync',
  'createReadStream',
]);

const ENV_SOURCES = new Set(['env']);

/** Programs whose arguments go over the network (as in the Python analyzer). */
const NETWORK_PROGRAM = /^(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|ftp|rsync|ssh|telnet)$/;

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
  if (!mayBeJavaScript(filename)) return [];
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

/**
 * First line (1-based) of code in `code` that defeats the parser — a
 * statement nested or chained deeply enough to overflow it, which the AST
 * checks skip — or undefined. Shares the parse with analyzeCode.
 */
export function analysisEvasion(code: string, filename = 'unknown.js'): { line: number; whole: boolean } | undefined {
  if (!mayBeJavaScript(filename)) return undefined;
  analyzeCode(code, filename);
  for (const chunk of sourceChunks(code)) {
    const rec = recordedEvasion(chunk.code) ?? (() => {
      const r = parseLenientReport(chunk.code);
      return { lines: r.evaded, whole: r.overflow && !r.ast };
    })();
    if (rec.whole) return { line: chunk.startLine, whole: true };
    if (rec.lines.length > 0) return { line: rec.lines[0] + chunk.startLine - 1, whole: false };
  }
  return undefined;
}

/**
 * Last resort when an overflow left no AST at all: a line-by-line look for
 * what the AST checks would have reported — exec/eval calls, and a request
 * or send carrying file contents or the environment — so a file built to
 * crash the parser doesn't come out clean.
 */
export function lineFallback(code: string): DataFlowResult[] {
  const out: DataFlowResult[] = [];
  const execCall = /(?<![\w$.])(?:eval|exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(|\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(|\bnew\s+Function\s*\(/;
  const send = /(?<![\w$])fetch\s*\(|\.(?:post|put|patch|request|send|write)\s*\(/;
  const source = /\breadFile(?:Sync)?\s*\(|(?<![\w$])process\.env\b/;
  const sourceVars = new Set<string>();
  code.split('\n').forEach((text, i) => {
    if (text.length > 4000) return; // the over-deep line itself
    const decl = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;]*)/.exec(text);
    if (decl && source.test(decl[2])) sourceVars.add(decl[1]);
    const snippet = text.trim().slice(0, 120);
    if (execCall.test(text)) {
      out.push({ type: 'eval-exec', line: i + 1, snippet, description: 'Command or code execution (line scan — the file overflows the parser)', dynamic: true });
    }
    if (send.test(text)) {
      const carried = source.test(text) ? 'inline source' : [...sourceVars].find(v => new RegExp(`(?<![\\w$.])${v}(?![\\w$])`).test(text));
      if (carried) {
        out.push({ type: 'source-to-sink', source: carried, sourceKind: 'file', line: i + 1, snippet, description: `Data flows from "${carried}" to a network call (line scan — the file overflows the parser)` });
      }
    }
  });
  return out;
}

function analyzeUncached(code: string): DataFlowResult[] {
  const results: DataFlowResult[] = [];
  let ast: JsAst;
  // Split once: re-splitting the file per call expression made analysis
  // quadratic in file size.
  let lines: string[] | undefined;
  const lineText = (line: number): string => (lines ??= code.split('\n'))[line - 1]?.trim() ?? '';

  const report = parseLenientReport(code);
  if (!report.ast) return report.overflow ? lineFallback(code) : results;
  ast = report.ast;
  // Module-level `const NAME = 'literal'`: a program named through a constant
  // (`spawnSync(FFMPEG, args)`) is as known as one written inline
  const constStrings = new Map<string, string>();
  for (const stmt of ast.program.body) {
    const decl = stmt.type === 'ExportNamedDeclaration' ? stmt.declaration : stmt;
    if (decl?.type !== 'VariableDeclaration' || decl.kind !== 'const') continue;
    for (const d of decl.declarations) {
      if (d.id.type !== 'Identifier' || !d.init) continue;
      if (d.init.type === 'StringLiteral') constStrings.set(d.id.name, d.init.value);
      else if (d.init.type === 'TemplateLiteral' && d.init.expressions.length === 0) constStrings.set(d.id.name, d.init.quasis[0]?.value.cooked ?? '');
    }
  }

  // Variable → what it holds. Matched in sink arguments as a whole identifier:
  // a substring test made a minified `o` match every `output`.
  const sourceVars = new Map<string, 'file' | 'env'>();
  const mentions = (argStr: string, name: string): boolean =>
    new RegExp(`(?<![\\w$.])${name.replace(/[.$]/g, '\\$&')}(?![\\w$])`).test(argStr);
  const networkImports = new Set<string>();
  // Environment values written inline in a request (`body: JSON.stringify(process.env)`,
  // `axios.post(url, process.env.KEY)`), by the rules of the Python analyzer:
  // the whole environment anywhere in the call, a single value only in the
  // request body (an API key in the headers of its own API is not a leak).
  const inlineEnv = (args: Node[], sinkName: string): string[] => inlineSources(args, sinkName, false)
    .filter(([, kind]) => kind === 'env').map(([name]) => name);
  /**
   * Sources written inline in a sink call: file contents (`readFileSync(…)`)
   * and the whole environment anywhere in it; a single environment value in
   * a request body — or, for a network program's argv (`allEnv`), anywhere.
   */
  const inlineSources = (args: Node[], sinkName: string, allEnv: boolean): Array<[string, 'file' | 'env']> => {
    if (args.length === 0) return [];
    const all = code.slice(args[0].start ?? 0, args[args.length - 1].end ?? 0);
    const out: Array<[string, 'file' | 'env']> = [];
    const file = all.match(/(?<![\w$])(?:fs\.)?(?:promises\.)?readFile(?:Sync)?\s*\(/);
    if (file) out.push([`${file[0].replace(/\s*\($/, '')}()`, 'file']);
    if (/(?<![\w$])(?<!(?:^|[^.])\.)process\.env(?![\w$]|\s*(?:\.|\[|\?\.))/.test(all)) out.push(['process.env', 'env']);
    const single = allEnv ? all : requestBody(args, sinkName);
    for (const m of single.matchAll(/(?<![\w$.])process\.env(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])/g)) out.push([m[0], 'env']);
    return out;
  };
  // Client sockets the code opens (`const ws = new WebSocket(url)`): `ws.send(…)`
  // goes to that remote endpoint, unlike a server socket answering its client
  const clientSockets = new Set<string>();
  // Variables holding the whole environment (`const e = process.env`, `{ ...process.env }`)
  // Variables holding the whole environment, by binding: minified code reuses
  // short names, and a parameter `t` in one function is not the `process.env`
  // copy `t` in another. Names only for unbound (global) assignments.
  const wholeEnvVars = new Set<string>();
  const wholeEnvBindings = new Set<object>();
  const wholeEnvAt = (p: NodePath, v: string): boolean => {
    if (v === 'process.env') return true;
    const binding = p.scope.getBinding(v);
    return binding ? wholeEnvBindings.has(binding) : wholeEnvVars.has(v);
  };
  const requestBody = (args: Node[], sinkName: string): string => {
    const text = (n: Node | undefined) => (n ? code.slice(n.start ?? 0, n.end ?? 0) : '');
    const parts: string[] = [];
    if (/^(?:send|write|emit)$/.test(sinkName)) parts.push(...args.map(text));
    if (/^(?:post|put|patch)$/.test(sinkName)) parts.push(text(args[1]));
    for (const a of args) {
      if (a.type !== 'ObjectExpression') continue;
      for (const p of a.properties) {
        if (p.type !== 'ObjectProperty') continue;
        const key = p.key.type === 'Identifier' ? p.key.name : p.key.type === 'StringLiteral' ? p.key.value : '';
        if (/^(?:body|data|json|form|payload)$/.test(key)) parts.push(text(p.value as Node));
      }
    }
    return parts.join(',');
  };
  // Subset of sinks that spawn processes (child_process) rather than open connections
  const processImports = new Set<string>();
  // `import 'zx/globals'` (or a zx script) puts `$` on the global object
  const zxGlobals = ast.program.body.some(st => st.type === 'ImportDeclaration' && /^zx(?:\/globals)?$/.test(st.source.value) && st.specifiers.length === 0)
    || /^#!.*\bzx\b/.test(code);

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
            ...(runsDirectly(sink?.fn ?? name, node.arguments, constStrings) ? { noShell: true } : {}),
          });
          if (sink?.kind === 'process' || !sink) {
            // What the process gets: file contents or the whole environment in
            // its arguments, or — for a network client (curl, nc, scp…) — any
            // environment value: `execFile('curl', ['-d', JSON.stringify(process.env), url])`
            // argv only: an options object (`{ env: process.env, cwd }`) configures
            // the child, it isn't data the child receives
            // (and a callback isn't argv either)
            const args = (node.arguments as Node[]).filter(a =>
              a.type !== 'ObjectExpression' && a.type !== 'FunctionExpression' && a.type !== 'ArrowFunctionExpression');
            const first = args[0];
            const program = first?.type === 'StringLiteral' ? first.value
              : first?.type === 'Identifier' ? constStrings.get(first.name) : undefined;
            const network = program !== undefined && NETWORK_PROGRAM.test(program.split('/').pop() ?? '');
            const pairs = inlineSources(args, name, network);
            // Variables only for a bare call: member calls (`cp.exec(x)`) are
            // matched against tracked variables in the sink branch below
            // Each argument's own text: a span from first to last argument took
            // in an options object between them (`execFile(p, argv, {env}, cb)`)
            const argStr = args.map(a => code.slice(a.start ?? 0, a.end ?? 0)).join(' ');
            if (node.callee.type === 'Identifier') {
              for (const [v, kind] of sourceVars) {
                if ((kind === 'file' || network || wholeEnvAt(path, v)) && mentions(argStr, v) && !pairs.some(([n]) => n === v)) pairs.push([v, kind]);
              }
            }
            for (const [sourceVar, sourceKind] of pairs) {
              if (sourceKind === 'env' && !wholeEnvAt(path, sourceVar) && !network) continue;
              results.push({
                type: 'source-to-sink',
                source: sourceVar,
                sourceKind,
                ...(sourceKind === 'env' && wholeEnvAt(path, sourceVar) ? { wholeEnv: true } : {}),
                sink: name,
                line,
                snippet: snippet.slice(0, 120),
                description: network
                  ? `Data flows from "${sourceVar}" to network program "${program}"`
                  : `Data flows from "${sourceVar}" into process execution "${name}"`,
              });
            }
          }
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
            const processSink = processImports.has(propName) || EXEC_FUNCTIONS.has(propName);
            const inlinePairs = processSink ? [] : inlineSources(node.arguments as Node[], propName, false);
            const inline = inlinePairs.map(([name]) => name);
            const socketClient = propName === 'send' && sinkObject !== undefined && clientSockets.has(sinkObject);
            for (const [sourceVar, sourceKind] of new Map<string, 'file' | 'env'>([...sourceVars, ...inlinePairs])) {
              if (inline.includes(sourceVar) || mentions(argStr, sourceVar)) {
                results.push({
                  type: 'source-to-sink',
                  source: sourceVar,
                  sourceKind,
                  ...(sourceKind === 'env' && wholeEnvAt(path, sourceVar) ? { wholeEnv: true } : {}),
                  sink: propName,
                  ...(sinkObject ? { sinkObject } : {}),
                  ...(socketClient ? { socketClient } : {}),
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
                ...(runsDirectly(propName, node.arguments, constStrings) ? { noShell: true } : {}),
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
            const inlinePairs = inlineSources(node.arguments as Node[], 'fetch', false);
            const inline = inlinePairs.map(([name]) => name);
            for (const [sourceVar, sourceKind] of new Map<string, 'file' | 'env'>([...sourceVars, ...inlinePairs])) {
              const argStr = code.slice(
                node.arguments[0]?.start ?? 0,
                node.arguments[node.arguments.length - 1]?.end ?? 0,
              );
              if (inline.includes(sourceVar) || mentions(argStr, sourceVar)) {
                results.push({
                  type: 'source-to-sink',
                  source: sourceVar,
                  sourceKind,
                  ...(sourceKind === 'env' && wholeEnvAt(path, sourceVar) ? { wholeEnv: true } : {}),
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

        if (init.type === 'NewExpression' && (
          (init.callee.type === 'Identifier' && init.callee.name === 'WebSocket')
          || (init.callee.type === 'MemberExpression' && init.callee.property.type === 'Identifier' && init.callee.property.name === 'WebSocket')
        )) clientSockets.add(id.name);

        const initText = code.slice(init.start ?? 0, init.end ?? 0);
        // Assigned, spread, or copied/serialized whole (not passed to some other call)
        const copies = init.type !== 'CallExpression'
          || /^(?:JSON\.stringify|Object\.assign|Object\.entries|structuredClone)\s*\(/.test(initText);
        if (copies && /(?<![\w$])(?<!(?:^|[^.])\.)process\.env(?![\w$]|\s*(?:\.|\[|\?\.))/.test(initText)) {
          sourceVars.set(id.name, 'env');
          const binding = path.scope.getBinding(id.name);
          if (binding) wholeEnvBindings.add(binding);
          else wholeEnvVars.add(id.name);
        }

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

      // zx / execa `$\`cmd ${arg}\``: a command run through a shell, each
      // interpolation quoted as one argument
      TaggedTemplateExpression(path) {
        const tag = path.node.tag;
        const fn = tag.type === 'CallExpression' ? tag.callee : tag.type === 'MemberExpression' && memberIs(tag, 'sync') ? tag.object : tag;
        if (fn.type !== 'Identifier' || fn.name !== '$') return;
        const mod = bindingModule(path.scope.getBinding('$'));
        if (mod ? !/^(?:zx(?:\/core)?|execa)$/.test(mod) : !zxGlobals) return;
        const line = path.node.loc?.start.line ?? 0;
        const quasi = path.node.quasi;
        const parts = quasi.quasis.map((q, i) => (q.value.cooked ?? '') + (i < quasi.expressions.length ? '${…}' : '')).join('');
        const program = (quasi.quasis[0]?.value.cooked ?? '').trim().split(/\s+/)[0] ?? '';
        const dynamic = quasi.expressions.length > 0;
        results.push({
          type: 'eval-exec',
          line,
          snippet: lineText(line).slice(0, 120),
          description: `${mod ?? 'zx'} $\`…\` — command execution`,
          ...(parts.trim() ? { command: parts.trim() } : {}),
          ...(dynamic ? { dynamic: true } : {}),
          // The program is written out and interpolations are quoted: unless it
          // is a shell or interpreter, what runs is that program with arguments
          ...(dynamic && program && !program.includes('${') && !SHELL_OR_INTERPRETER.test(program) ? { noShell: true } : {}),
        });
      },

      // Detect new Function() and new WebSocket()
      NewExpression(path) {
        const node = path.node;
        // new vm.Script(code) / new (require('vm').Script)(code)
        const vmSink = node.callee.type !== 'Identifier' ? sinkCallee(path) : undefined;
        if (vmSink?.kind === 'code') {
          const line = node.loc?.start.line ?? 0;
          results.push({
            type: 'eval-exec',
            line,
            snippet: lineText(line).slice(0, 120),
            description: `new ${vmSink.display}() — dynamic code execution`,
            ...commandText(node.arguments),
          });
        }
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

  for (const r of results) {
    if (r.type === 'source-to-sink' && r.sourceKind === 'env' && r.source === 'process.env') r.wholeEnv = true;
  }
  mergeFlows(ast, results, lineText);
  return results;
}

const describePath = (t: Taint): string => (t.kind === 'file' && t.resolved && t.resolved !== '…' ? ` (${t.resolved})` : '');

/**
 * Add what value-following finds (js-flow.ts) to the name-matched results:
 * where each file flow's path leads, flows the name match missed, credential
 * reads through built paths, and calls into the skill's helper modules.
 */
function mergeFlows(ast: JsAst, results: DataFlowResult[], lineText: (line: number) => string): void {
  let fa: ReturnType<typeof analyzeFlows>;
  try {
    fa = analyzeFlows(ast);
  } catch {
    return;
  }
  const byLine = new Map<number, typeof fa.flows>();
  for (const f of fa.flows) byLine.set(f.line, [...(byLine.get(f.line) ?? []), f]);
  const pathFields = (t: Taint | undefined): Pick<DataFlowResult, 'sourcePath' | 'resolvedPath'> =>
    t?.kind === 'file' && t.path ? { sourcePath: t.path, ...(t.resolved ? { resolvedPath: t.resolved } : {}) } : {};

  const covered = new Set<number>();
  for (const r of results) {
    if (r.type !== 'source-to-sink') continue;
    covered.add(r.line);
    if (r.sourceKind !== 'file') continue;
    const same = byLine.get(r.line)?.find(f => f.taint.kind === 'file' && (f.source === r.source || !fa.namedReads.has(r.source ?? '')));
    Object.assign(r, pathFields(same?.taint ?? fa.namedReads.get(r.source ?? '')));
  }
  for (const f of fa.flows) {
    if (covered.has(f.line)) continue;
    const t = f.taint;
    const kind = t.kind === 'file' ? 'file' : 'env';
    const what = t.kind === 'host' ? (f.source === t.origin ? '' : ` (${t.origin})`) : describePath(t);
    results.push({
      type: 'source-to-sink',
      source: f.source,
      sourceKind: kind,
      ...(t.kind === 'env' && t.wholeEnv ? { wholeEnv: true } : {}),
      ...pathFields(t),
      sink: f.sink,
      ...(f.sinkObject ? { sinkObject: f.sinkObject } : {}),
      derived: true,
      ...(f.dns ? { dns: true } : {}),
      line: f.line,
      snippet: lineText(f.line).slice(0, 120),
      description: f.via
        ? `Data flows from "${f.source}"${what} through ${f.via}() to ${f.sink}`
        : f.dns
          ? `Data flows from "${f.source}"${what} into a DNS query name (${f.sink})`
          : `Data flows from "${f.source}"${what} to ${/(?:^|\.|\()fetch\)?$/.test(f.sink) ? `${f.sink}()` : `network sink "${f.sink}"`}`,
    });
  }
  const reported = new Set(results.filter(r => r.type === 'fs-access').map(r => r.line));
  for (const c of fa.credentialReads) {
    if (reported.has(c.line)) continue;
    results.push({ type: 'fs-access', source: c.resolved, line: c.line, snippet: lineText(c.line).slice(0, 120), description: `Reading sensitive path: ${c.resolved}` });
  }
  for (const m of fa.moduleCalls) {
    const t = m.taint;
    results.push({
      type: 'module-call', source: m.source, sourceKind: t.kind === 'file' ? 'file' : 'env',
      ...(t.kind === 'env' && t.wholeEnv ? { wholeEnv: true } : {}), ...pathFields(t),
      module: m.module, exportName: m.exportName, argIndex: m.argIndex,
      line: m.line, snippet: lineText(m.line).slice(0, 120),
      description: `Data from "${m.source}"${describePath(t)} passed to ${m.module}`,
    });
  }
  for (const p of fa.paramSinks) {
    results.push({
      type: 'param-sink', exportName: p.exportName, argIndex: p.paramIndex, sink: p.sink,
      line: p.line, snippet: lineText(p.line).slice(0, 120),
      description: `Parameter ${p.paramIndex + 1} of export "${p.exportName}" reaches ${p.sink}`,
    });
  }
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
 * the program is a literal (or a module-level string constant) that is neither a shell nor an interpreter (which
 * would run code given as an argument), and no `shell: true` option. What it
 * runs is a known program with runtime arguments, not code built at runtime
 * (same rule as the Python analyzer's subprocess without shell=True).
 */
function runsDirectly(name: string, args: ArgNode[], constStrings: ReadonlyMap<string, string>): boolean {
  if (!DIRECT_EXEC_FUNCTIONS.has(name.slice(name.lastIndexOf('.') + 1))) return false;
  const program = args[0] as Node | undefined;
  const value = program?.type === 'StringLiteral' ? program.value
    : program?.type === 'Identifier' ? constStrings.get(program.name) : undefined;
  if (value === undefined || !value.trim() || SHELL_OR_INTERPRETER.test(value.trim())) return false;
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

function memberIs(m: Node, name: string): boolean {
  return memberName(m) === name;
}

function calleeText(callee: Node): string {
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') {
    const obj = callee.object.type === 'Identifier' ? callee.object.name : '';
    return obj ? `${obj}.${callee.property.name}` : `.${callee.property.name}`;
  }
  return '';
}
