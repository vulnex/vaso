import { basename, dirname, extname, join, normalize, relative } from 'node:path';
import type { ScanContext } from '../../core/types.js';
import { BINARY_EXTENSIONS, CODE_EXTENSIONS, isExcludedPath, relEscapes, vendorNamedSkills } from '../../core/utils.js';
import { readCappedFile } from '../../core/file-limits.js';
import { binaryFileFormat, sourceText } from '../../analyzers/binary-text.js';
import { analyzeCode, type DataFlowResult } from '../../analyzers/ast-analyzer.js';
import { analyzePythonDataFlow } from '../../analyzers/python-sinks.js';
import { vendorReferencePaths } from '../../core/skill-tree-files.js';
import { BinarySkillFile, skillFilesOf, skillsDirsOf } from './skill-files.js';

/**
 * What each skill check reads in each skill file. Every text file of a skill
 * is listed (getSkillFiles); here a file is told apart as
 *  - a script: by extension, by the interpreter SKILL.md runs it with
 *    (`python3 scripts/helper.txt`, `bash scripts/install`), or by its `#!`
 *    line — whatever its extension;
 *  - Markdown (SKILL.md, references): instructions the agent follows, read
 *    in views (MarkdownView);
 *  - package.json: its install lifecycle scripts run on `npm install`;
 *  - data: anything else (JSON, YAML, text) — read by the command patterns
 *    only, as documentation.
 */

export type SkillLang = 'js' | 'python' | 'shell' | 'ruby' | 'perl' | 'php' | 'powershell' | 'lua' | 'batch';
export type SkillFileKind = 'script' | 'markdown' | 'manifest' | 'data';

/**
 * Which part of a Markdown file a check reads (lines outside it blanked, so
 * line numbers still point into the file):
 *  - 'blocks': fenced and indented code blocks;
 *  - 'code': blocks plus inline code spans (`` `cmd` ``, `` !`cmd` ``);
 *  - 'prose': every line — for the command patterns, which match a command
 *    line wherever it is written ("Run this first: curl … | bash").
 */
export type MarkdownView = 'blocks' | 'code' | 'prose';

export interface SkillSource {
  file: string;
  text: string;
  kind: SkillFileKind;
  lang?: SkillLang;
  /** Markdown 'code' view: lines whose text comes from inline code spans only. */
  inlineLines?: ReadonlySet<number>;
  /** Markdown 'prose' view: lines that are plain prose — no code block, no inline code. */
  proseLines?: ReadonlySet<number>;
  /**
   * SKILL.md: lines holding `` !`cmd` `` spans or ```` ```! ```` blocks
   * (loadTimeCommands; a block on each of its lines) and their commands —
   * Claude Code runs them when it loads the skill, before the model reads a
   * word (unless `disableSkillShellExecution` is set). Absent when nothing runs them.
   */
  loadCommands?: ReadonlyMap<number, string[]>;
}

const LANG_BY_EXT: Record<string, SkillLang> = {
  '.js': 'js', '.mjs': 'js', '.cjs': 'js', '.jsx': 'js', '.ts': 'js', '.tsx': 'js', '.mts': 'js', '.cts': 'js',
  '.py': 'python', '.pyw': 'python',
  '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell', '.ksh': 'shell', '.fish': 'shell', '.command': 'shell',
  '.rb': 'ruby', '.pl': 'perl', '.pm': 'perl', '.php': 'php', '.lua': 'lua',
  '.ps1': 'powershell', '.psm1': 'powershell', '.bat': 'batch', '.cmd': 'batch',
};

/** Data and document formats: no `#!` line to look for. */
const DATA_EXTENSIONS = new Set([
  '.json', '.jsonc', '.json5', '.jsonl', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.env', '.properties',
  '.txt', '.text', '.rst', '.adoc', '.csv', '.tsv', '.xml', '.html', '.htm', '.css', '.scss', '.svg', '.lock', '.log',
  '.md', '.mdx', '.markdown',
]);

const MARKDOWN = /\.(?:md|mdx|markdown)$/i;

export function isMarkdownFile(file: string): boolean {
  return MARKDOWN.test(file);
}

/** The interpreter a `#!` line names (`#!/usr/bin/env -S node --flag`, `#!/bin/bash`). */
export function shebangLang(text: string): SkillLang | undefined {
  const m = /^#!\s*(\S+)(?:[ \t]+(.*))?/.exec(text.slice(0, 512));
  if (!m) return undefined;
  let prog = basename(m[1]);
  if (prog === 'env') {
    const words = (m[2] ?? '').split(/\s+/).filter(w => w && !w.startsWith('-') && !/^\w+=/.test(w));
    prog = words[0] ? basename(words[0]) : '';
  }
  return interpreterLang(prog);
}

function interpreterLang(prog: string): SkillLang | undefined {
  if (/^(?:node(?:js)?|bun|deno|tsx|ts-node)$/.test(prog)) return 'js';
  if (/^(?:python[\d.]*|pypy[\d.]*)$/.test(prog)) return 'python';
  if (/^(?:ba|z|k|da|a|fi)?sh$|^source$|^\.$/.test(prog)) return 'shell';
  if (prog === 'ruby') return 'ruby';
  if (prog === 'perl') return 'perl';
  if (/^php[\d.]*$/.test(prog)) return 'php';
  if (/^lua[\d.]*$/.test(prog)) return 'lua';
  if (/^(?:pwsh|powershell)$/i.test(prog)) return 'powershell';
  return undefined;
}

/**
 * `<interpreter> [options] <relative path>` in a SKILL.md: what it runs and
 * with what (`node scripts/tool.data`, `python3 -u scripts/helper.txt`,
 * `uv run scripts/x.py`, `bun run x.ts`, `bash "${CLAUDE_SKILL_DIR}/scripts/run.bin"`
 * — Claude Code's variable for the skill's own folder).
 */
const RUN_REFERENCE = /(?:^|[\s`'"(;&|$])((?:[\w./-]*\/)?(?:node(?:js)?|bun|deno|tsx|ts-node|python[\d.]*|pypy[\d.]*|bash|sh|zsh|ksh|dash|source|ruby|perl|php[\d.]*|lua[\d.]*|pwsh|powershell))(?:\s+(?:run|-[\w-]+(?:=\S*)?))*\s+["']?(?:\.\/|\$\{?CLAUDE_SKILL_DIR\}?\/)?((?:[\w.@+-]+\/)*[\w.@+-]+)/g;

/** The skill files a SKILL.md runs through an interpreter, and the language it runs them as. */
function runReferences(skillMd: string, text: string): Array<[string, SkillLang]> {
  const out: Array<[string, SkillLang]> = [];
  RUN_REFERENCE.lastIndex = 0;
  for (let m = RUN_REFERENCE.exec(text); m; m = RUN_REFERENCE.exec(text)) {
    const lang = interpreterLang(basename(m[1]));
    const ref = m[2];
    if (!lang || ref.split('/').some(s => s === '.' || s === '..')) continue;
    out.push([normalize(join(dirname(skillMd), ...ref.split('/'))), lang]);
  }
  return out;
}

const isSkillMd = (file: string) => basename(file).toUpperCase() === 'SKILL.MD';

/** Per file list: the language each SKILL.md runs a skill file as. */
const refCache = new WeakMap<object, Promise<Map<string, SkillLang>>>();

/** The files the installation's SKILL.md files run through an interpreter, with the language. */
export function skillRunReferences(ctx: ScanContext): Promise<Map<string, SkillLang>> {
  const key = ctx.skillFiles ?? ctx;
  let cached = refCache.get(key);
  if (!cached) {
    cached = (async () => {
      const files = await skillFilesOf(ctx);
      const listed = new Set(files);
      const out = new Map<string, SkillLang>();
      for (const file of files.filter(isSkillMd)) {
        let text: string;
        try {
          text = await readCappedFile(ctx.fs, file);
        } catch {
          continue;
        }
        for (const [path, lang] of runReferences(file, text)) {
          if (listed.has(path) && !out.has(path)) out.set(path, lang);
        }
      }
      return out;
    })();
    refCache.set(key, cached);
  }
  return cached;
}

/**
 * Folders in vendor dirs the installation's SKILL.md files run
 * (`node node_modules/helper`): the walk skips vendor dirs and only files a
 * SKILL.md names are read from them, so what such a folder holds goes
 * unreviewed (SKL-002 reports it).
 */
export async function vendorFolderRefs(ctx: ScanContext): Promise<Array<{ dir: string; skillMd: string }>> {
  const files = await skillFilesOf(ctx);
  const out: Array<{ dir: string; skillMd: string }> = [];
  for (const root of skillsDirsOf(ctx)) {
    const skillMds = files.filter(f => isSkillMd(f) && !relEscapes(relative(root, f)));
    const skills = vendorNamedSkills(root, skillMds.map(f => ({ name: basename(f), parentPath: dirname(f), isFile: true, isDirectory: false })));
    for (const file of skillMds) {
      let text: string;
      try {
        text = await readCappedFile(ctx.fs, file);
      } catch {
        continue;
      }
      for (const path of vendorReferencePaths(root, file, text)) {
        if (out.some(o => o.dir === path) || !isExcludedPath(root, dirname(path), { keepBuildOutput: true, skills })) continue;
        if (await ctx.fs.stat(path).then(st => st.isDirectory(), () => false)) out.push({ dir: path, skillMd: file });
      }
    }
  }
  return out;
}

/** Claude Code runs a SKILL.md's `` !`cmd` `` spans on load — unless a settings file turns that off. */
function runsLoadCommands(ctx: ScanContext): boolean {
  const agent = ctx.installation.agent;
  if (agent === 'skill-audit') return true;
  if (agent !== 'claude-code') return false;
  return !ctx.configs.some(c => (c.data as Record<string, unknown> | undefined)?.disableSkillShellExecution === true);
}

/** Whether `file` is code-like by its name: a failure to read it is worth a note (SKL-002). */
function codeByName(file: string, refs: ReadonlyMap<string, SkillLang>): boolean {
  const ext = extname(file).toLowerCase();
  return CODE_EXTENSIONS.has(ext) || isSkillMd(file) || refs.has(file) || (ext === '' && !basename(file).startsWith('.'));
}

/**
 * The text a check reads in a skill file, or undefined when it reads nothing
 * there:
 *  - 'code' (AST analysis): JavaScript/TypeScript and Python scripts only,
 *    however they are named;
 *  - 'patterns' (regex rules): every text file; Markdown in `view`.
 * Binary content (told by its format signature; a script never is) in a
 * file that is code by its name or by how SKILL.md runs it throws
 * BinarySkillFile, which SKL-002 reports; so does a read error or a size
 * over the limit (ScanLimitError). The same in any other file — a
 * spreadsheet template, a large dataset — is skipped quietly.
 */
export async function readSkillSource(
  ctx: ScanContext,
  file: string,
  mode: 'code' | 'patterns',
  view: MarkdownView = 'code',
  opts: { data?: boolean } = {},
): Promise<SkillSource | undefined> {
  const ext = extname(file).toLowerCase();
  const md = isMarkdownFile(file);
  const manifest = basename(file) === 'package.json';
  const refs = await skillRunReferences(ctx);
  // A compiled helper's extension (`run.bin`): judged by its content — a
  // script SKILL.md runs, or one with a `#!` line, is read as one; binary
  // content (a format signature) or a data blob is left to IOC-003/007
  if (BINARY_EXTENSIONS.has(ext)) {
    const loaded = await loadText(ctx, file);
    if ('err' in loaded) {
      if (refs.has(file)) throw loaded.err;
      return undefined;
    }
    const lang = refs.get(file) ?? shebangLang(loaded.text);
    if (!lang || (mode === 'code' && lang !== 'js' && lang !== 'python')) return undefined;
    return { file, text: loaded.text, kind: 'script', lang };
  }
  const named = LANG_BY_EXT[ext] ?? refs.get(file);
  const data = !md && !manifest && !named && DATA_EXTENSIONS.has(ext);
  if (mode === 'code' && (md || manifest || (named && named !== 'js' && named !== 'python') || data)) {
    return undefined;
  }
  // A check that skips data files needn't read one (`data: false`)
  if (data && opts.data === false) return undefined;
  const loaded = await loadText(ctx, file);
  if ('err' in loaded) {
    if (codeByName(file, refs)) throw loaded.err;
    return undefined;
  }
  const text = loaded.text;
  const lang = md || manifest ? undefined : named ?? (DATA_EXTENSIONS.has(ext) ? undefined : shebangLang(text));
  if (mode === 'code') {
    return lang === 'js' || lang === 'python' ? { file, text, kind: 'script', lang } : undefined;
  }
  if (md) {
    const parts = markdownParts(text);
    const load = isSkillMd(file) && runsLoadCommands(ctx) && parts.load.size > 0 ? parts.load : undefined;
    if (view === 'prose') {
      const proseLines = new Set<number>();
      parts.blocks.forEach((block, i) => { if (!block && !parts.inline[i]) proseLines.add(i + 1); });
      return { file, text: withoutListMarkers(text), kind: 'markdown', proseLines, ...(load ? { loadCommands: load } : {}) };
    }
    if (view === 'blocks') return { file, text: parts.blocks.join('\n'), kind: 'markdown' };
    const inlineLines = new Set<number>();
    const raw = load ? text.split('\n') : [];
    const lines = parts.blocks.map((block, i) => {
      if (block) return block;
      // a load-time command's line is code wherever its form stands
      // (a ```! fence opened mid-line, a !`…` span across lines)
      if (load?.has(i + 1)) return raw[i];
      if (!parts.inline[i]) return block;
      inlineLines.add(i + 1);
      return parts.inline[i];
    });
    return { file, text: lines.join('\n'), kind: 'markdown', inlineLines, ...(load ? { loadCommands: load } : {}) };
  }
  if (manifest) return { file, text, kind: 'manifest' };
  return lang ? { file, text, kind: 'script', lang } : { file, text, kind: 'data' };
}

type Loaded = { text: string } | { err: unknown };

/** Text read for the skill checks of one scan, per file (several checks read each file). */
const textCache = new WeakMap<object, { bytes: number; files: Map<string, Promise<Loaded>> }>();
/** Text kept for the other checks, at most: past it a file is read again by each. */
const MAX_CACHED_TEXT = 64 * 1024 * 1024;

/**
 * A skill file's text (NULs made spaces — sourceText), or why it can't be
 * had: unreadable, over the size limit, or binary (BinarySkillFile). Read
 * once per scan while the cache has room.
 */
function loadText(ctx: ScanContext, file: string): Promise<Loaded> {
  const key = ctx.skillFiles ?? ctx;
  let cache = textCache.get(key);
  if (!cache) textCache.set(key, cache = { bytes: 0, files: new Map() });
  const hit = cache.files.get(file);
  if (hit) return hit;
  const load = (async (): Promise<Loaded> => {
    try {
      const raw = await readCappedFile(ctx.fs, file);
      const format = await binaryFileFormat(ctx.fs, file, raw);
      if (format) return { err: new BinarySkillFile(file, format) };
      return { text: sourceText(raw) };
    } catch (err) {
      return { err };
    }
  })();
  if (cache.bytes < MAX_CACHED_TEXT) {
    cache.files.set(file, load);
    const entry = cache;
    void load.then(l => { entry.bytes += 'text' in l ? l.text.length : 0; });
  }
  return load;
}

/** Data flows of a JavaScript/TypeScript or Python skill script (its language, not its name, picks the analyzer). */
export function analyzeSkillSource(src: SkillSource): DataFlowResult[] {
  if (src.lang === 'python') return analyzePythonDataFlow(src.text);
  return src.lang === 'js' ? analyzeCode(src.text, jsAnalyzerName(src)) : [];
}

/**
 * The name the JavaScript analyzer reads a JavaScript source under: Babel
 * judges by the name, and a script SKILL.md runs with node is JavaScript
 * whatever it is called (`tool.data`, `helper.txt`).
 */
export function jsAnalyzerName(src: SkillSource): string {
  const ext = extname(src.file).toLowerCase();
  return LANG_BY_EXT[ext] === 'js' || ext === '' ? src.file : `${src.file}.js`;
}

/** npm runs these on `npm install` in the folder (prepare too, for a local install). */
const LIFECYCLE_SCRIPTS = new Set(['preinstall', 'install', 'postinstall', 'prepare']);

export interface PackageScript {
  name: string;
  command: string;
  /** 1-based line of its key in package.json (1 when not found). */
  line: number;
  /** Runs by itself on `npm install` (LIFECYCLE_SCRIPTS), not only on `npm run <name>`. */
  lifecycle: boolean;
}

/** The `scripts` of a package.json source; [] when it isn't one or doesn't parse. */
export function packageScripts(src: SkillSource): PackageScript[] {
  let scripts: unknown;
  try {
    scripts = (JSON.parse(src.text) as Record<string, unknown> | null)?.scripts;
  } catch {
    return [];
  }
  if (!scripts || typeof scripts !== 'object' || Array.isArray(scripts)) return [];
  const lines = src.text.split('\n');
  return Object.entries(scripts as Record<string, unknown>)
    .filter((e): e is [string, string] => typeof e[1] === 'string')
    .map(([name, command]) => {
      const at = lines.findIndex(l => l.includes(JSON.stringify(name)));
      return { name, command, line: at >= 0 ? at + 1 : 1, lifecycle: LIFECYCLE_SCRIPTS.has(name) };
    });
}

/**
 * Shell commands of a skill file that run without anyone choosing to run
 * them: a SKILL.md's `` !`cmd` `` spans (loadCommands) and a package.json's
 * install lifecycle scripts. `label` introduces the risk's reason.
 */
export function commandsRunOnTheirOwn(src: SkillSource): Array<{ command: string; line: number; label: string }> {
  if (src.kind === 'manifest') {
    return packageScripts(src).filter(s => s.lifecycle)
      .map(s => ({ command: s.command, line: s.line, label: `npm "${s.name}" script (runs on its own on \`npm install\`)` }));
  }
  // a command spanning lines (a ```! block) is listed on each: reported at its first
  return [...src.loadCommands ?? []].flatMap(([line, commands]) =>
    commands.filter(command => !src.loadCommands?.get(line - 1)?.includes(command))
      .map(command => ({ command, line, label: `${loadForm(command, src.text, line)} command (Claude Code runs it when it loads the skill)` })));
}

/**
 * How the load-time command on `line` that `matches` is written (`!`…`` or
 * ```! block), or undefined when none there does.
 */
export function loadFormAt(src: SkillSource, line: number, matches: (command: string) => boolean): string | undefined {
  const command = src.loadCommands?.get(line)?.find(matches);
  return command === undefined ? undefined : loadForm(command, src.text, line);
}

/** How a load-time command is written, for a finding's wording: `!`…`` or a ```! block. */
export function loadForm(command: string, text: string, line: number): string {
  return command.includes('\n') || !(text.split('\n')[line - 1] ?? '').includes('!`') ? '```! block' : '!`…`';
}

/** Every list marker at the start of a line blanked (scanWithPatterns skips lines starting with `*`). */
export function withoutListMarkers(text: string): string {
  return text.replace(/^([ \t]*)[*+-](?=[ \t])/gm, '$1 ');
}

export interface MarkdownParts {
  /** Fenced and indented code block lines; other lines ''. */
  blocks: string[];
  /** Inline code spans of each line outside blocks, joined; other lines ''. */
  inline: string[];
  /** 1-based lines holding load-time commands (loadTimeCommands), with them. */
  load: Map<number, string[]>;
}

const LIST_ITEM = /^\s{0,3}(?:[-*+]|\d{1,9}[.)])\s/;

/**
 * A Markdown file's code: fenced blocks (``` / ~~~), indented blocks (four
 * spaces or a tab after a blank line, not a list item's continuation) and
 * inline code spans (spans don't cross lines) — and the commands Claude Code
 * runs when it loads the file (loadTimeCommands), on every line each spans.
 */
export function markdownParts(md: string): MarkdownParts {
  const lines = md.split('\n');
  const blocks: string[] = new Array(lines.length).fill('');
  const inline: string[] = new Array(lines.length).fill('');
  const load = new Map<number, string[]>();
  let fence: string | undefined;
  let prevBlank = true;
  let indented = false;
  let inList = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = /^\s{0,3}(`{3,}|~{3,})/.exec(line);
    if (m) {
      if (!fence) fence = m[1];
      else if (m[1][0] === fence[0] && m[1].length >= fence.length) fence = undefined;
      indented = false;
      prevBlank = false;
      continue;
    }
    if (fence) {
      blocks[i] = line;
      continue;
    }
    const blank = line.trim() === '';
    if (!blank && /^(?: {4}|\t)/.test(line) && (indented || (prevBlank && !inList))) {
      blocks[i] = line;
      indented = true;
      prevBlank = false;
      continue;
    }
    if (!blank) {
      indented = false;
      if (LIST_ITEM.test(line)) inList = true;
      else if (!/^\s/.test(line)) inList = false;
      const spans = inlineSpans(line);
      if (spans.length > 0) inline[i] = spans.join(' ; ');
    }
    prevBlank = blank;
  }
  for (const run of loadTimeCommands(md)) {
    for (let line = run.line; line <= run.endLine; line++) {
      const at = load.get(line);
      if (!at) load.set(line, [run.command]);
      else if (!at.includes(run.command)) at.push(run.command);
    }
  }
  return { blocks, inline, load };
}

/** Inline code spans of one line: a run of N backticks to the next run of exactly N. */
function inlineSpans(line: string): string[] {
  const out: string[] = [];
  let i = line.indexOf('`');
  while (i >= 0 && out.length < 64) {
    let n = 1;
    while (line[i + n] === '`') n++;
    const ticks = '`'.repeat(n);
    let end = line.indexOf(ticks, i + n);
    while (end >= 0 && line[end + n] === '`') {
      let k = end;
      while (line[k] === '`') k++;
      end = line.indexOf(ticks, k);
    }
    if (end < 0) break;
    const code = line.slice(i + n, end).trim();
    if (code) out.push(code);
    i = line.indexOf('`', end + n);
  }
  return out;
}

/** A load-time command and the 1-based lines its form spans. */
export interface LoadTimeCommand {
  command: string;
  line: number;
  endLine: number;
}

/** At most this many load-time commands are read from one file. */
const MAX_LOAD_COMMANDS = 256;

/**
 * The shell commands Claude Code runs when it loads a skill or a custom
 * command, before the model reads a word — matched as Claude Code matches
 * them: a fenced block opened by ```` ```! ```` (to the next ```` ``` ````,
 * anywhere in the text; the whole block is one command), and `` !`cmd` ``
 * with the `!` at a line start or after whitespace (`` KEY=!`cmd` `` is
 * text) — a `!` inside another one-line code span doesn't count. Scanned by
 * hand: the forms' lazy regexes would rescan the rest of the file for each
 * unclosed opener.
 */
export function loadTimeCommands(md: string): LoadTimeCommand[] {
  if (!md.includes('```!') && !md.includes('!`')) return [];
  const starts: number[] = [0];
  for (let i = md.indexOf('\n'); i >= 0; i = md.indexOf('\n', i + 1)) starts.push(i + 1);
  const lineAt = (offset: number): number => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
  const out: LoadTimeCommand[] = [];
  const add = (command: string, from: number, to: number) => {
    const text = command.trim();
    if (text && out.length < MAX_LOAD_COMMANDS) out.push({ command: text, line: lineAt(from), endLine: lineAt(Math.max(from, to - 1)) });
  };
  // ```!\s*\n?([\s\S]*?)\n?```
  for (let i = md.indexOf('```!'); i >= 0 && out.length < MAX_LOAD_COMMANDS;) {
    let body = i + 4;
    while (body < md.length && /\s/.test(md[body])) body++;
    const close = md.indexOf('```', body);
    if (close < 0) break;
    add(md.slice(body, close), i, close + 3);
    i = md.indexOf('```!', close + 3);
  }
  // (?<=^|\s)!`([^`]+)` over the text with its other one-line code spans blanked
  if (md.includes('!`')) {
    const text = md.replace(/`[^`\n]+`/g, (span: string, at: number) =>
      (md[at - 1] === '!' || md[at - 1] === '`' ? span : `\`${' '.repeat(span.length - 2)}\``));
    for (let i = text.indexOf('!`'); i >= 0 && out.length < MAX_LOAD_COMMANDS;) {
      const close = text.indexOf('`', i + 2);
      if (close < 0) break;
      if ((i === 0 || /\s/.test(text[i - 1])) && close > i + 2) {
        add(text.slice(i + 2, close), i, close + 1);
        i = text.indexOf('!`', close + 1);
      } else {
        i = text.indexOf('!`', i + 1);
      }
    }
  }
  return out.sort((a, b) => a.line - b.line);
}
