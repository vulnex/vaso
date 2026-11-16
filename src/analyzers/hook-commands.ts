import { SECURITY_PATTERNS, scanWithPatterns } from './pattern-engine.js';
import { shellCommandWrapper } from '../mcp/shell-wrapper.js';
import { findArgSecrets, type ConfigSecret } from '../mcp/config-secrets.js';
import { scriptCommands, shellWords } from '../mcp/script-command.js';

/**
 * Shell-command analysis shared by the agent hook checks (CC-003, CUR-015,
 * WS-009). A hook is a command the agent runs on its own on every matching
 * event — often from a repository's committed config — so a download piped
 * into a shell runs remote code on each session, and a hook that ships its
 * stdin elsewhere ships the prompts, code and commands the agent handles.
 */

const FETCH_EXEC_RULES = SECURITY_PATTERNS.filter(r => r.category === 'curl-pipe');
const CREDENTIAL_RULES = SECURITY_PATTERNS.filter(r => r.category === 'credential-harvest');

/** Hosts that hide where a script or upload really goes (SKL-004's list plus request-capture services). */
const OPAQUE_HOSTS = /^(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|goo\.gl|cutt\.ly|rb\.gy|pastebin\.com|paste\.ee|hastebin\.com|termbin\.com|transfer\.sh|0x0\.st|webhook\.site|requestbin\.(?:com|net)|pipedream\.net|[\w-]+\.m\.pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|[\w-]+\.ngrok(?:-free)?\.(?:io|app|dev)|[\w-]+\.trycloudflare\.com|[\w-]+\.oast\.(?:fun|live|me|online|pro|site)|[\w-]+\.burpcollaborator\.net|[\w-]+\.interact\.sh)$/i;

/**
 * A `$` expansion or backtick substitution, other than plain $HOME and the
 * `trusted` variables — paths the agent itself sets for hooks (Claude Code's
 * ${CLAUDE_PROJECT_DIR}, Cursor's $CURSOR_PROJECT_DIR, …), which carry no
 * tool or prompt input.
 */
export function hookExpansion(trusted: readonly string[] = []): RegExp {
  const names = ['HOME', ...trusted].join('|');
  return new RegExp(`\`|\\$(?!\\{?(?:${names})\\b)[({A-Za-z_@*0-9]`);
}

const DYNAMIC_EXPANSION = hookExpansion();

/**
 * Shell text that is evaluated a second time with expanded data in it: `eval`
 * or `exec` as a command word with an expansion in its arguments, or a shell
 * `-c` script that the outer shell expands (unquoted or double-quoted). A
 * single-quoted `bash -c '…'` script is constant — its own contents are
 * judged by the other patterns — and `docker compose exec` / `npm exec` are
 * not the shell builtin. `expansion` says which expansions count (Claude Code
 * passes one that skips its path placeholders). A double-quoted argument is
 * read to its closing quote, past the separators inside it
 * (`bash -c "cd $DIR && $(jq -r .cmd)"`).
 */
export function evaluatesDynamicText(cmd: string, expansion: RegExp = DYNAMIC_EXPANSION): boolean {
  const separator = /;|&&|\|\||\||\n/g;
  let start = 0;
  // quoted spans read past their segment, at most 1 MiB in all (stays linear)
  let budget = 1 << 20;
  for (;;) {
    const sep = separator.exec(cmd);
    const end = sep ? sep.index : cmd.length;
    const raw = cmd.slice(start, end);
    // drop sudo / env / VAR=value prefixes to reach the command word
    const seg = raw.trim().replace(/^(?:(?:sudo|env|command|nohup)(?:\s+-\S+)*\s+|[A-Za-z_][A-Za-z0-9_]*=\S*\s+)+/, '');
    const word = /^(\S+)\s*(.*)$/s.exec(seg);
    if (word) {
      const [, head, rest] = word;
      // the argument text, a double-quoted one through its closing quote
      const argument = (text: string): string => {
        if (!text.startsWith('"') || budget <= 0) return text;
        const span = quotedSpan(cmd, start + raw.lastIndexOf(text));
        budget -= span.length;
        return span;
      };
      if ((head === 'eval' || head === 'exec') && expansion.test(argument(rest))) return true;
      if (/^(?:\S*\/)?(?:ba|z|da|k|mk)?sh$/.test(head)) {
        const c = /(?:^|\s)-[a-zA-Z]*c[a-zA-Z]*\s+(.*)$/s.exec(rest);
        if (c && !c[1].startsWith("'") && expansion.test(argument(c[1]))) return true;
      }
    }
    if (!sep) return false;
    start = end + sep[0].length;
  }
}

/** The double-quoted string starting at `at` (the opening quote), through its closing quote; at most 16 KiB. */
function quotedSpan(text: string, at: number): string {
  const limit = Math.min(text.length, at + 16_384);
  for (let i = at + 1; i < limit; i++) {
    if (text[i] === '\\') i++;
    else if (text[i] === '"') return text.slice(at, i + 1);
  }
  return text.slice(at, limit);
}

// `curl … | bash`, `jq -r .tool_input.command | sh`: whatever arrives on the
// pipe (a download, or the hook's JSON input) runs as a script
export const PIPE_TO_SHELL_PATTERN = /\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*\/)?(?:env\s+)?(?:ba|z|da|k|mk|fi)?sh\b(?!\s+[^\s|;&-]\S*)/;

/**
 * A network client sending data: curl with a request body or upload
 * (`-d`, `--data*`, `-F`, `--json`, `-T`), wget `--post-*`/`--body-*`, or
 * input piped/redirected into nc/ncat/netcat/telnet. Single-line, no nested
 * quantifiers over the same characters (hook commands are short, but the
 * check runs on repository-supplied text).
 */
const CURL_SEND = /\bcurl\b[^|;&\n]{0,2000}?\s(?:-[a-zA-Z]*[dFT]|--(?:data(?:-binary|-raw|-urlencode|-ascii)?|form|json|upload-file))(?=[\s=@'"]|$)/;
const WGET_SEND = /\bwget\b[^|;&\n]{0,2000}?\s--(?:post|body)-(?:data|file)\b/;
// input piped or redirected into a raw socket client, or into ssh (`… | ssh host 'cat > x'`)
const RAW_SOCKET_SEND = /\|\s*(?:nc|ncat|netcat|telnet|ssh)\s|\b(?:nc|ncat|netcat|telnet|ssh)\s[^|;&\n]{0,500}?<\s*\S/;
/**
 * A file copy to another host: scp / rsync / sftp whose LAST argument is a
 * remote target (`host:path`, `user@host:path`, rsync `host::module`) — an
 * upload; a remote source copied to a local path is a download.
 */
const REMOTE_COPY_SEND = /\b(?:scp|rsync|sftp)\s[^|;&\n]{0,2000}?\s(?:[\w.+-]{1,64}@)?([\w.-]{1,253}):{1,2}[^\s:'"]{0,1000}\s*$/;
/** Material worth stealing in the same script: environment dumps, secret-named variables. */
const SECRET_VARIABLE = /\$\{?[A-Z0-9_]{0,64}(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)\b/;
const SECRET_MATERIAL = new RegExp(`\\b(?:env|printenv|set)\\s*(?:\\||>)|${SECRET_VARIABLE.source}`);
/** A request header carrying a secret-named variable (`curl -H "Authorization: Bearer $API_KEY" …`). */
const HEADER_SECRET = new RegExp(`\\b(?:curl|wget|http|https|xh)\\b[^|;&\\n]{0,2000}?\\s(?:-H|--header)(?:\\s+|=)["']?[^"'\\n]{0,500}?${SECRET_VARIABLE.source}`);
/** `xargs … sh -c …`: every input line becomes shell code. */
const XARGS_SHELL = /\bxargs\b[^|;&\n]{0,500}?\s(?:[^\s/]{0,64}\/){0,8}(?:ba|z|da|k|mk)?sh\s+(?:-[a-zA-Z]+\s+){0,4}?-[a-zA-Z]*c\b/;
/** An interpreter given inline code (`python3 -c "…"`, `node -e '…'`, `perl -e …`). */
const INLINE_CODE = /(?:^|[\s;&|(])(?:[^\s/]{0,64}\/){0,8}(?:python[\d.]*|node|perl|ruby|php)\s+(?:-[A-Za-z]+\s+){0,4}?-(?:c|e|-eval)\s+/g;
/** Inline code that runs a command it builds (os.system, subprocess, child_process, exec/eval). */
const CODE_EXEC_SINK = /\b(?:os\.(?:system|popen|exec\w*|spawn\w*)|subprocess\.\w+|commands\.getoutput|pty\.spawn|child_process|exec(?:Sync|File|FileSync)?\s*\(|spawn(?:Sync)?\s*\(|system\s*\(|eval\s*\(|exec\s*\(|`)/;
/** …from the hook's input (stdin). */
const CODE_STDIN = /\b(?:sys\.stdin|process\.stdin|STDIN|stdin|input\s*\(\s*\))|\/dev\/stdin|readFileSync\(\s*0\b/;

export type HookRiskTier = 'critical' | 'warning' | 'info';

export interface HookRisk {
  tier: HookRiskTier;
  reason: string;
}

/** Where a network send in `line` goes, judged by its first URL. */
function destinationTier(line: string): { tier: 'warning' | 'info'; dest: string } {
  const raw = /https?:\/\/[^\s"'`|)<>;]+/.exec(line)?.[0];
  if (!raw) return { tier: 'warning', dest: 'a raw socket or computed address' };
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { tier: 'warning', dest: raw };
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const opaque = url.protocol !== 'https:' || /^[\d.]+$/.test(host) || host.includes(':') || OPAQUE_HOSTS.test(host);
  return { tier: opaque ? 'warning' : 'info', dest: `${url.protocol}//${host}` };
}

const STATEMENT_WINDOW = 16_384;
const STATEMENT_OVERLAP = 4_096;
/** Words every download-and-execute pattern contains (a cheap prefilter). */
const FETCH_WORD = /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|iex|invoke-expression)\b/i;

/**
 * The statements of a hook script, each analysed on its own: split at `;`,
 * `&&`, `||` and newlines (a pipeline stays whole; a newline after `|`, `&&`,
 * `||` or a backslash continues the statement), whitespace runs collapsed and
 * duplicates dropped, so padding a command — thousands of `true;` or of
 * spaces — cannot push a dangerous statement out of view. A statement longer
 * than 16 KiB is read in 16 KiB windows overlapping by 4 KiB. Linear in the
 * script's length; the patterns only ever see bounded text.
 */
export function hookStatements(script: string): string[] {
  const joined = script.replace(/\\\r?\n|(\|\|?|&&)[ \t]*\r?\n/g, (_m, op: string | undefined) => (op ? `${op} ` : ' '));
  const out = new Set<string>();
  for (const raw of joined.split(/;|&&|\|\||\r?\n/)) {
    const stmt = raw.replace(/\s+/g, ' ').trim();
    if (!stmt) continue;
    if (stmt.length <= STATEMENT_WINDOW) {
      out.add(stmt);
      continue;
    }
    for (let i = 0; ; i += STATEMENT_WINDOW - STATEMENT_OVERLAP) {
      out.add(stmt.slice(i, i + STATEMENT_WINDOW));
      if (i + STATEMENT_WINDOW >= stmt.length) break;
    }
  }
  return [...out];
}

/**
 * Credentials written into a hook's shell text, read statement by statement
 * as argv: `--password <pw>`, `-p<pw>` after a MySQL client, `sshpass -p`,
 * `redis-cli -a`, `https://user:<pw>@host`, `Authorization: Basic …`
 * headers, `NAME=<token>` assignments, known token formats. Each value comes
 * with a masked rendering; never print `value`.
 */
export function hookCommandSecrets(script: string): ConfigSecret[] {
  const out: ConfigSecret[] = [];
  const read = (words: string[], depth: number): void => {
    for (const secret of findArgSecrets(words)) {
      if (!out.some(o => o.value === secret.value)) out.push(secret);
    }
    if (depth >= MAX_NESTED_COMMANDS) return;
    for (const nested of nestedCommands(words)) {
      for (const stmt of scriptCommands(nested)) read(shellWords(stmt), depth + 1);
    }
  };
  for (const stmt of hookStatements(script)) read(shellWords(stmt), 0);
  return out;
}

/** How deep commands quoted inside commands are read (`ssh h "bash -c 'mysql -pX app'"` is two levels). */
const MAX_NESTED_COMMANDS = 3;
/** ssh options that take a value (OpenSSH ssh(1)): the host is the first word after the options. */
const SSH_VALUE_OPTION = /^-[BbcDEeFIiJLlmOoPpQRSWw]$/;

/**
 * The words of a command that are commands themselves, to be read as shell
 * text: a shell's `-c` script (`sh -c '…'`, also run through `sudo`, `env`,
 * `docker exec`, `xargs`), `su -c '…'`, the remote command `ssh [options]
 * host …` runs, and what `eval` evaluates. Only these positions: any other
 * argument is data — a commit message (`git commit -m "use sshpass -p x"`),
 * text `echo` prints, a search pattern — and a password-client command
 * spelled out in it runs nowhere.
 */
function nestedCommands(words: readonly string[]): string[] {
  const out: string[] = [];
  const name = (w: string): string => w.replace(/^.*\//, '');
  for (let i = 0; i < words.length; i++) {
    const w = name(words[i]);
    if (w === 'eval' && i === 0) {
      out.push(words.slice(1).join(' '));
    } else if (w === 'su') {
      const c = words.findIndex((a, k) => k > i && (a === '-c' || a === '--command'));
      if (c >= 0 && c + 1 < words.length) out.push(words[c + 1]);
    } else if (w === 'ssh') {
      let k = i + 1;
      while (k < words.length && words[k].startsWith('-') && words[k] !== '--') k += SSH_VALUE_OPTION.test(words[k]) ? 2 : 1;
      if (words[k] === '--') k++;
      // words after the host: ssh joins them with spaces for the remote shell
      if (k + 1 < words.length) out.push(words.slice(k + 1).join(' '));
      return out;
    } else if (shellCommandWrapper(words[i], words.slice(i + 1))) {
      const c = words.findIndex((a, k) => k > i && /^-[a-zA-Z]*c[a-zA-Z]*$/.test(a));
      const script = words.findIndex((a, k) => k > c && !a.startsWith('-'));
      if (c >= 0 && script >= 0) out.push(words[script]);
      return out;
    }
  }
  return out;
}

/**
 * Risks in one hook's shell text (`command`, or a PowerShell variant).
 * critical: downloads and runs code, or sends credential files / secret
 * variables / the environment over the network. warning: sends data to a
 * plaintext, IP, paste/tunnel or computed destination, or re-evaluates
 * expanded text as code. info: sends hook input to a named https host (the
 * documented audit-logging shape — still everything the agent handles).
 * The whole script is read, statement by statement (hookStatements).
 * `expansion` says which `$` expansions count as data — each agent passes
 * hookExpansion() with the path variables it sets for hooks.
 */
export function hookCommandRisks(script: string, opts: { expansion?: RegExp } = {}): HookRisk[] {
  const statements = hookStatements(script);
  const risks: HookRisk[] = [];

  let fetchExec: ReturnType<typeof scanWithPatterns> = [];
  for (const stmt of statements) {
    if (!FETCH_WORD.test(stmt)) continue;
    fetchExec = scanWithPatterns(stmt, FETCH_EXEC_RULES);
    if (fetchExec.length > 0) break;
  }
  if (fetchExec.length > 0) {
    risks.push({ tier: 'critical', reason: `downloads and executes code (${fetchExec[0].description.toLowerCase()}) every time the hook fires` });
  }

  // Credential material anywhere in the script taints a send anywhere in it
  // (`cp ~/.ssh/id_rsa /tmp/k; curl -T /tmp/k …`).
  const credentials = statements.some(stmt => SECRET_MATERIAL.test(stmt) || scanWithPatterns(stmt, CREDENTIAL_RULES).length > 0);
  for (const stmt of statements) {
    const copy = REMOTE_COPY_SEND.exec(stmt);
    if (!copy && !CURL_SEND.test(stmt) && !WGET_SEND.test(stmt) && !RAW_SOCKET_SEND.test(stmt)) continue;
    const { tier, dest } = copy ? { tier: 'warning' as const, dest: `${copy[1]} (scp/rsync/sftp upload)` } : destinationTier(stmt);
    if (credentials) {
      risks.push({ tier: 'critical', reason: `sends credential files, secret variables or the environment over the network (${dest})` });
    } else if (tier === 'warning') {
      risks.push({ tier, reason: `sends data to ${dest} (plaintext, IP, paste/tunnel host or computed address) — hook input carries prompts, code and commands` });
    } else {
      risks.push({ tier, reason: `sends data to ${dest} — hook input carries prompts, code and commands (audit-logging shape; confirm the endpoint is yours)` });
    }
    break;
  }

  // A secret variable in a request header goes to whoever runs that host
  // (no request body needed). The API the key belongs to is a normal use, so
  // a named https host is a warning; a plaintext, IP, paste/tunnel or
  // computed destination is critical.
  if (!risks.some(r => r.tier === 'critical')) {
    for (const stmt of statements) {
      if (!HEADER_SECRET.test(stmt)) continue;
      const { tier, dest } = destinationTier(stmt);
      risks.push(tier === 'warning'
        ? { tier: 'critical', reason: `sends a secret variable in a request header to ${dest} (plaintext, IP, paste/tunnel host or computed address)` }
        : { tier: 'warning', reason: `sends a secret variable in a request header to ${dest} — confirm the host is the service the secret belongs to` });
      break;
    }
  }

  // read on the whole script: a quoted `sh -c "…"` argument spans separators
  if (evaluatesDynamicText(script, opts.expansion)) {
    risks.push({ tier: 'warning', reason: 're-evaluates expanded text (eval/exec or an outer-quoted sh -c script) — hook input becomes code' });
  } else if (statements.some(stmt => XARGS_SHELL.test(stmt))) {
    risks.push({ tier: 'warning', reason: 'runs its input through xargs sh -c — every input line becomes shell code' });
  } else if (inlineCodeRunsInput(script)) {
    risks.push({ tier: 'warning', reason: 'runs inline interpreter code that executes a command built from its stdin — hook input becomes code' });
  } else if (fetchExec.length === 0 && statements.some(stmt => PIPE_TO_SHELL_PATTERN.test(stmt))) {
    risks.push({ tier: 'warning', reason: 'pipes data into a shell — hook input or command output runs as a script' });
  }
  return risks;
}

/** At most this many inline-code arguments are read per script (keeps the scan linear). */
const MAX_INLINE_CODE = 32;

/**
 * Whether an interpreter's inline code (`python3 -c "…"`, `node -e '…'`)
 * both reads stdin and runs a command it builds — the hook's JSON input
 * turned into a shell command. The quoted argument is read whole (16 KiB at
 * most), across the `;` inside it.
 */
function inlineCodeRunsInput(script: string): boolean {
  INLINE_CODE.lastIndex = 0;
  for (let n = 0; n < MAX_INLINE_CODE; n++) {
    const m = INLINE_CODE.exec(script);
    if (!m) return false;
    const at = m.index + m[0].length;
    const quote = script[at];
    let code: string;
    if (quote === '"') {
      code = quotedSpan(script, at);
    } else if (quote === "'") {
      const end = script.indexOf("'", at + 1);
      code = script.slice(at, end < 0 ? Math.min(script.length, at + 16_384) : Math.min(end + 1, at + 16_384));
    } else {
      code = /^\S{0,16384}/.exec(script.slice(at, at + 16_384))?.[0] ?? '';
    }
    if (CODE_EXEC_SINK.test(code) && CODE_STDIN.test(code)) return true;
  }
  return false;
}

/**
 * Risks of an HTTP hook (`type: "http"`): the agent POSTs the event's JSON —
 * prompts, tool input, file contents — to `url`. A named https host is the
 * documented audit-logging shape (info); a plaintext, IP, paste/tunnel host
 * or an unparseable URL is a warning.
 */
export function httpHookRisks(url: string): HookRisk[] {
  const { tier, dest } = destinationTier(url.trim());
  if (/^http:\/\/(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d+)?(?:\/|$)/i.test(url.trim())) {
    return [{ tier: 'info', reason: `posts hook input to a local endpoint (${dest})` }];
  }
  return [tier === 'warning'
    ? { tier, reason: `posts hook input (prompts, code, commands) to ${dest} — plaintext, IP, paste/tunnel host or computed address` }
    : { tier, reason: `posts hook input (prompts, code, commands) to ${dest} (audit-logging shape; confirm the endpoint is yours)` }];
}

/** One hook definition found in an agent's `hooks` object. */
export interface HookItem {
  event: string;
  matcher?: string;
  /** `command` / `bash` / `powershell` shell text (several when a hook sets more than one). */
  scripts: string[];
  /** `url` of an HTTP hook. */
  url?: string;
}

/**
 * The hooks of a `hooks` object in either documented shape: Claude-style
 * `{Event: [{matcher, hooks: [{type, command}]}]}` (Claude Code, Gemini CLI,
 * Devin) or flat `{event: [{type, command | bash | powershell | url}]}`
 * (Cursor, Copilot CLI). `prompt` / `agent` / `mcp_tool` hooks run nothing
 * here; Copilot's `exec` form spawns a program without a shell and is skipped
 * as well.
 */
export function hookItems(hooks: unknown): HookItem[] {
  const out: HookItem[] = [];
  if (!hooks || typeof hooks !== 'object' || Array.isArray(hooks)) return out;
  const add = (event: string, h: unknown, matcher?: string) => {
    if (!h || typeof h !== 'object') return;
    const rec = h as Record<string, unknown>;
    const type = typeof rec.type === 'string' ? rec.type : 'command';
    if (type === 'http') {
      if (typeof rec.url === 'string') out.push({ event, matcher, scripts: [], url: rec.url });
      return;
    }
    if (type !== 'command') return;
    // Exec form (`command` + `args`) spawns the program with no shell: only
    // a shell given `-c <script>` runs shell text
    if (Array.isArray(rec.args) && typeof rec.command === 'string') {
      const args = rec.args.filter((a): a is string => typeof a === 'string');
      const at = shellCommandWrapper(rec.command, args) ? args.findIndex(a => /^-[a-zA-Z]*c[a-zA-Z]*$/.test(a)) : -1;
      if (at >= 0 && typeof args[at + 1] === 'string') out.push({ event, matcher, scripts: [args[at + 1]] });
      return;
    }
    const scripts = [...new Set(['command', 'bash', 'powershell']
      .map(k => rec[k])
      .filter((v): v is string => typeof v === 'string' && v.trim() !== ''))];
    if (scripts.length > 0) out.push({ event, matcher, scripts });
  };
  for (const [event, entries] of Object.entries(hooks as Record<string, unknown>)) {
    for (const entry of Array.isArray(entries) ? entries : [entries]) {
      if (!entry || typeof entry !== 'object') continue;
      const e = entry as Record<string, unknown>;
      const matcher = typeof e.matcher === 'string' ? e.matcher : undefined;
      if (Array.isArray(e.hooks)) {
        for (const h of e.hooks) add(event, h, matcher);
      } else {
        add(event, e, matcher);
      }
    }
  }
  return out;
}

/** Risks of one hook item: its shell scripts and its HTTP target. */
export function hookItemRisks(item: HookItem, opts: { expansion?: RegExp } = {}): HookRisk[] {
  const risks = item.scripts.flatMap(s => hookCommandRisks(s, opts));
  if (item.url) risks.push(...httpHookRisks(item.url));
  return risks;
}

/** The highest tier among `risks`, or undefined when there are none. */
export function topTier(risks: readonly HookRisk[]): HookRiskTier | undefined {
  if (risks.some(r => r.tier === 'critical')) return 'critical';
  if (risks.some(r => r.tier === 'warning')) return 'warning';
  return risks.length > 0 ? 'info' : undefined;
}

/**
 * A hook finding's snippet: `<event>[(<matcher>)] hook: <body>`. Not
 * `<event>: <body>` — that reads as a `name: value` line, and an event named
 * like a credential (`SessionStart`) would have its whole command masked in
 * reports; the body is still masked where it holds a secret.
 */
export function hookSnippet(event: string, body: string, qualifier = ''): string {
  return `${event}${qualifier} hook: ${body}`;
}
