import { SECURITY_PATTERNS, scanWithPatterns } from './pattern-engine.js';

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
 * passes one that skips its path placeholders).
 */
export function evaluatesDynamicText(cmd: string, expansion: RegExp = DYNAMIC_EXPANSION): boolean {
  for (const raw of cmd.split(/;|&&|\|\||\||\n/)) {
    // drop sudo / env / VAR=value prefixes to reach the command word
    const seg = raw.trim().replace(/^(?:(?:sudo|env|command|nohup)(?:\s+-\S+)*\s+|[A-Za-z_][A-Za-z0-9_]*=\S*\s+)+/, '');
    const word = /^(\S+)\s*(.*)$/s.exec(seg);
    if (!word) continue;
    const [, head, rest] = word;
    if ((head === 'eval' || head === 'exec') && expansion.test(rest)) return true;
    if (/^(?:\S*\/)?(?:ba|z|da|k|mk)?sh$/.test(head)) {
      const c = /(?:^|\s)-[a-zA-Z]*c[a-zA-Z]*\s+(.*)$/s.exec(rest);
      if (c && !c[1].startsWith("'") && expansion.test(c[1])) return true;
    }
  }
  return false;
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
const RAW_SOCKET_SEND = /\|\s*(?:nc|ncat|netcat|telnet)\s|\b(?:nc|ncat|netcat|telnet)\s[^|;&\n]{0,500}?<\s*\S/;
/** Material worth stealing in the same script: environment dumps, secret-named variables. */
const SECRET_MATERIAL = /\b(?:env|printenv|set)\s*(?:\||>)|\$\{?[A-Z0-9_]{0,64}(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)\b/;

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
    if (!CURL_SEND.test(stmt) && !WGET_SEND.test(stmt) && !RAW_SOCKET_SEND.test(stmt)) continue;
    const { tier, dest } = destinationTier(stmt);
    if (credentials) {
      risks.push({ tier: 'critical', reason: `sends credential files, secret variables or the environment over the network (${dest})` });
    } else if (tier === 'warning') {
      risks.push({ tier, reason: `sends data to ${dest} (plaintext, IP, paste/tunnel host or computed address) — hook input carries prompts, code and commands` });
    } else {
      risks.push({ tier, reason: `sends data to ${dest} — hook input carries prompts, code and commands (audit-logging shape; confirm the endpoint is yours)` });
    }
    break;
  }

  if (statements.some(stmt => evaluatesDynamicText(stmt, opts.expansion))) {
    risks.push({ tier: 'warning', reason: 're-evaluates expanded text (eval/exec or an outer-quoted sh -c script) — hook input becomes code' });
  } else if (fetchExec.length === 0 && statements.some(stmt => PIPE_TO_SHELL_PATTERN.test(stmt))) {
    risks.push({ tier: 'warning', reason: 'pipes data into a shell — hook input or command output runs as a script' });
  }
  return risks;
}

/** The highest tier among `risks`, or undefined when there are none. */
export function topTier(risks: readonly HookRisk[]): HookRiskTier | undefined {
  if (risks.some(r => r.tier === 'critical')) return 'critical';
  if (risks.some(r => r.tier === 'warning')) return 'warning';
  return risks.length > 0 ? 'info' : undefined;
}
