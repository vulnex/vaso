/**
 * Whether a skill file can write or download files — anywhere, by any means
 * (SKL-003's own-folder helper rule, dt25 D2 "strict"): a skill that runs a
 * script from its own folder runs a fixed command only while nothing in the
 * skill can replace that script. The decision deliberately doesn't follow
 * paths — a write the path tracking can't place (a child process's `-o`, a
 * shell script's redirect, a helper module, a computed name) still counts.
 *
 * Text based and over-inclusive on purpose: a match in a comment-free line
 * counts even when it writes somewhere harmless; it only ever turns an
 * own-folder run back into a finding.
 */

export type WriteLang = 'js' | 'python' | 'shell' | 'other';

export interface SkillWrite {
  /** 1-based line. */
  line: number;
  /** What writes, in a few words ("runs curl", "writeFileSync()", "shell redirect"). */
  what: string;
}

/** File APIs that write, copy, move, link or extract (JS, Python, Ruby, PowerShell…), matched anywhere in code. */
const WRITE_APIS: Array<[RegExp, (m: RegExpExecArray) => string]> = [
  // JS fs / fs-extra / Deno / Bun
  [/\b(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|copyFile|copyFileSync|cpSync|renameSync|symlinkSync|linkSync|truncateSync|ftruncateSync|writevSync|writeSync|outputFile(?:Sync)?|outputJson(?:Sync)?|writeJson(?:Sync)?|ensureSymlink(?:Sync)?|ensureLink(?:Sync)?|ensureFile(?:Sync)?|moveSync|copySync|writeTextFile(?:Sync)?|extractAllTo|extractEntryTo|writeZip)\b/, m => `${m[1]}()`],
  [/\bBun\.write\b/, () => 'Bun.write()'],
  [/\bDeno\.(?:create|open|rename|symlink|link|copyFile|truncate)\b/, m => `${m[0]}()`],
  // a member call that writes, copies, moves or links (fs.rename, fsp.cp, fse.copy, stream.write…)
  // (not `env.copy()`, `df.rename(columns=…)`: no path argument)
  [/(?<!\b(?:stdout|stderr|console|stdin)\s*)\.(rename|symlink|link|cp|copy|move|write|writev|truncate|ftruncate)\s*\((?!\s*\)|\s*(?:columns|index|mapper|axis|inplace|deep)\s*=|\s*\{)/, m => `.${m[1]}()`],
  // an fs method picked at runtime: fs['write' + 'File']
  [/\b(?:fs|fsp|fse|fsPromises|fsExtra|promises)\s*\[(?!\s*\d)/, () => 'fs method chosen at runtime'],
  // modules that download or extract into files
  [/(?:require\s*\(|import\s*\(|\bfrom)\s*['"](download|extract-zip|decompress|node-downloader-helper|nodejs-file-downloader|adm-zip|unzipper|tar|tar-fs|tar-stream|wget-improved|pycurl|wget)['"]/, m => `uses ${m[1]}`],
  [/\btar\.(?:x|extract|c|create)\s*\(/, () => 'tar extract'],
  [/^\s*(?:import|from)\s+(pycurl|wget|requests_download|gdown)\b/, m => `uses ${m[1]}`],
  // open(…, 'w'/'a'/'x'/'+') — Python open/io.open/gzip.open/tarfile.open, fs.open/openSync
  [/\bopen(?:Sync)?\s*\([^\n]{0,300}?,\s*(?:mode\s*=\s*)?[rRbBuU]?['"](?=[rbtU]*[wax+])[rwabtxU+]{1,4}['"]/, () => 'open() for writing'],
  [/\bmode\s*=\s*[rRbBuU]?['"](?=[rbtU]*[wax+])[rwabtxU+]{1,4}['"]/, () => 'open() for writing'],
  [/\bO_(?:WRONLY|RDWR|CREAT|APPEND|TRUNC)\b/, () => 'open() for writing'],
  [/\bZipFile\s*\([^)\n]{0,300}['"][wax]['"]/, () => 'ZipFile() for writing'],
  // Python: pathlib, os, shutil, urllib, archives, temp files, savers
  [/\.(write_text|write_bytes|symlink_to|hardlink_to|link_to|touch|extractall|extract)\s*\(/, m => `.${m[1]}()`],
  [/\bos\.(rename|renames|replace|symlink|link|write|truncate|ftruncate|sendfile|copy_file_range)\s*\(/, m => `os.${m[1]}()`],
  [/\b(copyfile|copyfileobj|copytree|copy2|unpack_archive|make_archive|urlretrieve|NamedTemporaryFile|mkstemp)\b/, m => `${m[1]}()`],
  [/\bshutil\.(copy|move)\b/, m => `shutil.${m[1]}()`],
  [/\bwget\.download\b/, () => 'wget.download()'],
  [/\b(?:torch|np|numpy|joblib)\.save\w*\s*\(|\.(?:savefig|save_pretrained|to_csv|to_parquet|to_excel|to_pickle|to_feather|to_hdf)\s*\(/, () => 'saves a file'],
  // Ruby / Perl / PowerShell / batch
  [/\b(?:File\.(?:write|open|rename|symlink|link|copy)|FileUtils\.\w+|IO\.copy_stream)\b/, m => `${m[0]}`],
  [/\b(Out-File|Set-Content|Add-Content|Copy-Item|Move-Item|New-Item|Rename-Item|Expand-Archive|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|DownloadFile|DownloadString|WriteAllText|WriteAllBytes)\b/i, m => m[1]],
];

/** Programs that download or write files, recognized as a token anywhere (no other common meaning). */
const DOWNLOADERS = /(?<![\w.$/~-])(?:[\w./~-]*\/)?(curl|wget|aria2c|axel|rsync|scp|sftp|tftp|bitsadmin|certutil|iwr|unzip|gunzip|bunzip2|unxz|uudecode|7za?|robocopy|xcopy|mklink)(?:\.exe)?(?![\w.-])/;

/** Programs that write files, recognized at a command position only (the words have other meanings). */
const WRITERS = /(?:^|[;&|({`]|\$\(|\b(?:sudo|exec|env|xargs|then|do|else|nohup|time|command|busybox)\s+)\s*(?:[\w./~-]*\/)?(fetch|ftp|tee|dd|cp|mv|ln|install|rename|truncate|tar|zip|gzip|xz|bzip2|base64|xxd|openssl|patch|git|copy|move|sed|perl|ditto|pax|cpio)(?=$|[\s;&|)'"`])([^;&|\n]*)/g;

/** For the WRITERS that only sometimes write: the arguments that make them write. */
const WRITES_WHEN: Record<string, RegExp> = {
  base64: /(?:^|\s)(?:-d|-D|--decode|-o|--output)\b/,
  xxd: /(?:^|\s)-r\b/,
  openssl: /(?:^|\s)-out\b/,
  git: /^\s*(?:-\S+\s+)*(?:clone|pull|fetch|checkout|reset|restore|apply|am|merge|rebase|switch|stash|submodule|cherry-pick|worktree)\b/,
  sed: /(?:^|\s)-[a-zA-Z]*i/,
  perl: /(?:^|\s)-[a-zA-Z]*i/,
};

/** A shell redirect into a file (`> f`, `>> f`, `1> f`, `&> f`), not to `&2` or `/dev/null`. */
const REDIRECT = /(?:^|[\s"')\]}\d&])>>?\|?(?![&>=(])\s*(?!\/dev\/(?:null|stdout|stderr|tty|fd\/)\b)["'$~./\w{]/;

/** String literals of JavaScript/Python code, with the line each starts on. */
function stringLiterals(code: string): Array<{ text: string; line: number }> {
  const out: Array<{ text: string; line: number }> = [];
  const re = /"""[\s\S]*?"""|'''[\s\S]*?'''|`(?:[^`\\]|\\[\s\S])*`|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'/g;
  let m: RegExpExecArray | null;
  let line = 1;
  let at = 0;
  while ((m = re.exec(code))) {
    for (; at < m.index; at++) if (code.charCodeAt(at) === 10) line++;
    const q = m[0].startsWith('"""') || m[0].startsWith("'''") ? 3 : 1;
    out.push({ text: m[0].slice(q, m[0].length - q), line });
  }
  return out;
}

/** A command line (shell script, Markdown code, a command string in code): what in it writes. */
function commandWrite(text: string, html: boolean): string | undefined {
  const d = DOWNLOADERS.exec(text);
  if (d) return `runs ${d[1]}`;
  for (const m of text.matchAll(WRITERS)) {
    const when = WRITES_WHEN[m[1]];
    if (!when || when.test(m[2] ?? '')) return `runs ${m[1]}`;
  }
  // `<b>x</b>` in a string is markup, not a redirect
  if (!(html && /<[a-zA-Z/!]/.test(text)) && !/\(\(/.test(text) && REDIRECT.test(text)) return 'shell redirect';
  // a command string whose redirect target is joined on: `'… > ' + dest`
  if (html && /\s\d?>>?\s*$/.test(text)) return 'shell redirect';
  return undefined;
}

const COMMENT_LINE: Record<WriteLang, RegExp> = {
  js: /^\s*(?:\/\/|\/?\*)/,
  python: /^\s*#/,
  shell: /^\s*(?:#|::|rem\s)/i,
  other: /^\s*(?:#|\/\/|--|;|rem\s)/i,
};

/**
 * The first place `text` (a skill file in `lang`) writes or downloads a
 * file, or undefined when nothing in it does. JavaScript/Python: write APIs
 * in the code, and downloader/writer commands and redirects in its string
 * literals (`execSync('curl -o …')`, `['wget', '-O', …]`). Shell, Markdown
 * code and anything else: every line read as commands, plus the write APIs.
 */
export function firstSkillWrite(text: string, lang: WriteLang): SkillWrite | undefined {
  const lines = text.split('\n');
  const found: SkillWrite[] = [];
  lines.forEach((l, i) => {
    if (COMMENT_LINE[lang].test(l)) return;
    for (const [re, what] of WRITE_APIS) {
      const m = re.exec(l);
      if (m) {
        found.push({ line: i + 1, what: what(m) });
        return;
      }
    }
    if (lang === 'shell' || lang === 'other') {
      const w = commandWrite(l, false);
      if (w) found.push({ line: i + 1, what: w });
    }
  });
  if (lang === 'js' || lang === 'python') {
    const comment = COMMENT_LINE[lang];
    const byLine = new Map<number, string[]>();
    for (const s of stringLiterals(text)) {
      if (comment.test(lines[s.line - 1] ?? '')) continue;
      const parts = s.text.split('\n');
      for (let j = 0; j < parts.length; j++) {
        const w = commandWrite(parts[j], true);
        if (w) {
          found.push({ line: s.line + j, what: w });
          break;
        }
      }
      if (parts.length === 1) byLine.set(s.line, [...byLine.get(s.line) ?? [], s.text]);
    }
    // an argv list on one line: `['git', 'clone', url]`, `['base64', '-d', …]`
    for (const [line, parts] of byLine) {
      if (parts.length < 2) continue;
      const w = commandWrite(parts.join(' '), true);
      if (w) found.push({ line, what: w });
    }
  }
  return found.sort((a, b) => a.line - b.line)[0];
}
