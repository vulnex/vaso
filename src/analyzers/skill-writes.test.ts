import { describe, it, expect } from 'vitest';
import { firstSkillWrite } from './skill-writes.js';

const what = (text: string, lang: Parameters<typeof firstSkillWrite>[1]) => firstSkillWrite(text, lang)?.what;

describe('firstSkillWrite (SKL-003 D2 strict)', () => {
  it('JS: fs writers, member writers, computed fs methods, downloader modules', () => {
    expect(what("fs.writeFileSync(p, d);", 'js')).toBe('writeFileSync()');
    expect(what("await fsp.rename(a, b);", 'js')).toBe('.rename()');
    expect(what("res.body.pipe(fs.createWriteStream(p));", 'js')).toBe('createWriteStream()');
    expect(what("fs[m](a, b);", 'js')).toBe('fs method chosen at runtime');
    expect(what("const dl = require('download');", 'js')).toBe('uses download');
    expect(what("await Bun.write(p, t);", 'js')).toBe('Bun.write()');
    expect(what("fs.openSync(p, 'w');", 'js')).toBe('open() for writing');
  });

  it('JS/Python: downloader and writer commands in strings, argv lists and redirects', () => {
    expect(what("execFileSync('curl', ['-so', p, u]);", 'js')).toBe('runs curl');
    expect(what("execSync('wget -qO- ' + u + ' > ' + p);", 'js')).toBe('runs wget');
    expect(what("execSync(`cat a.txt > ${p}`);", 'js')).toBe('shell redirect');
    expect(what("spawnSync('cp', [a, b]);", 'js')).toBe('runs cp');
    expect(what("subprocess.run(['git', 'clone', url])", 'python')).toBe('runs git');
    expect(what("subprocess.run(['base64', '-d', '-o', p])", 'python')).toBe('runs base64');
    expect(what("os.system('tar xzf x.tgz')", 'python')).toBe('runs tar');
    expect(what("subprocess.run('echo hi >> log.txt', shell=True)", 'python')).toBe('shell redirect');
    expect(what("execSync('echo ' + data + ' > ' + dest); ", 'js')).toBe('shell redirect');
  });

  it('Python: open for writing, pathlib, os, shutil, urllib, archives', () => {
    expect(what("with open(os.path.join(a, b), 'wb') as f:", 'python')).toBe('open() for writing');
    expect(what("Path(p).write_text(s)", 'python')).toBe('.write_text()');
    expect(what("os.replace(a, b)", 'python')).toBe('os.replace()');
    expect(what("shutil.move(a, b)", 'python')).toBe('.move()');
    expect(what("urllib.request.urlretrieve(u, p)", 'python')).toBe('urlretrieve()');
    expect(what("tarfile.open(p).extractall(d)", 'python')).toBe('.extractall()');
  });

  it('shell: downloaders, writers at command position, redirects, sed -i', () => {
    expect(what('wget -qO "$(dirname "$0")/helper.sh" "$U"', 'shell')).toBe('runs wget');
    expect(what('echo x | tee out.txt', 'shell')).toBe('runs tee');
    expect(what('printf "%s" "$1" > "$d/helper.sh"', 'shell')).toBe('shell redirect');
    expect(what('exec 3>state.txt', 'shell')).toBe('shell redirect');
    expect(what("sed -i '' s/a/b/ f", 'shell')).toBe('runs sed');
    expect(what('Invoke-WebRequest -Uri $u -OutFile helper.ps1', 'shell')).toBe('Invoke-WebRequest');
  });

  it('reads, prints and look-alikes are not writes', () => {
    const js = [
      "const cp = require('child_process'), path = require('path');",
      "const s = require('fs').readFileSync(path.join(__dirname, 'a.txt'), 'utf8');",
      "process.stdout.write(s); console.log(x => x >= 1, a->b);",
      "const html = '<b>bold</b> <a href=\"x\">link</a>';",
      "cp.execFileSync('bash', [path.join(__dirname, 'h.sh')], { stdio: 'inherit' });",
      "const buf = Buffer.alloc(4); const t = s.replace('a', 'b');",
      "// curl -o helper.sh https://example.net/x  (a comment)",
      "execSync('git status --porcelain 2>&1');",
      '',
    ].join('\n');
    expect(firstSkillWrite(js, 'js')).toBeUndefined();
    const py = [
      'import os, subprocess, sys',
      'env = os.environ.copy()',
      "with open(path, 'rb') as f: data = f.read()",
      'df = df.rename(columns={"a": "b"})',
      'sys.stdout.write(data.decode())',
      "subprocess.run(['bash', os.path.join(here, 'h.sh')], env=env)",
      '# curl -o h.sh https://example.net/x',
      '',
    ].join('\n');
    expect(firstSkillWrite(py, 'python')).toBeUndefined();
    const sh = ['#!/bin/sh', 'set -e', 'echo "$1" 2>&1 >/dev/null', 'git status', 'ls -la "$(dirname "$0")"', 'if [ "$a" -gt 1 ]; then echo hi; fi', ''].join('\n');
    expect(firstSkillWrite(sh, 'shell')).toBeUndefined();
  });

  it('stays linear on a long pathological line', () => {
    const line = 'a/'.repeat(200_000) + ' open(' + 'x,'.repeat(100_000);
    const t = Date.now();
    firstSkillWrite(line, 'shell');
    firstSkillWrite(`'${line}'`, 'js');
    expect(Date.now() - t).toBeLessThan(3000);
  });
});
