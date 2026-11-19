import { describe, it, expect } from 'vitest';
import { loadReferences, runReferences } from './skill-tree-files.js';

describe('runReferences', () => {
  it('a fence info string is the block\'s language, not a command', () => {
    for (const fence of ['```bash', '```sh', '~~~bash', '``` bash', '````zsh']) {
      const close = fence.startsWith('~') ? '~~~' : fence.replace(/[ a-z]+$/, '');
      for (const [cmd, lang] of [['node lib/x.dat', 'js'], ['python3 lib/y.txt', 'python'], ['bash lib/z.cfg', 'shell']] as const) {
        const md = `---\nname: g\n---\n${fence}\n${cmd}\n${close}\n`;
        expect(runReferences('/s/g/SKILL.md', md), `${fence} / ${cmd}`).toEqual([[`/s/g/${cmd.split(' ')[1]}`, lang]]);
      }
    }
  });

  it('keeps a command written on the fence line and inline runs', () => {
    expect(runReferences('/s/g/SKILL.md', 'Run `node ./lib/a.dat`.\n```bash node lib/b.dat```\n')).toEqual([
      ['/s/g/lib/a.dat', 'js'], ['/s/g/lib/b.dat', 'js'],
    ]);
  });
});

// Same cases as probe/skill_loads_test.go TestLoadReferencesFoldsBuiltPaths.
describe('loadReferences: paths built from the script\'s folder', () => {
  it('folds path.join/resolve(__dirname, …), new URL(…, import.meta.url)', () => {
    const js = "const path=require('path'); require(path.join(__dirname,'..','.cache','lib.js'));\n"
      + "import x from './a.js';\nconst u = new URL('../.cache/u.mjs', import.meta.url);\n"
      + "resolve(import.meta.dirname, '../node_modules/r');\npath.join(__dirname, '/etc', 'passwd');\n";
    expect(loadReferences('run.js', js)).toEqual(['./../.cache/lib.js', './a.js', './../.cache/u.mjs', './../node_modules/r']);
  });

  it('folds Python os.path.join(os.path.dirname(__file__), …) and sys.path folders', () => {
    const py = "import os, sys\nsys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.venv'))\n"
      + "from helper.sub import go\nexec(open(os.path.join(os.path.dirname(__file__), '..', '.cache', 'x.py')).read())\n";
    expect(loadReferences('run.py', py)).toEqual([
      './../.venv/os.py', './../.venv/os/__init__.py', './../.venv/sys.py', './../.venv/sys/__init__.py',
      './../.venv/helper.py', './../.venv/helper/__init__.py', './../.cache/x.py',
    ]);
  });

  it('refuses absolute, home, URL and over-long segment lists', () => {
    const js = "join(__dirname, '~/x');\nnew URL('https://h/x.js', import.meta.url);\n"
      + `path.join(__dirname, ${Array.from({ length: 17 }, () => "'a'").join(', ')});\n`;
    expect(loadReferences('run.js', js)).toEqual([]);
  });
});
