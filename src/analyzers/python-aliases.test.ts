import { describe, it, expect } from 'vitest';
import { analyzePythonSinks } from './python-sinks.js';

const HEAD = 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n';
const injections = (code: string) => analyzePythonSinks(HEAD + code).filter((f) => f.kind === 'injection');

describe('Python sinks reached through assigned aliases', () => {
  it('a sink function bound to a name', () => {
    expect(injections('import subprocess\nrunner = subprocess.run\n@mcp.tool()\ndef f(host: str):\n    return runner("nslookup " + host, shell=True)\n')).not.toHaveLength(0);
  });

  it('getattr with an assembled name, module and builtins', () => {
    expect(injections('import subprocess\nrunner = getattr(subprocess, "r" + "un")\n@mcp.tool()\ndef f(host: str):\n    return runner("ping " + host, shell=True)\n')).not.toHaveLength(0);
    expect(injections('import builtins\n_ev = getattr(builtins, "ev" + "al")\n@mcp.tool()\ndef f(expr: str):\n    return str(_ev(expr))\n')).not.toHaveLength(0);
  });

  it('a module loaded with importlib, shell switched on through **kwargs', () => {
    const code = 'import importlib\nsp = importlib.import_module("subprocess")\nOPTS = {"shell": True, "text": True}\n@mcp.tool()\ndef f(path: str):\n    return sp.check_output("pandoc " + path, **OPTS)\n';
    expect(injections(code)).not.toHaveLength(0);
  });

  it('does not rewrite names bound to non-sink attributes', () => {
    const code = 'import platform\nsystem = platform.system\n@mcp.tool()\ndef f(x: str):\n    return system()\n';
    expect(analyzePythonSinks(HEAD + code)).toEqual([]);
  });
});

describe('Python pathlib joins of caller input', () => {
  it('flags Path / name read or written', () => {
    expect(injections('from pathlib import Path\nROOT = Path("/srv/uploads")\n@mcp.tool()\ndef save(filename: str, content: str):\n    (ROOT / filename).write_text(content)\n')).not.toHaveLength(0);
    expect(injections('from pathlib import Path\n@mcp.tool()\ndef read(name: str):\n    return Path("/srv/docs", name).read_text()\n')).not.toHaveLength(0);
  });

  it('passes a confined join and plain division', () => {
    const confined = 'from pathlib import Path\nROOT = Path("/srv").resolve()\n@mcp.tool()\ndef read(name: str):\n    p = (ROOT / name).resolve()\n    if not p.is_relative_to(ROOT):\n        raise ValueError()\n    return p.read_text()\n';
    expect(injections(confined)).toEqual([]);
    const division = 'from pathlib import Path\n@mcp.tool()\ndef ratio(file_count, total):\n    Path("/tmp/x").write_text(str(total / file_count))\n';
    expect(injections(division)).toEqual([]);
  });
});
