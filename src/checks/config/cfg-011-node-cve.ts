import { defineCheck } from '../../core/check-builder.js';

const VULNERABLE_RANGES = [
  { major: 18, minorMax: 20 },
  { major: 20, minorMax: 18 },
  { major: 22, minorMax: 12 },
];

export const cfg011 = defineCheck({
  id: 'CFG-011',
  name: 'Node.js CVE-2026-21636',
  category: 'config',
  severity: 'warning',
  description: 'Check if the Node.js version is vulnerable to CVE-2026-21636',

  async run(ctx, h) {
    // process.version is the Node running VASO — on a remote or snapshot
    // scan that is the scanning machine, not the scanned host.
    if (ctx.fs.kind === 'snapshot') {
      return h.passed('Not checked on remote/snapshot scans — the scanned host\'s Node.js version is not collected');
    }
    let nodeVersion: string;
    try {
      nodeVersion = process.version; // v20.11.0
    } catch {
      return h.passed('Could not determine Node.js version');
    }

    const match = nodeVersion.match(/^v(\d+)\.(\d+)\.\d+/);
    if (!match) {
      return h.passed(`Could not parse Node.js version: ${nodeVersion}`);
    }

    const major = parseInt(match[1], 10);
    const minor = parseInt(match[2], 10);

    const vulnerable = VULNERABLE_RANGES.some(
      range => major === range.major && minor <= range.minorMax
    );

    return h.result({
      passed: !vulnerable,
      message: vulnerable
        ? `Node.js ${nodeVersion} is vulnerable to CVE-2026-21636 — update recommended`
        : `Node.js ${nodeVersion} is not affected by CVE-2026-21636`,
    });
  },
});
