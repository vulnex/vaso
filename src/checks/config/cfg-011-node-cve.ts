import { execSync } from 'node:child_process';
import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';

const VULNERABLE_RANGES = [
  { major: 18, minorMax: 20 },
  { major: 20, minorMax: 18 },
  { major: 22, minorMax: 12 },
];

export const cfg011: CheckModule = {
  id: 'CFG-011',
  name: 'Node.js CVE-2026-21636',
  category: 'config',
  severity: 'warning',
  description: 'Check if the Node.js version is vulnerable to CVE-2026-21636',

  async run(_ctx: ScanContext): Promise<CheckResult> {
    let nodeVersion: string;
    try {
      nodeVersion = process.version; // v20.11.0
    } catch {
      return {
        id: 'CFG-011',
        name: 'Node.js CVE-2026-21636',
        category: 'config',
        severity: 'warning',
        passed: true,
        message: 'Could not determine Node.js version',
      };
    }

    const match = nodeVersion.match(/^v(\d+)\.(\d+)\.\d+/);
    if (!match) {
      return {
        id: 'CFG-011',
        name: 'Node.js CVE-2026-21636',
        category: 'config',
        severity: 'warning',
        passed: true,
        message: `Could not parse Node.js version: ${nodeVersion}`,
      };
    }

    const major = parseInt(match[1], 10);
    const minor = parseInt(match[2], 10);

    const vulnerable = VULNERABLE_RANGES.some(
      range => major === range.major && minor <= range.minorMax
    );

    return {
      id: 'CFG-011',
      name: 'Node.js CVE-2026-21636',
      category: 'config',
      severity: 'warning',
      passed: !vulnerable,
      message: vulnerable
        ? `Node.js ${nodeVersion} is vulnerable to CVE-2026-21636 — update recommended`
        : `Node.js ${nodeVersion} is not affected by CVE-2026-21636`,
    };
  },
};
