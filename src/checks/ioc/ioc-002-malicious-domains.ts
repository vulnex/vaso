import { readFile, readdir } from 'node:fs/promises';
import { join, extname } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getIOCDatabase } from '../../ioc/database.js';

const SCAN_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.json', '.yaml', '.yml', '.env', '.sh', '.md']);

async function getAllFiles(dirs: string[]): Promise<string[]> {
  const files: string[] = [];
  for (const dir of dirs) {
    try {
      const entries = await readdir(dir, { withFileTypes: true, recursive: true });
      for (const entry of entries) {
        if (entry.isFile() && SCAN_EXTENSIONS.has(extname(entry.name))) {
          const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(dir, entry.name);
          files.push(fullPath);
        }
      }
    } catch {}
  }
  return files;
}

export const ioc002: CheckModule = {
  id: 'IOC-002',
  name: 'Malicious Domains',
  category: 'ioc',
  severity: 'critical',
  description: 'Scan for known malicious domains in code and configs',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const dirs = [ctx.installation.installDir];
    if (ctx.installation.skillsDir) dirs.push(ctx.installation.skillsDir);

    const allContent: Array<{ file: string; content: string }> = [];

    for (const config of ctx.configs) {
      allContent.push({ file: config.filePath, content: config.raw });
    }

    const files = await getAllFiles(dirs);
    for (const file of files) {
      try {
        allContent.push({ file, content: await readFile(file, 'utf-8') });
      } catch {}
    }

    for (const { file, content } of allContent) {
      for (const domain of db.maliciousDomains) {
        if (content.includes(domain)) {
          const lines = content.split('\n');
          for (let i = 0; i < lines.length; i++) {
            if (lines[i].includes(domain)) {
              evidence.push({
                file,
                line: i + 1,
                snippet: lines[i].trim(),
                detail: `Known malicious domain: ${domain}`,
              });
            }
          }
        }
      }
    }

    return {
      id: 'IOC-002',
      name: 'Malicious Domains',
      category: 'ioc',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No known malicious domains found'
        : `Found ${evidence.length} reference(s) to known malicious domains`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
