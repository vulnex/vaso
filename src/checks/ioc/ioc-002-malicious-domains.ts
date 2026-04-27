import { join, extname } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';

const SCAN_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.json', '.yaml', '.yml', '.env', '.sh', '.md']);

async function getAllFilesViaCtx(ctx: ScanContext, dirs: string[]): Promise<string[]> {
  const files: string[] = [];
  for (const dir of dirs) {
    try {
      const entries = await ctx.fs.readdirEntries(dir, { recursive: true });
      for (const entry of entries) {
        if (entry.isFile && SCAN_EXTENSIONS.has(extname(entry.name))) {
          const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(dir, entry.name);
          files.push(fullPath);
        }
      }
    } catch {}
  }
  return files;
}

export const ioc002 = defineCheck({
  id: 'IOC-002',
  name: 'Malicious Domains',
  category: 'ioc',
  severity: 'critical',
  description: 'Scan for known malicious domains in code and configs',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const dirs = [ctx.installation.installDir];
    if (ctx.installation.skillsDir) dirs.push(ctx.installation.skillsDir);

    const allContent: Array<{ file: string; content: string }> = [];

    for (const config of ctx.configs) {
      allContent.push({ file: config.filePath, content: config.raw });
    }

    const files = await getAllFilesViaCtx(ctx, dirs);
    for (const file of files) {
      try {
        allContent.push({ file, content: await ctx.fs.readFile(file) });
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

    return h.fromEvidence(evidence, {
      passed: 'No known malicious domains found',
      failed: (n) => `Found ${n} reference(s) to known malicious domains`,
    });
  },
});
