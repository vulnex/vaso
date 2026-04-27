import { join, extname } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';

const SCAN_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.json', '.yaml', '.yml', '.env', '.sh']);

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

export const ioc001 = defineCheck({
  id: 'IOC-001',
  name: 'C2 IP Detection',
  category: 'ioc',
  severity: 'critical',
  description: 'Scan code and configs for known C2 (command and control) IP addresses',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const dirs = [ctx.installation.installDir];
    if (ctx.installation.skillsDir) dirs.push(ctx.installation.skillsDir);

    for (const config of ctx.configs) {
      for (const ip of db.c2Ips) {
        if (config.raw.includes(ip)) {
          const lines = config.raw.split('\n');
          for (let i = 0; i < lines.length; i++) {
            if (lines[i].includes(ip)) {
              evidence.push({
                file: config.filePath,
                line: i + 1,
                snippet: lines[i].trim(),
                detail: `Known C2 IP: ${ip}`,
              });
            }
          }
        }
      }
    }

    const files = await getAllFilesViaCtx(ctx, dirs);
    for (const file of files) {
      try {
        const content = await ctx.fs.readFile(file);
        for (const ip of db.c2Ips) {
          if (content.includes(ip)) {
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
              if (lines[i].includes(ip)) {
                evidence.push({
                  file,
                  line: i + 1,
                  snippet: lines[i].trim(),
                  detail: `Known C2 IP: ${ip}`,
                });
              }
            }
          }
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: 'No known C2 IP addresses found',
      failed: (n) => `Found ${n} reference(s) to known C2 IP addresses`,
    });
  },
});
