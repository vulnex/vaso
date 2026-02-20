import { readFile, readdir } from 'node:fs/promises';
import { join, extname } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getIOCDatabase } from '../../ioc/database.js';

const SCAN_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.json', '.yaml', '.yml', '.env', '.sh']);

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

export const ioc001: CheckModule = {
  id: 'IOC-001',
  name: 'C2 IP Detection',
  category: 'ioc',
  severity: 'critical',
  description: 'Scan code and configs for known C2 (command and control) IP addresses',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const dirs = [ctx.installation.installDir];
    if (ctx.installation.skillsDir) dirs.push(ctx.installation.skillsDir);

    // Check configs first
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

    // Check skill files
    const files = await getAllFiles(dirs);
    for (const file of files) {
      try {
        const content = await readFile(file, 'utf-8');
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

    return {
      id: 'IOC-001',
      name: 'C2 IP Detection',
      category: 'ioc',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No known C2 IP addresses found'
        : `Found ${evidence.length} reference(s) to known C2 IP addresses`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
