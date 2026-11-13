import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { iocSnippet } from './snippet.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { iocScanFiles, readScanFile } from './scan-files.js';
import { ipBoundaryRegex } from './boundary.js';

export const ioc001 = defineCheck({
  id: 'IOC-001',
  name: 'C2 IP Detection',
  category: 'ioc',
  severity: 'critical',
  description: 'Scan code and configs for known C2 (command and control) IP addresses',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();

    const ipRegexes = db.c2Ips.map(ip => ({ ip, re: ipBoundaryRegex(ip) }));

    const scan = (file: string, content: string) => {
      for (const { ip, re } of ipRegexes) {
        if (!re.test(content)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (re.test(lines[i])) {
            evidence.push({
              file,
              line: i + 1,
              // a minified or one-line file is one "line": show the match, not the file
              snippet: iocSnippet(lines[i], re),
              detail: `Known C2 IP: ${ip}`,
            });
          }
        }
      }
    };

    for (const config of ctx.configs) {
      scan(config.filePath, config.raw);
    }

    for (const file of await iocScanFiles(ctx)) {
      const content = await readScanFile(ctx, file);
      if (content !== undefined) scan(file, content);
    }

    return h.fromEvidence(evidence, {
      passed: 'No known C2 IP addresses found',
      failed: (n) => `Found ${n} reference(s) to known C2 IP addresses`,
    });
  },
});
