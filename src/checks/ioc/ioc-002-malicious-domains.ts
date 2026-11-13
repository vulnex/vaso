import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { iocSnippet } from './snippet.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { iocScanFiles, readScanFile } from './scan-files.js';
import { domainBoundaryRegex } from './boundary.js';

export const ioc002 = defineCheck({
  id: 'IOC-002',
  name: 'Malicious Domains',
  category: 'ioc',
  severity: 'critical',
  description: 'Scan for known malicious domains in code and configs',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();

    const domainRegexes = db.maliciousDomains.map(domain => ({
      domain,
      re: domainBoundaryRegex(domain),
    }));

    const scan = (file: string, content: string) => {
      for (const { domain, re } of domainRegexes) {
        if (!re.test(content)) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (re.test(lines[i])) {
            evidence.push({
              file,
              line: i + 1,
              // a minified or one-line file is one "line": show the match, not the file
              snippet: iocSnippet(lines[i], re),
              detail: `Known malicious domain: ${domain}`,
            });
          }
        }
      }
    };

    for (const config of ctx.configs) {
      scan(config.filePath, config.raw);
    }
    // One file at a time — never hold every file's content at once
    for (const file of await iocScanFiles(ctx)) {
      const content = await readScanFile(ctx, file);
      if (content !== undefined) scan(file, content);
    }

    return h.fromEvidence(evidence, {
      passed: 'No known malicious domains found',
      failed: (n) => `Found ${n} reference(s) to known malicious domains`,
    });
  },
});
