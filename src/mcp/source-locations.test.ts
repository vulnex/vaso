import { describe, it, expect } from 'vitest';
import { mapSourceEvidence } from './source-locations.js';
import type { CheckResult } from '../core/types.js';

const result = (file: string, line: number): CheckResult => ({
  id: 'MCP-004', name: 'x', category: 'mcp', severity: 'critical', passed: false, message: 'm',
  evidence: [{ file, line }],
});

describe('mapSourceEvidence', () => {
  it('maps a line of a joined multi-file source to its file and line', () => {
    const sourceCode = ['// === pkg/server.py ===', 'a', 'b', '// === pkg/tools.py ===', 'x', 'subprocess.run(cmd)'].join('\n');
    const results = [result('/srv/app/src/pkg/server.py', 6), result('/srv/app/src/pkg/server.py', 2)];
    mapSourceEvidence(results, [{ serverName: 'app', localPath: '/srv/app/src/pkg/server.py', sourceRoot: '/srv/app', sourceCode }]);
    expect(results[0].evidence![0]).toEqual({ file: '/srv/app/pkg/tools.py', line: 2 });
    expect(results[1].evidence![0]).toEqual({ file: '/srv/app/pkg/server.py', line: 1 });
  });

  it('names files of a resolved npm package after the package', () => {
    const sourceCode = ['// === dist/index.js ===', 'x', '// === dist/lib.js ===', 'eval(y)'].join('\n');
    const results = [result('srv-pkg', 4)];
    mapSourceEvidence(results, [{ serverName: 's', packageName: 'srv-pkg', sourceCode }]);
    expect(results[0].evidence![0]).toEqual({ file: 'srv-pkg/dist/lib.js', line: 1 });
  });

  it('leaves single-file sources alone', () => {
    const results = [result('/srv/one.js', 3)];
    mapSourceEvidence(results, [{ serverName: 's', localPath: '/srv/one.js', sourceCode: 'a\nb\nc' }]);
    expect(results[0].evidence![0]).toEqual({ file: '/srv/one.js', line: 3 });
  });
});
