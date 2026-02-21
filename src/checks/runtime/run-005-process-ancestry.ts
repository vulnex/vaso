import { execSync } from 'node:child_process';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const AGENT_KEYWORDS = ['openclaw', 'nanoclaw', 'picoclaw', 'ironclaw', 'nanobot', 'zeroclaw'];

const SUSPICIOUS_PARENTS = new Set([
  'curl', 'wget', 'nc', 'ncat', 'netcat',
  'python', 'python3', 'ruby', 'perl',
]);

const SUSPICIOUS_PARENT_PATTERNS = [
  /\bbash\s+-c\b/,
  /\bsh\s+-c\b/,
  /\bpython[23]?\s+-c\b/,
];

interface ProcessInfo {
  ppid: number;
  comm: string;
}

export const run005: CheckModule = {
  id: 'RUN-005',
  name: 'Process Ancestry Analysis',
  category: 'runtime',
  severity: 'warning',
  description: 'Check agent process ancestry for suspicious parent processes',
  supportedPlatforms: ['darwin', 'linux'],

  async run(_ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    let output = '';
    try {
      output = execSync('ps -eo pid,ppid,comm 2>/dev/null', { encoding: 'utf-8', timeout: 5000 });
    } catch {
      return {
        id: 'RUN-005',
        name: 'Process Ancestry Analysis',
        category: 'runtime',
        severity: 'warning',
        passed: true,
        message: 'Could not retrieve process list',
      };
    }

    const processMap = new Map<number, ProcessInfo>();
    const agentPids: number[] = [];
    const lines = output.split('\n');

    for (const line of lines.slice(1)) { // Skip header
      const trimmed = line.trim();
      if (!trimmed) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length < 3) continue;

      const pid = parseInt(parts[0], 10);
      const ppid = parseInt(parts[1], 10);
      const comm = parts.slice(2).join(' ');

      if (isNaN(pid) || isNaN(ppid)) continue;

      processMap.set(pid, { ppid, comm });

      const commLower = comm.toLowerCase();
      for (const keyword of AGENT_KEYWORDS) {
        if (commLower.includes(keyword)) {
          agentPids.push(pid);
          break;
        }
      }
    }

    // Walk PPID chain for each agent process
    for (const agentPid of agentPids) {
      let currentPid = agentPid;
      const agentComm = processMap.get(agentPid)?.comm ?? 'unknown';

      for (let depth = 0; depth < 5; depth++) {
        const proc = processMap.get(currentPid);
        if (!proc || proc.ppid === 0 || proc.ppid === currentPid) break;

        const parent = processMap.get(proc.ppid);
        if (!parent) break;

        const parentBaseName = parent.comm.split('/').pop()?.toLowerCase() ?? '';

        if (SUSPICIOUS_PARENTS.has(parentBaseName)) {
          evidence.push({
            file: 'ps',
            detail: `Agent process "${agentComm}" (PID ${agentPid}) has suspicious parent "${parent.comm}" (PID ${proc.ppid})`,
          });
          break;
        }

        for (const pattern of SUSPICIOUS_PARENT_PATTERNS) {
          if (pattern.test(parent.comm)) {
            evidence.push({
              file: 'ps',
              detail: `Agent process "${agentComm}" (PID ${agentPid}) has suspicious parent "${parent.comm}" (PID ${proc.ppid})`,
            });
            break;
          }
        }

        if (evidence.length > 0) break;
        currentPid = proc.ppid;
      }
    }

    return {
      id: 'RUN-005',
      name: 'Process Ancestry Analysis',
      category: 'runtime',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No suspicious process ancestry detected for agent processes'
        : `Found ${evidence.length} agent process(es) with suspicious parent processes`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
