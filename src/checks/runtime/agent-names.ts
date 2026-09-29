import type { AgentType } from '../../core/types.js';

/**
 * Process names (substring of `ps -o comm`, which Linux truncates to 15
 * chars) that belong to each agent. Only the scanned installation's own
 * processes are examined — one process must not be reported under every
 * framework installed on the host.
 */
export const AGENT_PROCESS_NAMES: Partial<Record<AgentType, string[]>> = {
  openclaw: ['openclaw'],
  nanoclaw: ['nanoclaw'],
  picoclaw: ['picoclaw'],
  ironclaw: ['ironclaw'],
  nanobot: ['nanobot'],
  zeroclaw: ['zeroclaw'],
  nemoclaw: ['nemoclaw', 'openshell'],
  hermes: ['hermes'],
  lyrie: ['lyrie'],
  'atomic-agent': ['atomic-agent', 'atag'],
};

/** Framework agents whose names appear in a service/unit file name. */
export function agentsNamedIn(name: string): AgentType[] {
  const lower = name.toLowerCase();
  return (Object.entries(AGENT_PROCESS_NAMES) as [AgentType, string[]][])
    .filter(([, names]) => names.some(n => lower.includes(n)))
    .map(([agent]) => agent);
}
