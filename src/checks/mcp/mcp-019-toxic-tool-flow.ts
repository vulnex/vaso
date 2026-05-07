import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const SOURCE_PATTERNS = [
  /readFile(?:Sync)?/,
  /readdir(?:Sync)?/,
  /createReadStream/,
  /execSync|exec\s*\(/,
  /spawn\s*\(/,
  /\bquery\s*\(/,
  /\bSELECT\b/i,
  /db\.(get|all|run)\s*\(/,
  /process\.env/,
  /homedir\(\)/,
  /os\.userInfo/,
  /\/etc\/passwd/,
  /\.ssh\//,
  /\.env\b/,
  /credentials/i,
];

const SINK_PATTERNS = [
  /\bfetch\s*\(/,
  /axios\s*[.(]/,
  /https?\.request\s*\(/,
  /sendMail/i,
  /createTransport/,
  /nodemailer/i,
  /WebSocket\.send|ws\.send/,
  /postMessage\s*\(/,
  /webhook/i,
  /slack/i,
  /discord/i,
  /telegram/i,
  /uploadFile/i,
  /putObject/i,
  /blob\.upload/i,
];

interface ToolClassification {
  name: string;
  isSource: boolean;
  isSink: boolean;
  sourceCapabilities: string[];
  sinkCapabilities: string[];
}

function classifyToolHandler(handlerCode: string): { isSource: boolean; isSink: boolean; sourceCapabilities: string[]; sinkCapabilities: string[] } {
  const sourceCapabilities: string[] = [];
  const sinkCapabilities: string[] = [];

  for (const pattern of SOURCE_PATTERNS) {
    const match = pattern.exec(handlerCode);
    if (match) {
      sourceCapabilities.push(match[0]);
    }
  }

  for (const pattern of SINK_PATTERNS) {
    const match = pattern.exec(handlerCode);
    if (match) {
      sinkCapabilities.push(match[0]);
    }
  }

  return {
    isSource: sourceCapabilities.length > 0,
    isSink: sinkCapabilities.length > 0,
    sourceCapabilities,
    sinkCapabilities,
  };
}

const TOOL_REGISTRATION_PATTERNS: RegExp[] = [
  /\.tool\(\s*['"]([^'"]+)['"]/g,
  /addTool\(\s*\{[^}]*name:\s*['"]([^'"]+)['"]/g,
  /register[_]?[Tt]ool\(\s*['"]([^'"]+)['"]/g,
  /\{\s*name:\s*['"]([^'"]+)['"](?:\s*,\s*description:\s*['"][^'"]*?['"])?[^}]*handler\s*:/g,
];

const MAX_HANDLER_WINDOW = 2000;

interface ToolSite {
  name: string;
  start: number;
}

function findToolRegistrationSites(sourceCode: string): ToolSite[] {
  const sites: ToolSite[] = [];
  const seen = new Set<string>();
  for (const pattern of TOOL_REGISTRATION_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(sourceCode)) !== null) {
      const name = match[1];
      if (seen.has(name)) continue;
      seen.add(name);
      sites.push({ name, start: match.index });
    }
  }
  sites.sort((a, b) => a.start - b.start);
  return sites;
}

/**
 * Slice each tool's handler from its registration site to the start of the next
 * registration site, capped at MAX_HANDLER_WINDOW. Bounding by the next site
 * prevents adjacent tools' source/sink capabilities from smearing.
 */
function extractToolHandlers(sourceCode: string): Map<string, string> {
  const handlers = new Map<string, string>();
  const sites = findToolRegistrationSites(sourceCode);
  if (sites.length === 0) return handlers;

  for (let i = 0; i < sites.length; i++) {
    const { name, start } = sites[i];
    const nextStart = i + 1 < sites.length ? sites[i + 1].start : sourceCode.length;
    const end = Math.min(nextStart, start + MAX_HANDLER_WINDOW, sourceCode.length);
    handlers.set(name, sourceCode.slice(start, end));
  }

  return handlers;
}

export const mcp019 = defineCheck({
  id: 'MCP-019',
  name: 'Toxic Tool Flow',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect dangerous source→sink tool combinations that enable data exfiltration via chained tool calls',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const sources = ctx.mcpServerSources ?? [];

    for (const source of sources) {
      if (!source.sourceCode) continue;

      const handlers = extractToolHandlers(source.sourceCode);
      const classifications: ToolClassification[] = [];

      if (handlers.size > 0) {
        // Classify each tool by its handler body
        for (const [name, body] of handlers) {
          const result = classifyToolHandler(body);
          classifications.push({ name, ...result });
        }
      } else {
        // No tool registrations found — analyze the whole source as one unit
        // This won't produce per-tool classifications, so skip toxic flow analysis
        continue;
      }

      const sourceTools = classifications.filter(c => c.isSource);
      const sinkTools = classifications.filter(c => c.isSink);

      if (sourceTools.length > 0 && sinkTools.length > 0) {
        const sourceNames = sourceTools.map(t => `${t.name} (${t.sourceCapabilities.join(', ')})`);
        const sinkNames = sinkTools.map(t => `${t.name} (${t.sinkCapabilities.join(', ')})`);

        evidence.push({
          file: source.localPath ?? source.serverName,
          detail: `Toxic flow: server "${source.serverName}" has source tools [${sourceNames.join('; ')}] and sink tools [${sinkNames.join('; ')}]. An agent could be prompt-injected to chain these for data exfiltration.`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No toxic source→sink tool combinations found in MCP servers',
      failed: (n) => `Found ${n} MCP server(s) with toxic tool flow (source + sink tools coexist)`,
    });
  },
});
