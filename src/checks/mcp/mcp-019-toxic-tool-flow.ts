import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { extractToolDefinitions } from '../../mcp/tool-baseline.js';

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

/**
 * Extract tool handler bodies from source code by finding tool registrations
 * and capturing the surrounding function body.
 */
function extractToolHandlers(sourceCode: string): Map<string, string> {
  const handlers = new Map<string, string>();
  const tools = extractToolDefinitions(sourceCode);

  if (tools.length === 0) {
    // No explicit tool registrations found — treat entire source as a single implicit handler
    return handlers;
  }

  for (const tool of tools) {
    // Find the tool registration and extract a generous window of surrounding code as the handler
    const escapedName = tool.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const toolRegex = new RegExp(`['"]${escapedName}['"]`, 'g');
    const match = toolRegex.exec(sourceCode);
    if (match) {
      // Grab a window of code after the tool name (up to 2000 chars or next tool registration)
      const start = match.index;
      const end = Math.min(start + 2000, sourceCode.length);
      handlers.set(tool.name, sourceCode.slice(start, end));
    }
  }

  return handlers;
}

export const mcp019: CheckModule = {
  id: 'MCP-019',
  name: 'Toxic Tool Flow',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect dangerous source→sink tool combinations that enable data exfiltration via chained tool calls',
  supportedAgents: ['mcp'],

  async run(ctx: ScanContext): Promise<CheckResult> {
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

    return {
      id: 'MCP-019',
      name: 'Toxic Tool Flow',
      category: 'mcp',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No toxic source→sink tool combinations found in MCP servers'
        : `Found ${evidence.length} MCP server(s) with toxic tool flow (source + sink tools coexist)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
