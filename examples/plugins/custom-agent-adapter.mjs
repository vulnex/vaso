/**
 * VASO Example Plugin: Custom Agent Adapter (Advanced)
 *
 * Demonstrates all three plugin APIs in a single file:
 *   - api.registerAdapter()  — custom agent framework support
 *   - api.registerCheck()    — agent-scoped security check
 *   - api.registerReporter() — single-line CI/CD reporter
 *
 * This plugin adds support for a fictional "ToolForge" agent framework.
 * Use it as a template when adding your own agent framework to VASO.
 *
 * Install: cp custom-agent-adapter.mjs ~/.vaso/plugins/
 * Verify:  vaso ext list
 */

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

// ---------------------------------------------------------------------------
// Section 1: Agent Adapter
//
// An AgentAdapter tells VASO how to discover an agent framework's
// installation, locate its config files, and find its tools/skills directory.
// ---------------------------------------------------------------------------

const TOOLFORGE_DIR = join(homedir(), '.toolforge');

const toolforgeAdapter = {
  // The agent identifier — must be unique across all adapters.
  // For user plugins, use a descriptive lowercase string.
  agent: 'toolforge',

  // Human-readable name shown in scan output.
  displayName: 'ToolForge',

  /**
   * Detect installed ToolForge instances.
   * Returns an array of AgentInstallation objects (one per instance found).
   */
  async detect(_options) {
    // Check if the ToolForge directory exists
    if (!existsSync(TOOLFORGE_DIR)) {
      return []; // Not installed — return empty array
    }

    // Read config files
    const configFiles = [];
    const configPath = join(TOOLFORGE_DIR, 'config.json');
    if (existsSync(configPath)) {
      try {
        const raw = readFileSync(configPath, 'utf-8');
        const data = JSON.parse(raw);
        configFiles.push({
          raw,
          format: 'json',
          filePath: configPath,
          data,
        });
      } catch {
        // Config exists but is malformed — still report the installation
        configFiles.push({
          raw: '',
          format: 'json',
          filePath: configPath,
          data: {},
        });
      }
    }

    // Check for optional YAML config
    const yamlPath = join(TOOLFORGE_DIR, 'toolforge.yml');
    if (existsSync(yamlPath)) {
      try {
        const raw = readFileSync(yamlPath, 'utf-8');
        // In a real adapter, you'd parse YAML here.
        // For this example, we store it as raw text only.
        configFiles.push({
          raw,
          format: 'yaml',
          filePath: yamlPath,
          data: {},
        });
      } catch {
        // Skip unreadable files
      }
    }

    return [{
      agent: 'toolforge',
      agentName: 'ToolForge',
      installDir: TOOLFORGE_DIR,
      configFiles,
      skillsDir: this.getSkillsDir(TOOLFORGE_DIR),
      gateway: configFiles[0] ? this.getGatewayInfo(configFiles[0].data) : undefined,
    }];
  },

  /**
   * Return default config file paths for this agent.
   */
  getConfigPaths() {
    return [
      join(TOOLFORGE_DIR, 'config.json'),
      join(TOOLFORGE_DIR, 'toolforge.yml'),
    ];
  },

  /**
   * Return the tools/skills directory for a given installation.
   */
  getSkillsDir(installDir) {
    const toolsDir = join(installDir, 'tools');
    return existsSync(toolsDir) ? toolsDir : undefined;
  },

  /**
   * Extract gateway/server info from parsed config.
   */
  getGatewayInfo(config) {
    const server = config?.server;
    if (!server) return undefined;
    return {
      host: server.host || '127.0.0.1',
      port: server.port || 9090,
      tls: server.tls === true,
      authMode: server.auth || 'none',
    };
  },

  /**
   * Optional: return paths to credential files for this agent.
   */
  getCredentialPaths(installDir) {
    const creds = join(installDir, 'credentials.json');
    return existsSync(creds) ? [creds] : [];
  },

  /**
   * Optional: return the CLI command for this agent.
   */
  getCLICommand() {
    return 'toolforge';
  },
};

// ---------------------------------------------------------------------------
// Section 2: Agent-Scoped Check
//
// This check only runs when scanning ToolForge installations.
// The `supportedAgents` field restricts which agents it applies to.
// ---------------------------------------------------------------------------

const toolforgeSandboxCheck = {
  id: 'USR-020',
  name: 'ToolForge Sandbox Configuration',
  category: 'config',
  severity: 'warning',
  description: 'Verify that ToolForge sandbox mode is properly configured',

  // This check only applies to ToolForge agents
  supportedAgents: ['toolforge'],

  async run(context) {
    const evidence = [];

    for (const config of context.configs) {
      const sandbox = config.data?.sandbox;

      // Check if sandbox is explicitly disabled
      if (sandbox === false || sandbox?.enabled === false) {
        evidence.push({
          file: config.filePath,
          detail: 'Sandbox mode is explicitly disabled',
        });
        continue;
      }

      // Check if sandbox is missing entirely
      if (sandbox === undefined) {
        evidence.push({
          file: config.filePath,
          detail: 'No sandbox configuration found (defaults may be insecure)',
        });
        continue;
      }

      // Check for overly permissive sandbox settings
      if (sandbox?.allowNetwork === true && sandbox?.allowFileSystem === true) {
        evidence.push({
          file: config.filePath,
          detail: 'Sandbox allows both network and filesystem access — overly permissive',
        });
      }
    }

    const passed = evidence.length === 0;

    return {
      id: 'USR-020',
      name: 'ToolForge Sandbox Configuration',
      category: 'config',
      severity: 'warning',
      passed,
      message: passed
        ? 'ToolForge sandbox is properly configured'
        : `Found ${evidence.length} sandbox configuration issue(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};

// ---------------------------------------------------------------------------
// Section 3: Single-Line CI/CD Reporter
//
// Outputs a single summary line suitable for CI/CD logs, Slack, or dashboards:
//   VASO: 85/100 (B) | 0 critical, 2 warning, 1 info | openclaw, toolforge
// ---------------------------------------------------------------------------

function createSummaryLineReporter() {
  return {
    format: 'summary-line',

    render(result) {
      const { totalScore, totalGrade, summary, agents } = result;
      const agentNames = agents.map(a => a.agent).join(', ');

      return [
        `VASO: ${totalScore}/100 (${totalGrade})`,
        `${summary.critical} critical, ${summary.warning} warning, ${summary.info} info`,
        agentNames,
      ].join(' | ') + '\n';
    },
  };
}

// ---------------------------------------------------------------------------
// Plugin export
// ---------------------------------------------------------------------------

export default {
  meta: {
    name: 'custom-agent-adapter',
    version: '1.0.0',
    description: 'ToolForge agent adapter with sandbox check and CI/CD reporter',
  },

  register(api) {
    // 1. Register the adapter so VASO can detect ToolForge installations
    api.registerAdapter(toolforgeAdapter);

    // 2. Register an agent-scoped check (only runs on ToolForge)
    api.registerCheck(toolforgeSandboxCheck);

    // 3. Register a CI/CD-friendly reporter (vaso scan --format summary-line)
    api.registerReporter('summary-line', createSummaryLineReporter);
  },
};
