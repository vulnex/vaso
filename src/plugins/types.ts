export type PluginAgentType = 'openclaw' | 'nanoclaw' | 'picoclaw';

export interface PluginConfig {
  blockOnCritical: boolean;
  blockOnWarning: boolean;
  timeout: number;
  excludeChecks: string[];
}

export interface PluginManifest {
  agent: PluginAgentType;
  vasoVersion: string;
  vasoBinaryPath: string;
  installedAt: string;
  pluginPath: string;
}

export interface PluginInfo {
  agent: PluginAgentType;
  installed: boolean;
  pluginPath: string | undefined;
  vasoBinaryPath: string | undefined;
  installedAt: string | undefined;
}

export interface PreStartScanResult {
  passed: boolean;
  blocked: boolean;
  blockReason: string | undefined;
  score: number;
  grade: string;
  summary: {
    critical: number;
    warning: number;
    info: number;
    passed: number;
    total: number;
  };
  criticalFindings: Array<{ id: string; name: string; message: string }>;
  warningFindings: Array<{ id: string; name: string; message: string }>;
  elapsedMs: number;
}

export const PLUGIN_AGENTS: PluginAgentType[] = ['openclaw', 'nanoclaw', 'picoclaw'];

export const DEFAULT_PLUGIN_CONFIG: PluginConfig = {
  blockOnCritical: true,
  blockOnWarning: false,
  timeout: 30_000,
  excludeChecks: [],
};
