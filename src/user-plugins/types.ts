import type { CheckModule } from '../core/types.js';
import type { AgentAdapter } from '../adapters/adapter.js';
import type { Reporter } from '../reporting/reporter.js';

/**
 * What a user plugin exports from its module.
 */
export interface VasoPlugin {
  meta?: {
    name: string;
    version?: string;
    description?: string;
  };
  register(api: VasoPluginAPI): void | Promise<void>;
}

/**
 * The API object passed to a plugin's register() function.
 */
export interface VasoPluginAPI {
  /** VASO version string */
  version: string;

  /** Register a single security check */
  registerCheck(check: CheckModule): void;

  /** Register multiple security checks */
  registerChecks(checks: CheckModule[]): void;

  /** Register an agent adapter */
  registerAdapter(adapter: AgentAdapter): void;

  /** Register an output reporter */
  registerReporter(format: string, factory: () => Reporter): void;
}

/**
 * Internal tracking of a loaded user plugin.
 */
export interface LoadedPlugin {
  path: string;
  name: string;
  version?: string;
  description?: string;
  status: 'loaded' | 'error';
  error?: string;
  registered: {
    checks: string[];
    adapters: string[];
    reporters: string[];
  };
}
