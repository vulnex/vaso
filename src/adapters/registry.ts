import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, AgentType } from '../core/types.js';
import { captureConfigLoadErrors, type ConfigLoadError } from '../core/config-loader.js';

export interface AdapterDetectionError {
  agent: AgentType;
  displayName: string;
  message: string;
}

/** A config file an adapter found but could not read/parse during detect().
 *  Adapters swallow these (a broken file must not abort detection), which
 *  historically made a corrupted config look identical to a clean or absent
 *  one. The registry captures them here so the engine can surface the gap. */
export interface AdapterConfigLoadError extends ConfigLoadError {
  agent: AgentType;
  displayName: string;
}

export interface AdapterDetectionResult {
  installations: AgentInstallation[];
  errors: AdapterDetectionError[];
  configLoadErrors: AdapterConfigLoadError[];
}

/**
 * Versions are strings everywhere downstream (advisory range matching,
 * reporters). A version lifted from a parsed config can be a number or an
 * object — coerce finite numbers, drop anything else.
 */
function coerceVersion(v: unknown): string | undefined {
  if (typeof v === 'string') return v.trim() || undefined;
  if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  return undefined;
}

export function normalizeVersions(inst: AgentInstallation): AgentInstallation {
  const out: AgentInstallation = { ...inst, version: coerceVersion(inst.version) };
  if (inst.otherInstalls) {
    out.otherInstalls = inst.otherInstalls.map(o => ({ ...o, version: coerceVersion(o.version) }));
  }
  return out;
}

export class AdapterRegistry {
  private adapters: AgentAdapter[] = [];

  register(adapter: AgentAdapter): void {
    // A second copy would detect every installation twice (as the check
    // registry does, refuse rather than silently double the results)
    if (this.adapters.some(a => a === adapter || a.agent === adapter.agent)) {
      throw new Error(`Adapter "${adapter.agent}" is already registered`);
    }
    this.adapters.push(adapter);
  }

  async detectAllDetailed(options?: DetectOptions): Promise<AdapterDetectionResult> {
    // Each detect() runs inside its own config-load capture context, so the
    // concurrently-running adapters get correctly-attributed load errors.
    const results = await Promise.allSettled(
      this.adapters.map(a => captureConfigLoadErrors(() => a.detect(options)))
    );

    const installations: AgentInstallation[] = [];
    const errors: AdapterDetectionError[] = [];
    const configLoadErrors: AdapterConfigLoadError[] = [];

    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      const adapter = this.adapters[i];
      if (result.status === 'fulfilled') {
        installations.push(...result.value.result.map(normalizeVersions));
        configLoadErrors.push(
          ...result.value.loadErrors.map(e => ({
            ...e,
            agent: adapter.agent,
            displayName: adapter.displayName,
          }))
        );
      } else {
        errors.push({
          agent: adapter.agent,
          displayName: adapter.displayName,
          message: result.reason instanceof Error ? result.reason.message : String(result.reason),
        });
      }
    }

    return { installations, errors, configLoadErrors };
  }

  async detectAll(options?: DetectOptions): Promise<AgentInstallation[]> {
    return (await this.detectAllDetailed(options)).installations;
  }

  getAdapters(): AgentAdapter[] {
    return [...this.adapters];
  }

  getAdapter(agent: AgentType): AgentAdapter | undefined {
    return this.adapters.find(a => a.agent === agent);
  }
}

export const adapterRegistry = new AdapterRegistry();
