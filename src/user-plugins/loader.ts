import { readdir, stat, readFile } from 'node:fs/promises';
import { join, basename, extname } from 'node:path';
import { homedir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { checkRegistry } from '../core/check-registry.js';
import { adapterRegistry } from '../adapters/registry.js';
import { registerReporter } from '../reporting/index.js';
import type { VasoPlugin, VasoPluginAPI, LoadedPlugin } from './types.js';
import type { CheckModule } from '../core/types.js';
import type { AgentAdapter } from '../adapters/adapter.js';
import type { Reporter } from '../reporting/reporter.js';

const VERSION = '0.2.1';

let loadedPlugins: LoadedPlugin[] = [];

function defaultPluginDir(): string {
  return join(homedir(), '.vaso', 'plugins');
}

/**
 * Resolve the entry point for a directory plugin.
 * Checks package.json "main" -> index.mjs -> index.js
 */
async function resolveDirectoryEntry(dirPath: string): Promise<string | null> {
  // Try package.json "main" field
  try {
    const pkgPath = join(dirPath, 'package.json');
    const pkgJson = JSON.parse(await readFile(pkgPath, 'utf-8'));
    if (pkgJson.main) {
      const mainPath = join(dirPath, pkgJson.main);
      const mainStat = await stat(mainPath);
      if (mainStat.isFile()) return mainPath;
    }
  } catch {
    // No package.json or invalid — fall through
  }

  // Try index.mjs then index.js
  for (const name of ['index.mjs', 'index.js']) {
    try {
      const candidate = join(dirPath, name);
      const s = await stat(candidate);
      if (s.isFile()) return candidate;
    } catch {
      // Not found — try next
    }
  }

  return null;
}

/**
 * Build a VasoPluginAPI that wraps the real registries,
 * recording what gets registered and catching errors.
 */
function buildPluginAPI(plugin: LoadedPlugin): VasoPluginAPI {
  return {
    version: VERSION,

    registerCheck(check: CheckModule): void {
      try {
        checkRegistry.register(check);
        plugin.registered.checks.push(check.id);
      } catch (err) {
        plugin.status = 'error';
        plugin.error = (plugin.error ? plugin.error + '; ' : '') +
          `Failed to register check "${check.id}": ${(err as Error).message}`;
      }
    },

    registerChecks(checks: CheckModule[]): void {
      for (const check of checks) {
        this.registerCheck(check);
      }
    },

    registerAdapter(adapter: AgentAdapter): void {
      try {
        adapterRegistry.register(adapter);
        plugin.registered.adapters.push(adapter.displayName);
      } catch (err) {
        plugin.status = 'error';
        plugin.error = (plugin.error ? plugin.error + '; ' : '') +
          `Failed to register adapter "${adapter.displayName}": ${(err as Error).message}`;
      }
    },

    registerReporter(format: string, factory: () => Reporter): void {
      try {
        registerReporter(format, factory);
        plugin.registered.reporters.push(format);
      } catch (err) {
        plugin.status = 'error';
        plugin.error = (plugin.error ? plugin.error + '; ' : '') +
          `Failed to register reporter "${format}": ${(err as Error).message}`;
      }
    },
  };
}

/**
 * Discover and load user plugins from the given directory
 * (defaults to ~/.vaso/plugins/).
 *
 * Broken plugins are recorded with status 'error' but never crash VASO.
 */
export async function loadUserPlugins(dir?: string): Promise<LoadedPlugin[]> {
  const pluginDir = dir ?? defaultPluginDir();
  loadedPlugins = [];

  // If the directory doesn't exist, that's fine — no user plugins
  let entries: string[];
  try {
    entries = await readdir(pluginDir);
  } catch {
    return loadedPlugins;
  }

  for (const entry of entries.sort()) {
    // Skip hidden files/dirs (dot or underscore prefix)
    if (entry.startsWith('.') || entry.startsWith('_')) continue;

    const fullPath = join(pluginDir, entry);
    let entryPoint: string;

    try {
      const entryStat = await stat(fullPath);

      if (entryStat.isDirectory()) {
        const resolved = await resolveDirectoryEntry(fullPath);
        if (!resolved) continue;
        entryPoint = resolved;
      } else if (entryStat.isFile()) {
        const ext = extname(entry);
        if (ext !== '.js' && ext !== '.mjs') continue;
        entryPoint = fullPath;
      } else {
        continue;
      }
    } catch {
      continue;
    }

    const plugin: LoadedPlugin = {
      path: fullPath,
      name: basename(entry, extname(entry)),
      status: 'loaded',
      registered: { checks: [], adapters: [], reporters: [] },
    };

    try {
      const fileUrl = pathToFileURL(entryPoint).href;
      const mod = await import(fileUrl);
      const pluginExport: VasoPlugin = mod.default ?? mod;

      if (pluginExport.meta) {
        if (pluginExport.meta.name) plugin.name = pluginExport.meta.name;
        if (pluginExport.meta.version) plugin.version = pluginExport.meta.version;
        if (pluginExport.meta.description) plugin.description = pluginExport.meta.description;
      }

      if (typeof pluginExport.register !== 'function') {
        plugin.status = 'error';
        plugin.error = 'Plugin does not export a register() function';
        loadedPlugins.push(plugin);
        continue;
      }

      const api = buildPluginAPI(plugin);
      await pluginExport.register(api);
    } catch (err) {
      plugin.status = 'error';
      plugin.error = `Failed to load plugin: ${(err as Error).message}`;
    }

    loadedPlugins.push(plugin);
  }

  return loadedPlugins;
}

/**
 * Return the list of plugins from the most recent loadUserPlugins() call.
 */
export function getLoadedPlugins(): LoadedPlugin[] {
  return [...loadedPlugins];
}

/**
 * Clear loaded plugin state (for testing).
 */
export function _resetForTesting(): void {
  loadedPlugins = [];
}
