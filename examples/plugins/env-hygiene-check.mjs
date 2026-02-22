/**
 * VASO Example Plugin: Environment Hygiene Check
 *
 * Demonstrates: api.registerCheck() — registering a single security check.
 *
 * This plugin detects insecure environment variable patterns in agent configs
 * that often indicate development settings leaked into production:
 *   - NODE_ENV=development, DEBUG=true, LOG_LEVEL=debug
 *   - Verbose error flags (SHOW_ERRORS, DEV_MODE)
 *   - Internal/development hostnames (localhost, *.internal, 192.168.*)
 *
 * Install: cp env-hygiene-check.mjs ~/.vaso/plugins/
 * Verify:  vaso ext list
 */

import { readFileSync } from 'node:fs';

// Patterns that suggest development/debug settings in production configs.
// Each entry has a regex for line-by-line matching and a human-readable label.
const INSECURE_ENV_PATTERNS = [
  { pattern: /\bNODE_ENV\s*[=:]\s*['"]?development/i, label: 'NODE_ENV set to development' },
  { pattern: /\bDEBUG\s*[=:]\s*['"]?true/i, label: 'DEBUG mode enabled' },
  { pattern: /\bLOG_LEVEL\s*[=:]\s*['"]?debug/i, label: 'LOG_LEVEL set to debug' },
  { pattern: /\bSHOW_ERRORS\s*[=:]\s*['"]?true/i, label: 'SHOW_ERRORS enabled' },
  { pattern: /\bDEV_MODE\s*[=:]\s*['"]?true/i, label: 'DEV_MODE enabled' },
  { pattern: /\bVERBOSE\s*[=:]\s*['"]?true/i, label: 'VERBOSE mode enabled' },
];

// Hostnames/IPs that should not appear in production config values.
const DEV_HOST_PATTERNS = [
  { pattern: /\blocalhost\b/, label: 'localhost reference' },
  { pattern: /\b127\.0\.0\.1\b/, label: '127.0.0.1 loopback reference' },
  { pattern: /\b192\.168\.\d{1,3}\.\d{1,3}\b/, label: 'Private 192.168.x.x IP' },
  { pattern: /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, label: 'Private 10.x.x.x IP' },
  { pattern: /\.internal\b/, label: 'Internal hostname (.internal)' },
  { pattern: /\.local\b/, label: 'Local hostname (.local)' },
];

/**
 * Walk a nested object, calling `visitor(keyPath, value)` for every leaf value.
 * keyPath is a dot-separated string like "server.gateway.host".
 */
function walkObject(obj, visitor, prefix = '') {
  if (obj === null || obj === undefined) return;
  for (const [key, value] of Object.entries(obj)) {
    const keyPath = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      walkObject(value, visitor, keyPath);
    } else {
      visitor(keyPath, value);
    }
  }
}

export default {
  meta: {
    name: 'env-hygiene-check',
    version: '1.0.0',
    description: 'Detects development/debug environment settings in production configs',
  },

  register(api) {
    api.registerCheck({
      id: 'USR-001',
      name: 'Environment Hygiene',
      category: 'config',
      severity: 'warning',
      description: 'Detect development/debug environment patterns in agent configs',

      async run(context) {
        const evidence = [];

        for (const config of context.configs) {
          // --- Structured walk: check parsed config data ---
          // This catches values regardless of file format (JSON, YAML, etc.)
          walkObject(config.data, (keyPath, value) => {
            const strValue = String(value);

            // Check for dev host references in config values
            for (const { pattern, label } of DEV_HOST_PATTERNS) {
              if (pattern.test(strValue)) {
                evidence.push({
                  file: config.filePath,
                  detail: `${label} in config key "${keyPath}" = "${strValue.slice(0, 60)}"`,
                });
              }
            }
          });

          // --- Line-by-line scan: catches patterns in raw text ---
          // This covers .env files, comments, and non-parsed formats.
          const lines = config.raw.split('\n');
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i];

            // Skip comment lines
            if (/^\s*[#;\/\/]/.test(line)) continue;

            for (const { pattern, label } of INSECURE_ENV_PATTERNS) {
              if (pattern.test(line)) {
                evidence.push({
                  file: config.filePath,
                  line: i + 1,
                  snippet: line.trim().slice(0, 80),
                  detail: label,
                });
              }
            }
          }
        }

        const passed = evidence.length === 0;

        return {
          id: 'USR-001',
          name: 'Environment Hygiene',
          category: 'config',
          severity: 'warning',
          passed,
          message: passed
            ? 'No development/debug environment patterns found in configs'
            : `Found ${evidence.length} development/debug pattern(s) in agent configs`,
          evidence: evidence.length > 0 ? evidence : undefined,
        };
      },
    });
  },
};
