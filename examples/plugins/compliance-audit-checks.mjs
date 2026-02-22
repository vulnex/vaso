/**
 * VASO Example Plugin: Compliance Audit Checks
 *
 * Demonstrates:
 *   - api.registerChecks() — batch registration of multiple checks
 *   - fix() method — returning remediation guidance
 *   - Multiple severity levels across checks
 *   - Shared helper function to reduce duplication
 *
 * Registers 3 compliance-oriented checks:
 *   USR-010 (critical): Audit logging must be enabled
 *   USR-011 (warning):  Log rotation should be configured
 *   USR-012 (warning):  Data retention policy should be defined
 *
 * Install: cp compliance-audit-checks.mjs ~/.vaso/plugins/
 * Verify:  vaso ext list
 */

// ---------------------------------------------------------------------------
// Shared helper: scan all configs for keys matching any of the given patterns
// ---------------------------------------------------------------------------

/**
 * Search all configs for keys matching the provided patterns.
 * Looks in both the parsed config data (structured walk) and raw text.
 *
 * @param {Array} configs - context.configs from ScanContext
 * @param {Array<{pattern: RegExp, label: string}>} keyPatterns - patterns to match against key paths
 * @returns {{ found: boolean, evidence: Array }} Whether any match was found plus evidence
 */
function findInConfigs(configs, keyPatterns) {
  const evidence = [];

  for (const config of configs) {
    // Structured walk of parsed data
    walkObject(config.data, (keyPath, value) => {
      for (const { pattern, label } of keyPatterns) {
        if (pattern.test(keyPath)) {
          evidence.push({
            file: config.filePath,
            detail: `Found ${label}: "${keyPath}" = ${JSON.stringify(value)}`,
          });
        }
      }
    });

    // Line-by-line scan of raw config text
    const lines = config.raw.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\s*[#;\/\/]/.test(line)) continue;

      for (const { pattern, label } of keyPatterns) {
        if (pattern.test(line)) {
          // Avoid duplicate evidence if already found via structured walk
          const alreadyFound = evidence.some(
            e => e.file === config.filePath && e.detail?.includes(label)
          );
          if (!alreadyFound) {
            evidence.push({
              file: config.filePath,
              line: i + 1,
              snippet: line.trim().slice(0, 80),
              detail: `Found ${label} in raw config`,
            });
          }
        }
      }
    }
  }

  return { found: evidence.length > 0, evidence };
}

/**
 * Walk a nested object, calling `visitor(keyPath, value)` for every leaf.
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

// ---------------------------------------------------------------------------
// Check definitions
// ---------------------------------------------------------------------------

const auditLoggingCheck = {
  id: 'USR-010',
  name: 'Audit Logging Enabled',
  category: 'config',
  severity: 'critical',
  description: 'Verify that audit logging is enabled for compliance requirements',

  async run(context) {
    const { found, evidence } = findInConfigs(context.configs, [
      { pattern: /\baudit[._-]?log/i, label: 'audit logging config' },
      { pattern: /\blogging[._]audit/i, label: 'logging.audit config' },
      { pattern: /\baudit[._-]?enabled/i, label: 'audit enabled flag' },
      { pattern: /\bLOG_AUDIT/i, label: 'LOG_AUDIT variable' },
    ]);

    // For audit logging, NOT finding it is the failure case
    return {
      id: 'USR-010',
      name: 'Audit Logging Enabled',
      category: 'config',
      severity: 'critical',
      passed: found,
      message: found
        ? `Audit logging configuration found (${evidence.length} reference(s))`
        : 'No audit logging configuration found — required for compliance',
      evidence: found ? undefined : [{
        file: context.configs[0]?.filePath || 'N/A',
        detail: 'No audit logging keys found in any agent config',
      }],
      fixable: !found,
      fixDescription: 'Add audit logging configuration to your agent config',
    };
  },

  // Demonstrates the fix() method — returns guidance for manual remediation.
  // In real checks, fix() could modify config files directly if `applied: true`.
  async fix(context) {
    return {
      checkId: 'USR-010',
      applied: false,
      message: [
        'To enable audit logging, add one of the following to your agent config:',
        '',
        '  YAML:  logging:',
        '           audit:',
        '             enabled: true',
        '             destination: /var/log/agent/audit.log',
        '',
        '  JSON:  "logging": { "audit": { "enabled": true } }',
        '',
        '  ENV:   LOG_AUDIT=true',
        '',
        'Ensure the audit log directory exists and has appropriate permissions.',
      ].join('\n'),
    };
  },
};

const logRotationCheck = {
  id: 'USR-011',
  name: 'Log Rotation Configured',
  category: 'config',
  severity: 'warning',
  description: 'Verify that log rotation is configured to prevent disk exhaustion',

  async run(context) {
    const { found, evidence } = findInConfigs(context.configs, [
      { pattern: /\blog[._-]?rotation/i, label: 'log rotation config' },
      { pattern: /\bmaxSize/i, label: 'maxSize setting' },
      { pattern: /\bmaxFiles/i, label: 'maxFiles setting' },
      { pattern: /\brotate[._-]?logs/i, label: 'log rotation flag' },
      { pattern: /\blogrotate/i, label: 'logrotate config' },
    ]);

    return {
      id: 'USR-011',
      name: 'Log Rotation Configured',
      category: 'config',
      severity: 'warning',
      passed: found,
      message: found
        ? `Log rotation configuration found (${evidence.length} reference(s))`
        : 'No log rotation configuration found — logs may grow unbounded',
      evidence: found ? undefined : [{
        file: context.configs[0]?.filePath || 'N/A',
        detail: 'No log rotation keys (maxSize, maxFiles, rotation) found in configs',
      }],
    };
  },
};

const dataRetentionCheck = {
  id: 'USR-012',
  name: 'Data Retention Policy',
  category: 'config',
  severity: 'warning',
  description: 'Verify that a data retention policy is defined for stored data',

  async run(context) {
    const { found, evidence } = findInConfigs(context.configs, [
      { pattern: /\bretention/i, label: 'retention policy' },
      { pattern: /\bdataRetention/i, label: 'data retention config' },
      { pattern: /\bttl\b/i, label: 'TTL setting' },
      { pattern: /\bexpir[ey]/i, label: 'expiry setting' },
      { pattern: /\bpurge[._-]?after/i, label: 'purge-after setting' },
    ]);

    return {
      id: 'USR-012',
      name: 'Data Retention Policy',
      category: 'config',
      severity: 'warning',
      passed: found,
      message: found
        ? `Data retention configuration found (${evidence.length} reference(s))`
        : 'No data retention policy found — data may accumulate indefinitely',
      evidence: found ? undefined : [{
        file: context.configs[0]?.filePath || 'N/A',
        detail: 'No retention/TTL/expiry keys found in configs',
      }],
    };
  },
};

// ---------------------------------------------------------------------------
// Plugin export
// ---------------------------------------------------------------------------

export default {
  meta: {
    name: 'compliance-audit-checks',
    version: '1.0.0',
    description: 'Compliance checks for audit logging, log rotation, and data retention',
  },

  register(api) {
    // Use registerChecks() to register all three at once (batch registration).
    api.registerChecks([
      auditLoggingCheck,
      logRotationCheck,
      dataRetentionCheck,
    ]);
  },
};
