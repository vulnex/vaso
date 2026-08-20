#!/usr/bin/env node
var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/core/local-fs-provider.ts
import { access as fsAccess, readdir, readFile, stat, realpath, readlink } from "fs/promises";
import { execFileSync, execFile } from "child_process";
import { homedir as osHomedir, hostname as osHostname } from "os";
import { promisify } from "util";
var execFileAsync, LocalFSProvider;
var init_local_fs_provider = __esm({
  "src/core/local-fs-provider.ts"() {
    "use strict";
    execFileAsync = promisify(execFile);
    LocalFSProvider = class {
      platform = process.platform;
      async readFile(path) {
        return readFile(path, "utf-8");
      }
      async readBytes(path) {
        return readFile(path);
      }
      async readdir(path) {
        return readdir(path);
      }
      async readdirEntries(path, options) {
        const entries = await readdir(path, {
          withFileTypes: true,
          recursive: options?.recursive ?? false
        });
        return entries.map((e) => ({
          name: e.name,
          isFile: e.isFile(),
          isDirectory: e.isDirectory(),
          isSymbolicLink: e.isSymbolicLink(),
          parentPath: e.parentPath
        }));
      }
      async access(path) {
        try {
          await fsAccess(path);
          return true;
        } catch {
          return false;
        }
      }
      async stat(path) {
        const s = await stat(path);
        return {
          mode: s.mode,
          isFile: () => s.isFile(),
          isDirectory: () => s.isDirectory()
        };
      }
      async realpath(path) {
        return realpath(path);
      }
      async readlink(path) {
        return readlink(path);
      }
      async exec(cmd, args, options) {
        try {
          const result = await execFileAsync(cmd, args, {
            encoding: "utf-8",
            timeout: options?.timeout ?? 1e4,
            cwd: options?.cwd
          });
          return {
            stdout: result.stdout,
            stderr: result.stderr,
            exitCode: 0
          };
        } catch (err) {
          const e = err;
          return {
            stdout: e.stdout ?? "",
            stderr: e.stderr ?? "",
            exitCode: e.status ?? e.code ?? 1
          };
        }
      }
      execSync(cmd, args, options) {
        return execFileSync(cmd, args, {
          encoding: "utf-8",
          timeout: options?.timeout ?? 1e4,
          stdio: ["pipe", "pipe", "pipe"],
          cwd: options?.cwd
        }).toString();
      }
      homedir() {
        return osHomedir();
      }
      hostname() {
        return osHostname();
      }
      getEnv(key) {
        return process.env[key];
      }
    };
  }
});

// src/core/config-loader.ts
import { extname } from "path";
import { AsyncLocalStorage } from "async_hooks";
import YAML from "yaml";
import { parse as parseTOML } from "smol-toml";
async function captureConfigLoadErrors(fn) {
  const loadErrors = [];
  const result = await loadErrorStore.run(loadErrors, fn);
  return { result, loadErrors };
}
function recordLoadError(error) {
  loadErrorStore.getStore()?.push(error);
}
function isFileNotFound(error) {
  if (error?.code === "ENOENT") return true;
  return error instanceof Error && error.message.startsWith("ENOENT");
}
function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
async function loadConfig(filePath, fs) {
  const provider = fs ?? new LocalFSProvider();
  let raw;
  try {
    raw = await provider.readFile(filePath);
  } catch (error) {
    if (!isFileNotFound(error)) {
      recordLoadError({ filePath, stage: "read", message: errorMessage(error) });
    }
    throw error;
  }
  const ext = extname(filePath).toLowerCase();
  const format = detectFormat(ext, filePath);
  let data;
  try {
    data = parseContent(raw, format);
  } catch (error) {
    recordLoadError({ filePath, stage: "parse", message: errorMessage(error) });
    throw error;
  }
  if (data === UNPARSEABLE && raw.trim().length > 0) {
    recordLoadError({
      filePath,
      stage: "parse",
      message: "Content did not parse as JSON, YAML, or TOML"
    });
  }
  return { raw, format, filePath, data: data === UNPARSEABLE ? {} : data };
}
function detectFormat(ext, filePath) {
  switch (ext) {
    case ".json":
      return "json";
    case ".yaml":
    case ".yml":
      return "yaml";
    case ".env":
      return "env";
    case ".toml":
      return "toml";
    default:
      if (filePath.endsWith(".env") || filePath.includes(".env.")) return "env";
      return "unknown";
  }
}
function parseContent(raw, format) {
  switch (format) {
    case "json":
      return JSON.parse(raw);
    case "yaml":
      return YAML.parse(raw) ?? {};
    case "env":
      return parseEnv(raw);
    case "toml":
      return parseTOML(raw);
    case "unknown":
      return tryParse(raw);
  }
}
function parseEnv(raw) {
  const data = {};
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) continue;
    const key = trimmed.slice(0, eqIndex).trim();
    let value = trimmed.slice(eqIndex + 1).trim();
    if (value.startsWith('"') && value.endsWith('"') || value.startsWith("'") && value.endsWith("'")) {
      value = value.slice(1, -1);
    }
    data[key] = value;
  }
  return data;
}
function tryParse(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    try {
      return YAML.parse(raw) ?? {};
    } catch {
      try {
        return parseTOML(raw);
      } catch {
        return UNPARSEABLE;
      }
    }
  }
}
var loadErrorStore, UNPARSEABLE;
var init_config_loader = __esm({
  "src/core/config-loader.ts"() {
    "use strict";
    init_local_fs_provider();
    loadErrorStore = new AsyncLocalStorage();
    UNPARSEABLE = {};
  }
});

// src/adapters/registry.ts
var registry_exports = {};
__export(registry_exports, {
  AdapterRegistry: () => AdapterRegistry,
  adapterRegistry: () => adapterRegistry
});
var AdapterRegistry, adapterRegistry;
var init_registry = __esm({
  "src/adapters/registry.ts"() {
    "use strict";
    init_config_loader();
    AdapterRegistry = class {
      adapters = [];
      register(adapter) {
        this.adapters.push(adapter);
      }
      async detectAllDetailed(options) {
        const results = await Promise.allSettled(
          this.adapters.map((a) => captureConfigLoadErrors(() => a.detect(options)))
        );
        const installations = [];
        const errors = [];
        const configLoadErrors = [];
        for (let i = 0; i < results.length; i++) {
          const result = results[i];
          const adapter = this.adapters[i];
          if (result.status === "fulfilled") {
            installations.push(...result.value.result);
            configLoadErrors.push(
              ...result.value.loadErrors.map((e) => ({
                ...e,
                agent: adapter.agent,
                displayName: adapter.displayName
              }))
            );
          } else {
            errors.push({
              agent: adapter.agent,
              displayName: adapter.displayName,
              message: result.reason instanceof Error ? result.reason.message : String(result.reason)
            });
          }
        }
        return { installations, errors, configLoadErrors };
      }
      async detectAll(options) {
        return (await this.detectAllDetailed(options)).installations;
      }
      getAdapters() {
        return [...this.adapters];
      }
      getAdapter(agent) {
        return this.adapters.find((a) => a.agent === agent);
      }
    };
    adapterRegistry = new AdapterRegistry();
  }
});

// src/core/utils.ts
import { join, extname as extname2, dirname, relative, sep } from "path";
import { mkdir, writeFile } from "fs/promises";
function getNestedValue(obj, path) {
  return path.split(".").reduce((curr, key) => {
    if (curr && typeof curr === "object") return curr[key];
    return void 0;
  }, obj);
}
function isExcludedPath(root, parentPath) {
  if (!parentPath) return false;
  const rel = relative(root, parentPath);
  if (!rel || rel.startsWith("..")) return false;
  for (const segment of rel.split(sep)) {
    if (segment && EXCLUDED_DIRS.has(segment)) return true;
  }
  return false;
}
function getAllSkillsDirs(installation) {
  if (installation.skillsDirs && installation.skillsDirs.length > 0) {
    return installation.skillsDirs;
  }
  return installation.skillsDir ? [installation.skillsDir] : [];
}
async function getSkillFiles(dir, fs) {
  const provider = fs ?? new LocalFSProvider();
  const files = [];
  try {
    const entries = await provider.readdirEntries(dir, { recursive: true });
    for (const entry of entries) {
      if (!entry.isFile) continue;
      if (!CODE_EXTENSIONS.has(extname2(entry.name))) continue;
      if (isExcludedPath(dir, entry.parentPath)) continue;
      const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(dir, entry.name);
      files.push(fullPath);
    }
  } catch {
  }
  return files;
}
function setNestedValue(obj, path, value) {
  const keys = path.split(".");
  let current = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    if (!(keys[i] in current) || typeof current[keys[i]] !== "object" || current[keys[i]] === null) {
      current[keys[i]] = {};
    }
    current = current[keys[i]];
  }
  current[keys[keys.length - 1]] = value;
}
function deepMerge(base, override) {
  const result = { ...base };
  for (const key of Object.keys(override)) {
    const baseVal = base[key];
    const overVal = override[key];
    if (overVal !== null && typeof overVal === "object" && !Array.isArray(overVal) && baseVal !== null && typeof baseVal === "object" && !Array.isArray(baseVal)) {
      result[key] = deepMerge(
        baseVal,
        overVal
      );
    } else {
      result[key] = overVal;
    }
  }
  return result;
}
async function pathExists(path, fs) {
  const provider = fs ?? new LocalFSProvider();
  return provider.access(path);
}
async function writeFileEnsureDir(path, content) {
  const parent = dirname(path);
  if (parent && parent !== "." && parent !== "/") {
    await mkdir(parent, { recursive: true });
  }
  await writeFile(path, content, "utf-8");
}
var CODE_EXTENSIONS, EXCLUDED_DIRS;
var init_utils = __esm({
  "src/core/utils.ts"() {
    "use strict";
    init_local_fs_provider();
    CODE_EXTENSIONS = /* @__PURE__ */ new Set([".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".py", ".sh", ".bash"]);
    EXCLUDED_DIRS = /* @__PURE__ */ new Set([
      "node_modules",
      ".git",
      "dist",
      "build",
      ".next",
      ".cache",
      ".venv",
      "venv",
      "__pycache__"
    ]);
  }
});

// src/core/check-registry.ts
var check_registry_exports = {};
__export(check_registry_exports, {
  CheckRegistry: () => CheckRegistry,
  checkRegistry: () => checkRegistry
});
var CheckRegistry, checkRegistry;
var init_check_registry = __esm({
  "src/core/check-registry.ts"() {
    "use strict";
    CheckRegistry = class {
      checks = [];
      register(check) {
        if (this.checks.some((c) => c.id === check.id)) {
          throw new Error(`Check "${check.id}" is already registered`);
        }
        this.checks.push(check);
      }
      registerAll(checks) {
        for (const check of checks) {
          this.register(check);
        }
      }
      getAll() {
        return [...this.checks];
      }
      getByCategory(category) {
        return this.checks.filter((c) => c.category === category);
      }
      getForAgent(agent) {
        return this.checks.filter(
          (c) => (!c.supportedAgents || c.supportedAgents.includes(agent)) && !c.excludedAgents?.includes(agent)
        );
      }
      getForPlatform(platform) {
        return this.checks.filter(
          (c) => !c.supportedPlatforms || c.supportedPlatforms.includes(platform)
        );
      }
      getApplicable(agent, platform) {
        return this.checks.filter((c) => {
          const agentMatch = !c.supportedAgents || c.supportedAgents.includes(agent);
          const notExcluded = !c.excludedAgents?.includes(agent);
          const platformMatch = !c.supportedPlatforms || c.supportedPlatforms.includes(platform);
          return agentMatch && notExcluded && platformMatch;
        });
      }
      count() {
        return this.checks.length;
      }
    };
    checkRegistry = new CheckRegistry();
  }
});

// src/reporting/owasp-agentic.ts
function owaspAgenticForCheckId(id) {
  return CHECK_AGENTIC_MAP[id] ?? [];
}
function applyAgenticTags(checks) {
  for (const check of checks) {
    const ids = CHECK_AGENTIC_MAP[check.id];
    if (ids && ids.length > 0) check.owaspAgentic = ids;
  }
}
function computeOwaspAgenticCoverage(result) {
  const byRisk = /* @__PURE__ */ new Map();
  for (const id of Object.keys(OWASP_AGENTIC_TITLES)) {
    byRisk.set(id, { checks: /* @__PURE__ */ new Set(), failed: 0 });
  }
  for (const agent of result.agents) {
    for (const finding of agent.results) {
      const risks = CHECK_AGENTIC_MAP[finding.id];
      if (!risks) continue;
      for (const risk of risks) {
        const bucket = byRisk.get(risk);
        bucket.checks.add(finding.id);
        if (!finding.passed) bucket.failed += 1;
      }
    }
  }
  return Object.keys(OWASP_AGENTIC_TITLES).map((id) => {
    const b = byRisk.get(id);
    return {
      id,
      title: OWASP_AGENTIC_TITLES[id],
      checks: [...b.checks].sort(),
      failed: b.failed,
      covered: b.checks.size > 0,
      inCatalog: AGENTIC_RISKS_IN_CATALOG.has(id)
    };
  });
}
function hasOwaspAgenticFindings(result) {
  return result.agents.some((a) => a.results.some((r) => CHECK_AGENTIC_MAP[r.id]));
}
function renderOwaspAgenticCoverageMarkdown(result) {
  if (!hasOwaspAgenticFindings(result)) return "";
  const rows = computeOwaspAgenticCoverage(result);
  const lines = [
    "## OWASP Agentic AI Top 10 Coverage",
    "",
    "| Risk | Title | Checks | Status |",
    "| --- | --- | --- | --- |"
  ];
  for (const row2 of rows) {
    let status;
    if (!row2.inCatalog) {
      status = "not covered (runtime/behavioral)";
    } else if (!row2.covered) {
      status = "no findings in this scan";
    } else if (row2.failed > 0) {
      status = `\u26A0\uFE0F ${row2.failed} finding(s)`;
    } else {
      status = "\u2705 pass";
    }
    lines.push(`| ${row2.id} | ${row2.title} | ${row2.checks.join(", ") || "\u2014"} | ${status} |`);
  }
  lines.push("");
  return lines.join("\n");
}
var OWASP_AGENTIC_TITLES, CHECK_AGENTIC_MAP, AGENTIC_RISKS_IN_CATALOG;
var init_owasp_agentic = __esm({
  "src/reporting/owasp-agentic.ts"() {
    "use strict";
    OWASP_AGENTIC_TITLES = {
      AAI001: "Agent Authorization and Control Hijacking",
      AAI002: "Agent Critical Systems Interaction",
      AAI003: "Agent Goal and Instruction Manipulation",
      AAI005: "Agent Impact Chain and Blast Radius",
      AAI006: "Agent Memory and Context Manipulation",
      AAI007: "Agent Orchestration and Multi-Agent Exploitation",
      AAI009: "Agent Supply Chain and Dependency Attacks",
      AAI011: "Agent Untraceability",
      AAI012: "Agent Checker out of the Loop",
      AAI014: "Agent Alignment Faking"
    };
    CHECK_AGENTIC_MAP = {
      // Dedicated MCP scanner (mcp category)
      "MCP-001": ["AAI007"],
      "MCP-002": ["AAI009", "AAI001"],
      "MCP-003": ["AAI001"],
      "MCP-004": ["AAI002", "AAI005"],
      "MCP-005": ["AAI002", "AAI003"],
      "MCP-006": ["AAI005"],
      "MCP-007": ["AAI003"],
      "MCP-008": ["AAI009"],
      "MCP-009": ["AAI001", "AAI005"],
      "MCP-010": ["AAI009", "AAI006"],
      "MCP-011": ["AAI001", "AAI009"],
      "MCP-012": ["AAI001"],
      "MCP-013": ["AAI001"],
      "MCP-014": ["AAI001"],
      "MCP-015": ["AAI001"],
      "MCP-016": ["AAI001"],
      "MCP-017": ["AAI001", "AAI005"],
      "MCP-018": ["AAI001"],
      "MCP-019": ["AAI003", "AAI005"],
      "MCP-020": ["AAI006", "AAI003"],
      "MCP-021": ["AAI002", "AAI005"],
      "MCP-022": ["AAI002", "AAI005", "AAI009"],
      "MCP-023": ["AAI001", "AAI005"],
      "MCP-024": ["AAI003"],
      "MCP-025": ["AAI007"],
      "MCP-026": ["AAI007"],
      "MCP-027": ["AAI009"],
      "MCP-028": ["AAI006", "AAI009"],
      "MCP-029": ["AAI001"],
      "MCP-030": ["AAI009"],
      "MCP-031": ["AAI005", "AAI002"],
      "MCP-032": ["AAI005", "AAI002"],
      "MCP-033": ["AAI001"],
      "MCP-034": ["AAI003"],
      "MCP-035": ["AAI009"],
      // Server config (CFG)
      "CFG-001": ["AAI005"],
      "CFG-002": ["AAI001"],
      "CFG-003": ["AAI001"],
      "CFG-004": ["AAI005"],
      "CFG-005": ["AAI002", "AAI001"],
      "CFG-006": ["AAI002", "AAI005"],
      "CFG-007": ["AAI001", "AAI005"],
      "CFG-008": ["AAI002", "AAI005"],
      "CFG-009": ["AAI001"],
      "CFG-010": ["AAI005"],
      "CFG-011": ["AAI009"],
      "CFG-012": ["AAI001", "AAI005"],
      "CFG-013": ["AAI001", "AAI005"],
      "CFG-014": ["AAI001", "AAI012"],
      "CFG-015": ["AAI005"],
      "CFG-016": ["AAI002", "AAI005"],
      "CFG-017": ["AAI002", "AAI005"],
      "CFG-018": ["AAI005"],
      "CFG-019": ["AAI009"],
      "CFG-020": ["AAI001"],
      "CFG-021": ["AAI002", "AAI005"],
      "CFG-022": ["AAI002", "AAI005"],
      "CFG-023": ["AAI009"],
      "CFG-024": ["AAI002", "AAI005"],
      // Network exposure (NET)
      "NET-001": ["AAI005"],
      "NET-002": ["AAI001", "AAI005"],
      "NET-003": ["AAI001", "AAI005"],
      "NET-004": ["AAI005"],
      "NET-005": ["AAI005"],
      // Runtime (RUN)
      "RUN-001": ["AAI002", "AAI005"],
      "RUN-002": ["AAI002", "AAI005"],
      "RUN-003": ["AAI009"],
      "RUN-004": ["AAI002", "AAI005"],
      "RUN-005": ["AAI002"],
      // Policy (POL)
      "POL-001": ["AAI012", "AAI001"],
      "POL-002": ["AAI011"],
      "POL-003": ["AAI001"],
      "POL-004": ["AAI002", "AAI005"],
      "POL-005": ["AAI001"],
      // Skills code analysis (SKL)
      "SKL-001": ["AAI005", "AAI002"],
      "SKL-002": ["AAI009", "AAI002"],
      "SKL-003": ["AAI002"],
      "SKL-004": ["AAI002", "AAI009"],
      "SKL-005": ["AAI002", "AAI005"],
      "SKL-006": ["AAI002", "AAI005"],
      "SKL-007": ["AAI003"],
      "SKL-008": ["AAI005", "AAI002"],
      "SKL-009": ["AAI002", "AAI005"],
      "SKL-010": ["AAI002"],
      "SKL-011": ["AAI009"],
      "SKL-013": ["AAI002", "AAI012", "AAI005"],
      // Indicators of compromise (IOC)
      "IOC-001": ["AAI009", "AAI005"],
      "IOC-002": ["AAI009", "AAI005"],
      "IOC-003": ["AAI009"],
      "IOC-004": ["AAI009"],
      "IOC-005": ["AAI009"],
      "IOC-006": ["AAI009"],
      "IOC-007": ["AAI009", "AAI002"],
      "IOC-008": ["AAI009"],
      // Advisory / known-CVE (ADV)
      "ADV-001": ["AAI009"],
      "ADV-002": ["AAI009"],
      "ADV-003": ["AAI009"],
      "ADV-004": ["AAI009"],
      "ADV-005": ["AAI009"],
      // OpenClaw (OC)
      "OC-001": ["AAI007", "AAI001"],
      "OC-003": ["AAI001"],
      "OC-004": ["AAI005", "AAI001"],
      "OC-005": ["AAI001"],
      "OC-006": ["AAI006"],
      "OC-007": ["AAI001", "AAI002"],
      // NanoClaw (NC)
      "NC-001": ["AAI002", "AAI005"],
      "NC-002": ["AAI001", "AAI002"],
      "NC-003": ["AAI005", "AAI002"],
      "NC-004": ["AAI005"],
      "NC-005": ["AAI002", "AAI009"],
      // IronClaw (IC)
      "IC-001": ["AAI005"],
      "IC-002": ["AAI005"],
      "IC-003": ["AAI005"],
      "IC-004": ["AAI001"],
      "IC-005": ["AAI002", "AAI005"],
      "IC-006": ["AAI002", "AAI005"],
      "IC-007": ["AAI012", "AAI001"],
      "IC-008": ["AAI002", "AAI005"],
      "IC-009": ["AAI001", "AAI005"],
      "IC-010": ["AAI001"],
      "IC-011": ["AAI005"],
      "IC-012": ["AAI009"],
      // Nanobot (NB)
      "NB-001": ["AAI001"],
      "NB-002": ["AAI001"],
      "NB-003": ["AAI002", "AAI005"],
      "NB-004": ["AAI002"],
      "NB-005": ["AAI005"],
      "NB-006": ["AAI003", "AAI006"],
      "NB-007": ["AAI003", "AAI006"],
      "NB-008": ["AAI001"],
      "NB-009": ["AAI006"],
      "NB-010": ["AAI005", "AAI001"],
      "NB-011": ["AAI005"],
      "NB-012": ["AAI009"],
      // ZeroClaw (ZC)
      "ZC-001": ["AAI001"],
      "ZC-002": ["AAI001"],
      "ZC-003": ["AAI005"],
      "ZC-004": ["AAI001"],
      "ZC-005": ["AAI012", "AAI001"],
      "ZC-006": ["AAI002", "AAI005"],
      "ZC-007": ["AAI001"],
      "ZC-008": ["AAI009"],
      "ZC-009": ["AAI001"],
      "ZC-010": ["AAI005", "AAI009"],
      "ZC-011": ["AAI005"],
      "ZC-012": ["AAI005"],
      "ZC-013": ["AAI001"],
      "ZC-014": ["AAI002", "AAI005"],
      // Lyrie (LY)
      "LY-001": ["AAI012", "AAI002"],
      "LY-002": ["AAI012", "AAI002"],
      "LY-003": ["AAI001", "AAI003"],
      "LY-004": ["AAI001"],
      "LY-005": ["AAI012"],
      "LY-006": ["AAI001"],
      "LY-007": ["AAI001"],
      "LY-008": ["AAI001", "AAI005"],
      "LY-009": ["AAI012"],
      "LY-010": ["AAI005", "AAI001"],
      "LY-011": ["AAI005"],
      "LY-012": ["AAI006"],
      "LY-013": ["AAI006", "AAI002"],
      "LY-014": ["AAI002", "AAI009"],
      "LY-015": ["AAI002", "AAI009"],
      "LY-016": ["AAI007", "AAI009"],
      "LY-017": ["AAI007", "AAI006"],
      "LY-018": ["AAI005"],
      // Hermes (HM)
      "HM-001": ["AAI001"],
      "HM-002": ["AAI001"],
      "HM-003": ["AAI001"],
      "HM-004": ["AAI001", "AAI005"],
      "HM-005": ["AAI005", "AAI001"],
      "HM-006": ["AAI009"],
      "HM-007": ["AAI009"],
      "HM-008": ["AAI012", "AAI001"],
      "HM-009": ["AAI012", "AAI002"],
      "HM-010": ["AAI009", "AAI002"],
      // Coding agents (CC/CD/CG/CDX/OPC/GEM/QC/CUR/GHC)
      "CC-001": ["AAI012", "AAI001"],
      "CC-002": ["AAI001", "AAI002"],
      "CC-003": ["AAI002", "AAI001"],
      "CC-004": ["AAI001"],
      "CC-005": ["AAI009"],
      "CC-006": ["AAI007", "AAI009"],
      "CC-007": ["AAI001", "AAI002"],
      "CC-008": ["AAI001"],
      "CC-009": ["AAI005", "AAI002"],
      "CC-010": ["AAI002", "AAI003"],
      "CC-011": ["AAI003", "AAI007"],
      "CC-012": ["AAI006", "AAI003"],
      "CD-001": ["AAI001"],
      "CD-002": ["AAI001"],
      "CD-003": ["AAI009"],
      "CD-004": ["AAI009"],
      "CD-005": ["AAI009"],
      "CD-006": ["AAI012", "AAI001"],
      "CD-007": ["AAI005", "AAI002"],
      "CD-008": ["AAI002", "AAI001"],
      "CD-009": ["AAI002", "AAI001"],
      "CD-010": ["AAI001"],
      "CDX-001": ["AAI012", "AAI001"],
      "CDX-002": ["AAI002", "AAI005"],
      "CDX-003": ["AAI001"],
      "CDX-004": ["AAI009"],
      "CDX-005": ["AAI005", "AAI001"],
      "CDX-006": ["AAI001", "AAI012"],
      "CDX-007": ["AAI006", "AAI003"],
      "CDX-008": ["AAI001", "AAI012"],
      "CDX-009": ["AAI002", "AAI001"],
      "CG-003": ["AAI011"],
      "CG-004": ["AAI005"],
      "CG-005": ["AAI009"],
      "CG-006": ["AAI007", "AAI009"],
      "CUR-001": ["AAI002", "AAI005"],
      "CUR-002": ["AAI012", "AAI001"],
      "CUR-003": ["AAI001", "AAI002"],
      "CUR-004": ["AAI001"],
      "CUR-005": ["AAI001"],
      "CUR-006": ["AAI009"],
      "CUR-007": ["AAI011"],
      "CUR-008": ["AAI005", "AAI002"],
      "CUR-009": ["AAI001", "AAI002"],
      "CUR-010": ["AAI011"],
      "GEM-001": ["AAI001"],
      "GEM-002": ["AAI001"],
      "GEM-003": ["AAI001", "AAI002"],
      "GEM-004": ["AAI012", "AAI001"],
      "GEM-005": ["AAI002", "AAI005"],
      "GEM-006": ["AAI005", "AAI002"],
      "GEM-007": ["AAI009"],
      "GEM-008": ["AAI009"],
      "GEM-009": ["AAI012", "AAI001"],
      "GEM-010": ["AAI006", "AAI003"],
      "GHC-001": ["AAI006"],
      "GHC-002": ["AAI012", "AAI001"],
      "GHC-003": ["AAI001"],
      "GHC-004": ["AAI009"],
      "GHC-005": ["AAI009"],
      "GHC-006": ["AAI009"],
      "GHC-007": ["AAI002"],
      "GHC-008": ["AAI006", "AAI003"],
      "OPC-001": ["AAI001"],
      "OPC-002": ["AAI001", "AAI012"],
      "OPC-003": ["AAI009"],
      "OPC-004": ["AAI011"],
      "OPC-005": ["AAI009", "AAI002"],
      "OPC-006": ["AAI007", "AAI001"],
      "OPC-007": ["AAI006", "AAI003"],
      "OPC-008": ["AAI012", "AAI001"],
      "OPC-009": ["AAI009"],
      "OPC-010": ["AAI009"],
      "OPC-011": ["AAI005"],
      "OPC-012": ["AAI009"],
      "QC-001": ["AAI001"],
      "QC-002": ["AAI001"],
      "QC-003": ["AAI012", "AAI001"],
      "QC-004": ["AAI007", "AAI012"],
      "QC-005": ["AAI001"],
      "QC-006": ["AAI009"],
      "QC-007": ["AAI009"],
      "QC-008": ["AAI012", "AAI001"],
      "QC-009": ["AAI011"],
      "QC-010": ["AAI006", "AAI003"]
    };
    AGENTIC_RISKS_IN_CATALOG = new Set(
      Object.values(CHECK_AGENTIC_MAP).flat()
    );
  }
});

// src/core/types.ts
function isScannableAgentType(v) {
  return v !== "mcp" && v !== "skill-audit" && AGENT_TYPES.includes(v);
}
var AGENT_TYPES, CHECK_CATEGORIES, CODING_AGENTS;
var init_types = __esm({
  "src/core/types.ts"() {
    "use strict";
    AGENT_TYPES = [
      "openclaw",
      "nanoclaw",
      "picoclaw",
      "mcp",
      "ironclaw",
      "nanobot",
      "zeroclaw",
      "nemoclaw",
      "hermes",
      "lyrie",
      "claude-code",
      "claude-desktop",
      "chatgpt-desktop",
      "codex",
      "opencode",
      "gemini-cli",
      "qwen-code",
      "copilot-cli",
      "cursor-cli",
      "skill-audit"
    ];
    CHECK_CATEGORIES = [
      "config",
      "skills",
      "ioc",
      "network",
      "runtime",
      "policy",
      "mcp",
      "openclaw",
      "nanoclaw",
      "ironclaw",
      "nanobot",
      "zeroclaw",
      "lyrie",
      "hermes",
      "advisory",
      "coding-agent"
    ];
    CODING_AGENTS = ["claude-code", "claude-desktop", "chatgpt-desktop", "codex", "opencode", "gemini-cli", "qwen-code", "copilot-cli", "cursor-cli"];
  }
});

// src/remediation/config-writer.ts
import { readFile as readFile2, writeFile as writeFile2, chmod } from "fs/promises";
import YAML2 from "yaml";
import { parse as parseTOML2, stringify as stringifyTOML } from "smol-toml";
async function updateEnvFile(filePath, key, value) {
  const content = await readFile2(filePath, "utf-8");
  const lines = content.split("\n");
  let found = false;
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) continue;
    const lineKey = trimmed.slice(0, eqIndex).trim();
    if (lineKey === key) {
      lines[i] = `${key}=${value}`;
      found = true;
      break;
    }
  }
  if (!found) {
    let insertIndex = lines.length;
    while (insertIndex > 0 && lines[insertIndex - 1].trim() === "") {
      insertIndex--;
    }
    lines.splice(insertIndex, 0, `${key}=${value}`);
  }
  await writeFile2(filePath, lines.join("\n"), "utf-8");
}
async function updateJsonFile(filePath, keyPath, value) {
  const content = await readFile2(filePath, "utf-8");
  const obj = JSON.parse(content);
  const indentMatch = content.match(/^(\s+)/m);
  const indent = indentMatch ? indentMatch[1].length : 2;
  setNestedValue(obj, keyPath, value);
  await writeFile2(filePath, JSON.stringify(obj, null, indent) + "\n", "utf-8");
}
async function updateYamlFile(filePath, keyPath, value) {
  const content = await readFile2(filePath, "utf-8");
  const doc = YAML2.parseDocument(content);
  const keys = keyPath.split(".");
  doc.setIn(keys, value);
  await writeFile2(filePath, doc.toString(), "utf-8");
}
async function updateTomlFile(filePath, keyPath, value) {
  const content = await readFile2(filePath, "utf-8");
  const obj = parseTOML2(content);
  setNestedValue(obj, keyPath, value);
  await writeFile2(filePath, stringifyTOML(obj) + "\n", "utf-8");
}
async function chmodFile(filePath, mode) {
  await chmod(filePath, mode);
}
async function updateConfigValue(config, keyPath, value) {
  switch (config.format) {
    case "env":
      await updateEnvFile(config.filePath, keyPath, String(value));
      break;
    case "json":
      await updateJsonFile(config.filePath, keyPath, value);
      break;
    case "yaml":
      await updateYamlFile(config.filePath, keyPath, value);
      break;
    case "toml":
      await updateTomlFile(config.filePath, keyPath, value);
      break;
    default:
      throw new Error(`Cannot write to config format: ${config.format}`);
  }
}
async function fixFirstConfig(configs, spec) {
  for (const config of configs) {
    if (config.format === "env") {
      if (spec.env === void 0) continue;
      await updateEnvFile(config.filePath, spec.env, spec.envValue ?? String(spec.value));
    } else if (config.format === "json" || config.format === "yaml" || config.format === "toml") {
      if (spec.path === void 0) continue;
      await updateConfigValue(config, spec.path, spec.value);
    } else {
      continue;
    }
    return { checkId: spec.checkId, applied: true, message: spec.message };
  }
  return {
    checkId: spec.checkId,
    applied: false,
    message: spec.noConfigMessage ?? "No compatible config file found"
  };
}
var init_config_writer = __esm({
  "src/remediation/config-writer.ts"() {
    "use strict";
    init_utils();
  }
});

// src/ioc/public-key.ts
var IOC_FEED_PUBLIC_KEY, DEFAULT_FEED_URL, DEFAULT_STALENESS_DAYS;
var init_public_key = __esm({
  "src/ioc/public-key.ts"() {
    "use strict";
    IOC_FEED_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJSmVPfCeHLycd5KGDiDBD0lwdK++oe4fVy6RmVedsm0=
-----END PUBLIC KEY-----`;
    DEFAULT_FEED_URL = "https://raw.githubusercontent.com/vulnex/vaso/main/feeds/feed.json";
    DEFAULT_STALENESS_DAYS = 7;
  }
});

// src/ioc/updater.ts
var updater_exports = {};
__export(updater_exports, {
  deserializeBinaryPatterns: () => deserializeBinaryPatterns,
  deserializePatterns: () => deserializePatterns,
  fetchAndUpdateFeed: () => fetchAndUpdateFeed,
  isFeedStale: () => isFeedStale,
  loadCachedFeed: () => loadCachedFeed,
  mergeFeedIntoDatabase: () => mergeFeedIntoDatabase,
  verifyFeedSignature: () => verifyFeedSignature
});
import { verify as cryptoVerify, createPublicKey } from "crypto";
import { existsSync, readFileSync } from "fs";
import { mkdir as mkdir2, readFile as readFile3, writeFile as writeFile3, unlink } from "fs/promises";
import { join as join32 } from "path";
import { homedir } from "os";
function verifyFeedSignature(feedBytes, sigBase64, publicKeyPem = IOC_FEED_PUBLIC_KEY) {
  try {
    const sig = Buffer.from(sigBase64, "base64");
    if (sig.length !== 64) return false;
    const keyObject = createPublicKey(publicKeyPem);
    return cryptoVerify(null, feedBytes, keyObject, sig);
  } catch {
    return false;
  }
}
function deserializePatterns(serialized) {
  return serialized.map((s) => new RegExp(s.source, s.flags ?? ""));
}
function deserializeBinaryPatterns(serialized) {
  return serialized.map((s) => {
    if (s.type === "buffer") {
      return { name: s.name, pattern: Buffer.from(s.pattern, "hex"), type: "buffer" };
    }
    return { name: s.name, pattern: new RegExp(s.pattern, s.flags ?? ""), type: "regex" };
  });
}
function dedupeStrings(base, additions) {
  const set = new Set(base);
  for (const item of additions) set.add(item);
  return [...set];
}
function dedupeRegExps(base, additions) {
  const seen = new Set(base.map((r) => `${r.source}|||${r.flags}`));
  const result = [...base];
  for (const r of additions) {
    const key = `${r.source}|||${r.flags}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(r);
    }
  }
  return result;
}
function dedupeBinaryPatterns(base, additions) {
  const seen = new Set(base.map((p) => `${p.name}|||${p.type}`));
  const result = [...base];
  for (const p of additions) {
    const key = `${p.name}|||${p.type}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(p);
    }
  }
  return result;
}
function mergeFeedIntoDatabase(bundled, feedData) {
  return {
    c2Ips: dedupeStrings(bundled.c2Ips, feedData.c2Ips ?? []),
    maliciousDomains: dedupeStrings(bundled.maliciousDomains, feedData.maliciousDomains ?? []),
    fileHashes: dedupeStrings(bundled.fileHashes, feedData.fileHashes ?? []),
    maliciousPublishers: dedupeStrings(bundled.maliciousPublishers, feedData.maliciousPublishers ?? []),
    maliciousSkillPatterns: dedupeRegExps(
      bundled.maliciousSkillPatterns,
      feedData.maliciousSkillPatterns ? deserializePatterns(feedData.maliciousSkillPatterns) : []
    ),
    trustedSkillNames: dedupeStrings(bundled.trustedSkillNames, feedData.trustedSkillNames ?? []),
    trustedMCPPackages: dedupeStrings(bundled.trustedMCPPackages, feedData.trustedMCPPackages ?? []),
    binaryPatterns: dedupeBinaryPatterns(
      bundled.binaryPatterns,
      feedData.binaryPatterns ? deserializeBinaryPatterns(feedData.binaryPatterns) : []
    )
  };
}
function isFeedStale(thresholdDays = DEFAULT_STALENESS_DAYS, metadataDir = IOC_DIR) {
  let raw;
  try {
    raw = readFileSync(join32(metadataDir, METADATA_FILE), "utf-8");
  } catch {
    return false;
  }
  try {
    const meta = JSON.parse(raw);
    const lastCheck = new Date(meta.lastCheckAt).getTime();
    if (isNaN(lastCheck)) return false;
    const ageMs = Date.now() - lastCheck;
    return ageMs > thresholdDays * 24 * 60 * 60 * 1e3;
  } catch {
    return false;
  }
}
async function loadCachedFeed(feedDir = IOC_DIR, publicKeyPem = IOC_FEED_PUBLIC_KEY) {
  try {
    const feedPath = join32(feedDir, FEED_FILE);
    const sigPath = join32(feedDir, SIG_FILE);
    let feedBytes;
    let sigContent;
    try {
      feedBytes = await readFile3(feedPath);
      sigContent = (await readFile3(sigPath, "utf-8")).trim();
    } catch {
      return null;
    }
    if (!verifyFeedSignature(feedBytes, sigContent, publicKeyPem)) {
      await unlink(feedPath).catch(() => {
      });
      await unlink(sigPath).catch(() => {
      });
      return null;
    }
    const feed = JSON.parse(feedBytes.toString("utf-8"));
    return feed.data;
  } catch {
    return null;
  }
}
async function fetchAndUpdateFeed(options = {}) {
  const feedUrl = options.feedUrl ?? DEFAULT_FEED_URL;
  const feedDir = options.feedDir ?? IOC_DIR;
  const publicKeyPem = options.publicKeyPem ?? IOC_FEED_PUBLIC_KEY;
  const force = options.force ?? false;
  await mkdir2(feedDir, { recursive: true });
  if (!force && existsSync(join32(feedDir, METADATA_FILE)) && !isFeedStale(DEFAULT_STALENESS_DAYS, feedDir)) {
    return { success: true, message: "Feed is up to date (not stale)." };
  }
  let currentVersion = 0;
  try {
    const metaRaw = await readFile3(join32(feedDir, METADATA_FILE), "utf-8");
    const meta = JSON.parse(metaRaw);
    currentVersion = meta.feedVersion;
  } catch {
  }
  let feedResponse;
  let sigResponse;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      [feedResponse, sigResponse] = await Promise.all([
        fetch(feedUrl, { signal: controller.signal }),
        fetch(feedUrl + ".sig", { signal: controller.signal })
      ]);
    } finally {
      clearTimeout(timeout);
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, message: `Failed to fetch feed: ${msg}` };
  }
  if (!feedResponse.ok) {
    return { success: false, message: `Feed fetch failed: HTTP ${feedResponse.status}` };
  }
  if (!sigResponse.ok) {
    return { success: false, message: `Signature fetch failed: HTTP ${sigResponse.status}` };
  }
  const feedBytes = Buffer.from(await feedResponse.arrayBuffer());
  const sigBase64 = (await sigResponse.text()).trim();
  let feed;
  try {
    feed = JSON.parse(feedBytes.toString("utf-8"));
    if (!feed.meta || typeof feed.meta.version !== "number" || !feed.data) {
      return { success: false, message: "Invalid feed format: missing meta or data fields." };
    }
  } catch {
    return { success: false, message: "Invalid feed JSON." };
  }
  if (feed.meta.version <= currentVersion && !force) {
    return {
      success: true,
      message: `Feed version ${feed.meta.version} is not newer than cached version ${currentVersion}.`
    };
  }
  if (!verifyFeedSignature(feedBytes, sigBase64, publicKeyPem)) {
    return { success: false, message: "Feed signature verification failed." };
  }
  await writeFile3(join32(feedDir, FEED_FILE), feedBytes);
  await writeFile3(join32(feedDir, SIG_FILE), sigBase64);
  const metadata = {
    lastUpdated: (/* @__PURE__ */ new Date()).toISOString(),
    feedVersion: feed.meta.version,
    feedUrl,
    lastCheckAt: (/* @__PURE__ */ new Date()).toISOString()
  };
  await writeFile3(join32(feedDir, METADATA_FILE), JSON.stringify(metadata, null, 2));
  const data = feed.data;
  const newIndicators = {
    c2Ips: data.c2Ips?.length ?? 0,
    maliciousDomains: data.maliciousDomains?.length ?? 0,
    fileHashes: data.fileHashes?.length ?? 0,
    maliciousPublishers: data.maliciousPublishers?.length ?? 0,
    maliciousSkillPatterns: data.maliciousSkillPatterns?.length ?? 0,
    trustedSkillNames: data.trustedSkillNames?.length ?? 0,
    trustedMCPPackages: data.trustedMCPPackages?.length ?? 0,
    binaryPatterns: data.binaryPatterns?.length ?? 0
  };
  return {
    success: true,
    message: `Feed updated to version ${feed.meta.version}.`,
    newIndicators,
    feedVersion: feed.meta.version
  };
}
var IOC_DIR, FEED_FILE, SIG_FILE, METADATA_FILE, FETCH_TIMEOUT_MS;
var init_updater = __esm({
  "src/ioc/updater.ts"() {
    "use strict";
    init_public_key();
    IOC_DIR = join32(homedir(), ".vaso", "ioc");
    FEED_FILE = "feed.json";
    SIG_FILE = "feed.json.sig";
    METADATA_FILE = "metadata.json";
    FETCH_TIMEOUT_MS = 15e3;
  }
});

// src/ioc/database.ts
function buildBundledDatabase() {
  return {
    c2Ips: [...C2_IPS],
    maliciousDomains: [...MALICIOUS_DOMAINS],
    fileHashes: [...FILE_HASHES],
    maliciousPublishers: [...MALICIOUS_PUBLISHERS],
    maliciousSkillPatterns: [...MALICIOUS_SKILL_PATTERNS],
    trustedSkillNames: [...TRUSTED_SKILL_NAMES],
    trustedMCPPackages: [...TRUSTED_MCP_PACKAGES],
    binaryPatterns: [...BINARY_PATTERNS]
  };
}
async function initIOCDatabase() {
  if (_initialized) return;
  const bundled = buildBundledDatabase();
  try {
    const { loadCachedFeed: loadCachedFeed2, mergeFeedIntoDatabase: mergeFeedIntoDatabase2 } = await Promise.resolve().then(() => (init_updater(), updater_exports));
    const feedData = await loadCachedFeed2();
    if (feedData) {
      _db = mergeFeedIntoDatabase2(bundled, feedData);
    } else {
      _db = bundled;
    }
  } catch {
    _db = bundled;
  }
  _initialized = true;
}
function getIOCDatabase() {
  if (!_db) {
    _db = buildBundledDatabase();
  }
  return _db;
}
function reloadIOCDatabase() {
  _db = null;
  _initialized = false;
}
var C2_IPS, MALICIOUS_DOMAINS, FILE_HASHES, MALICIOUS_PUBLISHERS, MALICIOUS_SKILL_PATTERNS, TRUSTED_SKILL_NAMES, BINARY_PATTERNS, TRUSTED_MCP_PACKAGES, _db, _initialized;
var init_database = __esm({
  "src/ioc/database.ts"() {
    "use strict";
    C2_IPS = [
      "185.199.228.220",
      "45.33.32.156",
      "198.51.100.1",
      "203.0.113.42",
      "192.0.2.100"
    ];
    MALICIOUS_DOMAINS = [
      "clawhavoc.io",
      "claw-payload.net",
      "openclaw-update.xyz",
      "skill-cdn.ru",
      "agent-tools.cc",
      "clawbot-plugins.tk",
      "ai-agent-free.ml",
      "openclaw-crack.ga",
      "skillhub-mirror.cf"
    ];
    FILE_HASHES = [
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      // empty file
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
      // AMOS stealer v1
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
      // AMOS stealer v2
      "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
      // ClawHavoc dropper
    ];
    MALICIOUS_PUBLISHERS = [
      "clawhavoc",
      "bloom-security",
      "openclaw-official-tools",
      "free-claw-plugins",
      "ai-toolbox-pro",
      "claw-community-contrib",
      "skill-marketplace-bot",
      "agent-extensions-free",
      "opensource-malware-test",
      // Confirmed-malware OpenClaw skill publishers, sourced from the Agent Threat
      // Rules public blacklist (github.com/Agent-Threat-Rule/agent-threat-rules,
      // data/public-blacklist.json, 2026-04-16; MIT-licensed). These three named
      // threat actors account for all 552 confirmed-malware skills in that dataset
      // (hightower6eu: 354, sakaen736jih: 198); matching on publisher via IOC-004
      // flags every skill they ship, not just individually enumerated names.
      "hightower6eu",
      "sakaen736jih",
      "52yuanchangxing"
    ];
    MALICIOUS_SKILL_PATTERNS = [
      /claw.*havoc/i,
      /openclaw.*crack/i,
      /free.*premium/i,
      /hack.*tool/i,
      /stealer/i,
      /keylog/i,
      /rat[-_]?tool/i,
      /backdoor/i,
      /trojan/i,
      /miner[-_]?skill/i
    ];
    TRUSTED_SKILL_NAMES = [
      "filesystem",
      "web-search",
      "calculator",
      "calendar",
      "weather",
      "translator",
      "code-runner",
      "database-query",
      "email-sender",
      "slack-bot",
      "github-helper",
      "docker-manager",
      "kubernetes-admin",
      "aws-cli",
      "gcp-tools",
      "azure-helper",
      "openai-chat",
      "image-generator",
      "pdf-reader",
      "markdown-editor"
    ];
    BINARY_PATTERNS = [
      { name: "ELF binary", pattern: Buffer.from([127, 69, 76, 70]), type: "buffer" },
      { name: "Mach-O 64-bit binary", pattern: Buffer.from([207, 250, 237, 254]), type: "buffer" },
      { name: "Mach-O 32-bit binary", pattern: Buffer.from([206, 250, 237, 254]), type: "buffer" },
      { name: "PE/DOS executable", pattern: Buffer.from([77, 90]), type: "buffer" },
      { name: "NUL-padding shellcode", pattern: /\x00{16,}/, type: "regex" },
      { name: "Packed JS eval wrapper", pattern: /eval\(function\(p,a,c,k,e/, type: "regex" }
    ];
    TRUSTED_MCP_PACKAGES = [
      "@modelcontextprotocol/server-filesystem",
      "@modelcontextprotocol/server-github",
      "@modelcontextprotocol/server-gitlab",
      "@modelcontextprotocol/server-google-maps",
      "@modelcontextprotocol/server-memory",
      "@modelcontextprotocol/server-postgres",
      "@modelcontextprotocol/server-puppeteer",
      "@modelcontextprotocol/server-sequentialthinker",
      "@modelcontextprotocol/server-slack",
      "@modelcontextprotocol/server-sqlite",
      "@modelcontextprotocol/server-brave-search",
      "@modelcontextprotocol/server-fetch",
      "@modelcontextprotocol/server-everything",
      "mcp-server-fetch",
      "mcp-server-sqlite",
      "mcp-server-filesystem"
    ];
    _db = null;
    _initialized = false;
  }
});

// src/mcp/tool-baseline.ts
import { createHash as createHash3 } from "crypto";
import { mkdir as mkdir3, readFile as readFile4, writeFile as writeFile4 } from "fs/promises";
import { join as join40 } from "path";
import { homedir as homedir2 } from "os";
function defaultBaselineStore() {
  return new FileToolBaselineStore(join40(homedir2(), ".vaso", "mcp-tool-baselines"));
}
function sourceIdentity(source) {
  return source.localPath ?? source.packageName ?? source.serverName;
}
function baselineKey(source, hostname) {
  const identity = sourceIdentity(source);
  const hash = createHash3("sha256").update(identity).update("|").update(source.serverName).update("|").update(hostname ?? "").digest("hex").slice(0, 16);
  const slug = source.serverName.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 32);
  return `${slug}-${hash}`;
}
function hashToolDefinition(tool) {
  const payload = JSON.stringify({
    name: tool.name,
    description: tool.description ?? "",
    schema: tool.schema ?? ""
  });
  return createHash3("sha256").update(payload).digest("hex");
}
function toolsToHashMap(tools) {
  const map = {};
  for (const tool of tools) {
    map[tool.name] = hashToolDefinition(tool);
  }
  return map;
}
function makeBaseline(source, tools) {
  return {
    serverName: source.serverName,
    identity: sourceIdentity(source),
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    tools: toolsToHashMap(tools)
  };
}
async function diffToolBaseline(store, source, currentTools, hostname) {
  const key = baselineKey(source, hostname);
  const existing = await store.load(key);
  const baseline = makeBaseline(source, currentTools);
  if (!existing) {
    await store.save(key, baseline);
    return {
      diff: { changed: [], added: [], removed: [] },
      isFirstScan: true
    };
  }
  const diff = { changed: [], added: [], removed: [] };
  for (const [name, hash] of Object.entries(baseline.tools)) {
    if (name in existing.tools) {
      if (existing.tools[name] !== hash) {
        diff.changed.push({ name, oldHash: existing.tools[name], newHash: hash });
      }
    } else {
      diff.added.push(name);
    }
  }
  for (const name of Object.keys(existing.tools)) {
    if (!(name in baseline.tools)) {
      diff.removed.push(name);
    }
  }
  await store.save(key, baseline);
  return { diff, isFirstScan: false };
}
function extractToolDefinitions(sourceCode) {
  const byName = /* @__PURE__ */ new Map();
  const record = (name, description, schema) => {
    const existing = byName.get(name);
    if (!existing) {
      byName.set(name, { name, description, schema });
      return;
    }
    if (description && !existing.description) existing.description = description;
    if (schema && !existing.schema) existing.schema = schema;
  };
  const runPattern = (re, hasSchema = false) => {
    let match;
    while ((match = re.exec(sourceCode)) !== null) {
      record(match[1], match[2] ?? void 0, hasSchema ? match[3] ?? void 0 : void 0);
    }
  };
  runPattern(/\.tool\(\s*['"]([^'"]+)['"]\s*(?:,\s*['"]((?:[^'"\\]|\\.)*)['"]\s*)?(?:,\s*(\{[^}]*\})\s*)?/g, true);
  runPattern(/addTool\(\s*\{[^}]*name:\s*['"]([^'"]+)['"][^}]*(?:description:\s*['"]((?:[^'"\\]|\\.)*?)['"])?/g);
  runPattern(/register[_]?[Tt]ool\(\s*['"]([^'"]+)['"]\s*(?:,\s*['"]((?:[^'"\\]|\\.)*?)['"])?/g);
  runPattern(/\{\s*name:\s*['"]([^'"]+)['"](?:\s*,\s*description:\s*['"]((?:[^'"\\]|\\.)*?)['"])?[^}]*handler\s*:/g);
  runPattern(/(?:const|let|var)\s+(?:tool)?[Nn]ame\s*=\s*['"]([^'"]+)['"][\s\S]{0,400}?\bdescription\s*:\s*['"]((?:[^'"\\]|\\.)*?)['"]/g);
  runPattern(/(?:register[_]?[Tt]ool|\.tool)\(\s*['"]([^'"]+)['"]\s*,\s*\{[\s\S]{0,400}?\bdescription\s*:\s*['"]((?:[^'"\\]|\\.)*?)['"]/g);
  runPattern(/\bname\s*:\s*['"]([^'"]+)['"][\s\S]{0,200}?\bdescription\s*:\s*['"]((?:[^'"\\]|\\.)*?)['"]/g);
  return [...byName.values()];
}
function extractPromptNames(sourceCode) {
  const names = /* @__PURE__ */ new Set();
  const add = (n) => {
    if (n) names.add(n);
  };
  let match;
  const inlineRe = /(?:registerPrompt|\.prompt)\(\s*['"]([^'"]+)['"]/g;
  while ((match = inlineRe.exec(sourceCode)) !== null) add(match[1]);
  const sepRe = /(?:const|let|var)\s+(?:prompt)?[Nn]ame\s*=\s*['"]([^'"]+)['"][\s\S]{0,400}?registerPrompt\(/g;
  while ((match = sepRe.exec(sourceCode)) !== null) add(match[1]);
  return [...names];
}
var FileToolBaselineStore;
var init_tool_baseline = __esm({
  "src/mcp/tool-baseline.ts"() {
    "use strict";
    FileToolBaselineStore = class {
      constructor(baseDir) {
        this.baseDir = baseDir;
      }
      async load(key) {
        try {
          const raw = await readFile4(join40(this.baseDir, `${key}.json`), "utf-8");
          return JSON.parse(raw);
        } catch {
          return null;
        }
      }
      async save(key, baseline) {
        await mkdir3(this.baseDir, { recursive: true });
        await writeFile4(join40(this.baseDir, `${key}.json`), JSON.stringify(baseline, null, 2), "utf-8");
      }
    };
  }
});

// src/advisory/updater.ts
var updater_exports2 = {};
__export(updater_exports2, {
  DEFAULT_ADVISORY_FEED_URL: () => DEFAULT_ADVISORY_FEED_URL,
  fetchAndUpdateAdvisoryFeed: () => fetchAndUpdateAdvisoryFeed,
  isAdvisoryFeedStale: () => isAdvisoryFeedStale,
  loadCachedAdvisoryFeed: () => loadCachedAdvisoryFeed,
  mergeAdvisoryFeed: () => mergeAdvisoryFeed
});
import { existsSync as existsSync2, readFileSync as readFileSync2 } from "fs";
import { mkdir as mkdir4, readFile as readFile5, writeFile as writeFile5, unlink as unlink2 } from "fs/promises";
import { join as join41 } from "path";
import { homedir as homedir3 } from "os";
function mergeAdvisoryFeed(bundled, feedData) {
  const byId = /* @__PURE__ */ new Map();
  for (const adv of bundled.advisories) {
    byId.set(adv.id, adv);
  }
  for (const adv of feedData.advisories) {
    byId.set(adv.id, adv);
  }
  return { advisories: [...byId.values()] };
}
function isAdvisoryFeedStale(thresholdDays = DEFAULT_STALENESS_DAYS, metadataDir = ADVISORY_DIR) {
  let raw;
  try {
    raw = readFileSync2(join41(metadataDir, METADATA_FILE2), "utf-8");
  } catch {
    return false;
  }
  try {
    const meta = JSON.parse(raw);
    const lastCheck = new Date(meta.lastCheckAt).getTime();
    if (isNaN(lastCheck)) return false;
    const ageMs = Date.now() - lastCheck;
    return ageMs > thresholdDays * 24 * 60 * 60 * 1e3;
  } catch {
    return false;
  }
}
async function loadCachedAdvisoryFeed(feedDir = ADVISORY_DIR, publicKeyPem = IOC_FEED_PUBLIC_KEY) {
  try {
    const feedPath = join41(feedDir, FEED_FILE2);
    const sigPath = join41(feedDir, SIG_FILE2);
    let feedBytes;
    let sigContent;
    try {
      feedBytes = await readFile5(feedPath);
      sigContent = (await readFile5(sigPath, "utf-8")).trim();
    } catch {
      return null;
    }
    if (!verifyFeedSignature(feedBytes, sigContent, publicKeyPem)) {
      await unlink2(feedPath).catch(() => {
      });
      await unlink2(sigPath).catch(() => {
      });
      return null;
    }
    const feed = JSON.parse(feedBytes.toString("utf-8"));
    return feed.data;
  } catch {
    return null;
  }
}
async function fetchAndUpdateAdvisoryFeed(options = {}) {
  const feedUrl = options.feedUrl ?? DEFAULT_ADVISORY_FEED_URL;
  const feedDir = options.feedDir ?? ADVISORY_DIR;
  const publicKeyPem = options.publicKeyPem ?? IOC_FEED_PUBLIC_KEY;
  const force = options.force ?? false;
  await mkdir4(feedDir, { recursive: true });
  if (!force && existsSync2(join41(feedDir, METADATA_FILE2)) && !isAdvisoryFeedStale(DEFAULT_STALENESS_DAYS, feedDir)) {
    return { success: true, message: "Advisory feed is up to date (not stale)." };
  }
  let currentVersion = 0;
  try {
    const metaRaw = await readFile5(join41(feedDir, METADATA_FILE2), "utf-8");
    const meta = JSON.parse(metaRaw);
    currentVersion = meta.feedVersion;
  } catch {
  }
  let feedResponse;
  let sigResponse;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS2);
    try {
      [feedResponse, sigResponse] = await Promise.all([
        fetch(feedUrl, { signal: controller.signal }),
        fetch(feedUrl + ".sig", { signal: controller.signal })
      ]);
    } finally {
      clearTimeout(timeout);
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, message: `Failed to fetch advisory feed: ${msg}` };
  }
  if (!feedResponse.ok) {
    return { success: false, message: `Advisory feed fetch failed: HTTP ${feedResponse.status}` };
  }
  if (!sigResponse.ok) {
    return { success: false, message: `Advisory signature fetch failed: HTTP ${sigResponse.status}` };
  }
  const feedBytes = Buffer.from(await feedResponse.arrayBuffer());
  const sigBase64 = (await sigResponse.text()).trim();
  let feed;
  try {
    feed = JSON.parse(feedBytes.toString("utf-8"));
    if (!feed.meta || typeof feed.meta.version !== "number" || !feed.data) {
      return { success: false, message: "Invalid advisory feed format." };
    }
  } catch {
    return { success: false, message: "Invalid advisory feed JSON." };
  }
  if (feed.meta.version <= currentVersion && !force) {
    return {
      success: true,
      message: `Advisory feed version ${feed.meta.version} is not newer than cached version ${currentVersion}.`
    };
  }
  if (!verifyFeedSignature(feedBytes, sigBase64, publicKeyPem)) {
    return { success: false, message: "Advisory feed signature verification failed." };
  }
  await writeFile5(join41(feedDir, FEED_FILE2), feedBytes);
  await writeFile5(join41(feedDir, SIG_FILE2), sigBase64);
  const metadata = {
    lastUpdated: (/* @__PURE__ */ new Date()).toISOString(),
    feedVersion: feed.meta.version,
    feedUrl,
    lastCheckAt: (/* @__PURE__ */ new Date()).toISOString()
  };
  await writeFile5(join41(feedDir, METADATA_FILE2), JSON.stringify(metadata, null, 2));
  return {
    success: true,
    message: `Advisory feed updated to version ${feed.meta.version}.`,
    newAdvisories: feed.data.advisories.length,
    feedVersion: feed.meta.version
  };
}
var ADVISORY_DIR, FEED_FILE2, SIG_FILE2, METADATA_FILE2, FETCH_TIMEOUT_MS2, DEFAULT_ADVISORY_FEED_URL;
var init_updater2 = __esm({
  "src/advisory/updater.ts"() {
    "use strict";
    init_updater();
    init_public_key();
    ADVISORY_DIR = join41(homedir3(), ".vaso", "advisory");
    FEED_FILE2 = "advisory-feed.json";
    SIG_FILE2 = "advisory-feed.json.sig";
    METADATA_FILE2 = "metadata.json";
    FETCH_TIMEOUT_MS2 = 15e3;
    DEFAULT_ADVISORY_FEED_URL = "https://raw.githubusercontent.com/vulnex/vaso/main/feeds/advisory-feed.json";
  }
});

// src/advisory/database.ts
function buildBundledAdvisoryDatabase() {
  return {
    advisories: [...BUNDLED_ADVISORIES]
  };
}
async function initAdvisoryDatabase() {
  if (_initialized2) return;
  const bundled = buildBundledAdvisoryDatabase();
  try {
    const { loadCachedAdvisoryFeed: loadCachedAdvisoryFeed2, mergeAdvisoryFeed: mergeAdvisoryFeed2 } = await Promise.resolve().then(() => (init_updater2(), updater_exports2));
    const feedData = await loadCachedAdvisoryFeed2();
    if (feedData) {
      _db2 = mergeAdvisoryFeed2(bundled, feedData);
    } else {
      _db2 = bundled;
    }
  } catch {
    _db2 = bundled;
  }
  _initialized2 = true;
}
function getAdvisoryDatabase() {
  if (!_db2) {
    _db2 = buildBundledAdvisoryDatabase();
  }
  return _db2;
}
function reloadAdvisoryDatabase() {
  _db2 = null;
  _initialized2 = false;
}
var BUNDLED_ADVISORIES, _db2, _initialized2;
var init_database2 = __esm({
  "src/advisory/database.ts"() {
    "use strict";
    BUNDLED_ADVISORIES = [
      // ── OpenClaw ──────────────────────────────────────────────────────
      {
        id: "CVE-2026-40001",
        title: "OpenClaw gateway authentication bypass",
        agent: "openclaw",
        affectedVersions: ">=1.0.0 <1.5.3",
        fixedVersion: "1.5.3",
        severity: "critical",
        description: "Gateway auth middleware can be bypassed with crafted HTTP headers, allowing unauthenticated skill execution.",
        reference: "https://github.com/vulnex/vaso-advisories/blob/main/CVE-2026-40001.md",
        published: "2026-01-15",
        exploitAvailable: true,
        tags: ["framework"]
      },
      {
        id: "CVE-2026-40002",
        title: "OpenClaw sub-agent config injection",
        agent: "openclaw",
        affectedVersions: ">=1.2.0 <1.4.7",
        fixedVersion: "1.4.7",
        severity: "warning",
        description: "Sub-agent configuration values are not properly sanitized, allowing config injection via crafted profile names.",
        reference: "https://github.com/vulnex/vaso-advisories/blob/main/CVE-2026-40002.md",
        published: "2026-02-01",
        tags: ["framework"]
      },
      {
        id: "CVE-2026-40003",
        title: "OpenClaw skill sandbox escape via symlink",
        agent: "openclaw",
        affectedVersions: ">=1.0.0 <1.6.0",
        fixedVersion: "1.6.0",
        severity: "critical",
        description: "Skills can escape the sandbox by creating symlinks to files outside the workspace directory.",
        published: "2026-02-10",
        exploitAvailable: true,
        tags: ["framework"]
      },
      {
        id: "VASO-EOL-OC-100",
        title: "OpenClaw 0.x end-of-life",
        agent: "openclaw",
        affectedVersions: ">=0.0.0 <1.0.0",
        severity: "warning",
        description: "OpenClaw 0.x is end-of-life and no longer receives security patches. Upgrade to 1.x or later.",
        published: "2025-06-01",
        eolNotice: true,
        tags: ["framework"]
      },
      // ── NanoClaw ──────────────────────────────────────────────────────
      {
        id: "CVE-2026-40010",
        title: "NanoClaw container mount escape",
        agent: "nanoclaw",
        affectedVersions: ">=2.0.0 <2.3.1",
        fixedVersion: "2.3.1",
        severity: "critical",
        description: "Container mount allowlist can be bypassed using path traversal, allowing access to host filesystem.",
        reference: "https://github.com/vulnex/vaso-advisories/blob/main/CVE-2026-40010.md",
        published: "2026-01-20",
        exploitAvailable: true,
        tags: ["framework"]
      },
      {
        id: "CVE-2026-40011",
        title: "NanoClaw env variable leak in logs",
        agent: "nanoclaw",
        affectedVersions: ">=2.0.0 <2.2.0",
        fixedVersion: "2.2.0",
        severity: "warning",
        description: "Environment variables including API keys are written to debug logs in plaintext.",
        published: "2026-01-05",
        tags: ["framework"]
      },
      // ── PicoClaw ──────────────────────────────────────────────────────
      {
        id: "CVE-2026-40020",
        title: "PicoClaw gateway TLS downgrade",
        agent: "picoclaw",
        affectedVersions: ">=0.1.0 <0.5.2",
        fixedVersion: "0.5.2",
        severity: "critical",
        description: "TLS connections can be downgraded to plaintext via MITM, exposing gateway traffic.",
        published: "2026-02-15",
        tags: ["framework"]
      },
      // ── IronClaw ──────────────────────────────────────────────────────
      {
        id: "CVE-2026-40030",
        title: "IronClaw TOML injection in config parser",
        agent: "ironclaw",
        affectedVersions: ">=0.1.0 <0.4.0",
        fixedVersion: "0.4.0",
        severity: "critical",
        description: "TOML config parser does not properly escape user-controlled values, allowing injection of arbitrary config keys.",
        reference: "https://github.com/vulnex/vaso-advisories/blob/main/CVE-2026-40030.md",
        published: "2026-01-10",
        exploitAvailable: true,
        tags: ["framework"]
      },
      {
        id: "CVE-2026-40031",
        title: "IronClaw gRPC gateway unauthenticated reflection",
        agent: "ironclaw",
        affectedVersions: ">=0.1.0 <0.3.5",
        fixedVersion: "0.3.5",
        severity: "warning",
        description: "gRPC server reflection is enabled by default, leaking service and method definitions to unauthenticated clients.",
        published: "2026-02-05",
        tags: ["framework"]
      },
      // ── Nanobot ───────────────────────────────────────────────────────
      {
        id: "CVE-2026-40040",
        title: "Nanobot Discord message injection",
        agent: "nanobot",
        affectedVersions: ">=1.0.0 <1.4.0",
        fixedVersion: "1.4.0",
        severity: "critical",
        description: "Discord message handler does not sanitize input, allowing injection of bot commands via crafted messages.",
        published: "2026-01-25",
        tags: ["framework"]
      },
      {
        id: "CVE-2026-40041",
        title: "Nanobot shell command filter bypass",
        agent: "nanobot",
        affectedVersions: ">=1.0.0 <1.3.5",
        fixedVersion: "1.3.5",
        severity: "critical",
        description: "Shell command filter can be bypassed using backtick substitution, allowing arbitrary command execution.",
        published: "2026-02-12",
        exploitAvailable: true,
        tags: ["framework"]
      },
      // ── ZeroClaw ──────────────────────────────────────────────────────
      {
        id: "CVE-2026-40050",
        title: "ZeroClaw auth key leak via debug endpoint",
        agent: "zeroclaw",
        affectedVersions: ">=0.1.0 <0.2.4",
        fixedVersion: "0.2.4",
        severity: "critical",
        description: "Debug endpoint exposes authentication keys in response headers when debug mode is enabled.",
        reference: "https://github.com/vulnex/vaso-advisories/blob/main/CVE-2026-40050.md",
        published: "2026-01-30",
        exploitAvailable: true,
        tags: ["framework"]
      },
      {
        id: "CVE-2026-40051",
        title: "ZeroClaw Composio integration path traversal",
        agent: "zeroclaw",
        affectedVersions: ">=0.1.0 <0.3.0",
        fixedVersion: "0.3.0",
        severity: "warning",
        description: "Composio tool integration allows path traversal in tool names, enabling access to files outside the workspace.",
        published: "2026-02-08",
        tags: ["framework"]
      },
      // ── Dependency advisories ─────────────────────────────────────────
      {
        id: "CVE-2026-40100",
        title: "ws (WebSocket) denial-of-service via crafted frame",
        agent: "*",
        affectedVersions: ">=0.0.0",
        severity: "warning",
        description: "The ws package before 8.17.1 is vulnerable to DoS via specially crafted WebSocket frames.",
        published: "2026-01-08",
        tags: ["dependency"],
        affectedDependency: { name: "ws", versionConstraint: ">=0.0.0 <8.17.1" }
      },
      // ── MCP package advisories ────────────────────────────────────────
      // Matched by MCP-027 against pinned `npx pkg@version` server specs.
      // First published in advisory feed v2 (2026-07-10); folded into the
      // bundle so fresh installs get them without `vaso update`.
      {
        id: "CVE-2025-6514",
        title: "mcp-remote OS command injection via malicious MCP server (RCE)",
        agent: "mcp",
        affectedVersions: ">=0.0.5 <0.1.16",
        fixedVersion: "0.1.16",
        severity: "critical",
        description: "A malicious or compromised remote MCP server can return a crafted authorization_endpoint URL during OAuth flow initialization; mcp-remote passes it to open(), resulting in arbitrary OS command execution on the connecting client (full parameter control on Windows via PowerShell subexpression evaluation; arbitrary executable launch on macOS/Linux). CVSS 9.6.",
        reference: "https://github.com/advisories/GHSA-6xpm-ggf7-wc3p",
        published: "2025-07-09",
        exploitAvailable: true,
        tags: ["mcp", "cve", "rce"],
        affectedDependency: { name: "mcp-remote", versionConstraint: ">=0.0.5 <0.1.16" }
      },
      {
        id: "CVE-2025-49596",
        title: "MCP Inspector proxy missing authentication enables browser-based RCE",
        agent: "mcp",
        affectedVersions: "<0.14.1",
        fixedVersion: "0.14.1",
        severity: "critical",
        description: "The MCP Inspector proxy accepted unauthenticated requests to launch MCP commands over stdio; a malicious website visited by the developer could reach the locally-running proxy (CSRF / 0.0.0.0-day / DNS rebinding) and execute arbitrary code on the host. Fixed in 0.14.1 with a default proxy session token and allowed-origin verification. CVSS 9.4.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2025-49596",
        published: "2025-06-13",
        exploitAvailable: true,
        tags: ["mcp", "cve", "rce"],
        affectedDependency: { name: "@modelcontextprotocol/inspector", versionConstraint: "<0.14.1" }
      },
      {
        id: "CVE-2025-53109",
        title: "Filesystem MCP server symlink bypass grants full filesystem access (EscapeRoute)",
        agent: "mcp",
        affectedVersions: ">=0.2.0 <2025.7.1",
        fixedVersion: "2025.7.1",
        severity: "critical",
        description: "Symbolic-link checks in @modelcontextprotocol/server-filesystem fall back to parent-directory validation, so a symlink pointing outside the allowed roots grants read/write access to the entire filesystem, escalating to code execution via LaunchAgents/cron. No fixed 0.x release was published \u2014 upgrade to 2025.7.1 or later. CVSS 8.4.",
        reference: "https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/",
        published: "2025-07-01",
        exploitAvailable: true,
        tags: ["mcp", "cve", "sandbox-escape"],
        affectedDependency: { name: "@modelcontextprotocol/server-filesystem", versionConstraint: ">=0.2.0 <2025.7.1" }
      },
      {
        id: "CVE-2025-53110",
        title: "Filesystem MCP server directory containment bypass via prefix match (EscapeRoute)",
        agent: "mcp",
        affectedVersions: ">=0.2.0 <2025.7.1",
        fixedVersion: "2025.7.1",
        severity: "warning",
        description: "Path validation in @modelcontextprotocol/server-filesystem used a naive string-prefix check, so any path that merely starts with an allowed directory string (e.g. /tmp/allowed_dir-evil next to /tmp/allowed_dir) is treated as in scope, allowing listing, reading, and writing outside the configured sandbox. CVSS 7.3.",
        reference: "https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/",
        published: "2025-07-01",
        tags: ["mcp", "cve", "sandbox-escape"],
        affectedDependency: { name: "@modelcontextprotocol/server-filesystem", versionConstraint: ">=0.2.0 <2025.7.1" }
      },
      {
        id: "VASO-MAL-2025-001",
        title: "postmark-mcp npm package backdoored \u2014 BCC exfiltration of all outgoing email",
        agent: "mcp",
        affectedVersions: ">=1.0.16",
        severity: "critical",
        description: "The postmark-mcp npm package impersonated Postmark Labs' MCP server; version 1.0.16 added a hidden BCC of every email sent through the server to an attacker address at giftshop.club (first confirmed malicious MCP server in the wild, Koi Security). The package was removed from npm; any remaining install at 1.0.16 or later is backdoored and should be removed, and mail credentials rotated. There is no fixed version \u2014 use the official Postmark-published server instead.",
        reference: "https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft",
        published: "2025-09-26",
        tags: ["mcp", "malicious-package", "supply-chain"],
        affectedDependency: { name: "postmark-mcp", versionConstraint: ">=1.0.16" }
      },
      {
        // Sourced from Agent Threat Rules ATR-2026-01931 (github.com/Agent-Threat-Rule/agent-threat-rules,
        // MIT-licensed); version range per the rule's description and GHSA.
        id: "CVE-2026-0755",
        title: "gemini-mcp-tool command injection + @file exfiltration (RCE)",
        agent: "mcp",
        affectedVersions: ">=1.1.2 <1.1.6",
        fixedVersion: "1.1.6",
        severity: "critical",
        description: "The gemini-mcp-tool npm MCP server passes user-controlled prompt text to the OS shell via execAsync without neutralising metacharacters (CWE-78), so a prompt carrying ;, |, $(), backticks, or && achieves unauthenticated RCE (CVSS 9.8). Its Gemini CLI @file parser also dereferences attacker-supplied @-paths, exfiltrating arbitrary local files (@~/.ssh/id_rsa, @~/.aws/credentials, @/etc/passwd). Upgrade to 1.1.6+.",
        reference: "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/tool-poisoning/ATR-2026-01931-gemini-mcp-tool-command-injection-file-exfil.yaml",
        published: "2026-01-01",
        exploitAvailable: true,
        tags: ["mcp", "cve", "rce"],
        affectedDependency: { name: "gemini-mcp-tool", versionConstraint: ">=1.1.2 <1.1.6" }
      },
      // ── Config-pattern advisory ───────────────────────────────────────
      {
        id: "VASO-CFG-2026-001",
        title: "Dangerous auto_approve_tools wildcard pattern",
        agent: "*",
        affectedVersions: ">=0.0.0",
        severity: "critical",
        description: 'Setting auto_approve_tools to "*" or "all" disables tool approval, allowing unrestricted tool execution.',
        published: "2025-12-01",
        tags: ["config"],
        configPattern: { key: "auto_approve_tools", valuePattern: "^(\\*|all)$" }
      },
      // ── Coding-agent advisories (GhostApproval, Wiz 2026-07-08) ────────
      // Symlink-following (CWE-61) + confirmation-prompt misrepresentation
      // (CWE-451) let a malicious repo trick an assistant into writing outside
      // the workspace (SSH keys, shell rc). Version-based arm complements the
      // static artifact detector SKL-013. https://www.wiz.io/blog/ghostapproval-a-trust-boundary-gap-in-ai-coding-assistants
      {
        id: "CVE-2026-50549",
        title: "Cursor GhostApproval symlink-write sandbox bypass",
        agent: "cursor-cli",
        affectedVersions: "<3.0.0",
        fixedVersion: "3.0.0",
        severity: "critical",
        description: 'The diff UI displays the in-workspace symlink path while the backend follows the link and writes to its resolved target on Accept, so an approved "local" edit can write to ~/.ssh/authorized_keys or a shell rc file (GhostApproval, CWE-61 + CWE-451).',
        reference: "https://www.wiz.io/blog/ghostapproval-a-trust-boundary-gap-in-ai-coding-assistants",
        published: "2026-07-08",
        exploitAvailable: true,
        tags: ["coding-agent", "symlink", "ghostapproval"]
      },
      {
        id: "VASO-GHOSTAPPROVAL-CC",
        title: "Claude Code symlink target not surfaced in edit confirmation",
        agent: "claude-code",
        affectedVersions: "<2.1.32",
        fixedVersion: "2.1.32",
        severity: "warning",
        description: "Before v2.1.32, the Edit/Write permission dialog showed the in-workspace filename while the agent resolved a symlink to a sensitive target, so users approved edits whose real destination was hidden (GhostApproval, CWE-451). v2.1.32 added a symlink warning in the permission dialog; later versions resolve symlinks before writing. Upgrade to restore informed consent on symlinked paths.",
        reference: "https://www.wiz.io/blog/ghostapproval-a-trust-boundary-gap-in-ai-coding-assistants",
        published: "2026-07-08",
        tags: ["coding-agent", "symlink", "ghostapproval"]
      }
    ];
    _db2 = null;
    _initialized2 = false;
  }
});

// src/reporting/owasp-mcp.ts
function owaspMcpForCheckId(id) {
  return CHECK_OWASP_MAP[id];
}
function applyOwaspTags(checks) {
  for (const check of checks) {
    const id = CHECK_OWASP_MAP[check.id];
    if (id) check.owaspMcp = id;
  }
}
function computeOwaspMcpCoverage(result) {
  const byRisk = /* @__PURE__ */ new Map();
  for (const id of Object.keys(OWASP_MCP_TITLES)) {
    byRisk.set(id, { checks: /* @__PURE__ */ new Set(), failed: 0 });
  }
  for (const agent of result.agents) {
    for (const finding of agent.results) {
      const risk = CHECK_OWASP_MAP[finding.id];
      if (!risk) continue;
      const bucket = byRisk.get(risk);
      bucket.checks.add(finding.id);
      if (!finding.passed) bucket.failed += 1;
    }
  }
  return Object.keys(OWASP_MCP_TITLES).map((id) => {
    const b = byRisk.get(id);
    return {
      id,
      title: OWASP_MCP_TITLES[id],
      checks: [...b.checks].sort(),
      failed: b.failed,
      covered: b.checks.size > 0
    };
  });
}
function hasOwaspMcpFindings(result) {
  return result.agents.some((a) => a.results.some((r) => CHECK_OWASP_MAP[r.id]));
}
function renderOwaspMcpCoverageMarkdown(result) {
  if (!hasOwaspMcpFindings(result)) return "";
  const rows = computeOwaspMcpCoverage(result);
  const lines = [
    "## OWASP MCP Top 10 Coverage",
    "",
    "| Risk | Title | Checks | Status |",
    "| --- | --- | --- | --- |"
  ];
  for (const row2 of rows) {
    const status = !row2.covered ? "not covered (runtime/operational)" : row2.failed > 0 ? `\u26A0\uFE0F ${row2.failed} finding(s)` : "\u2705 pass";
    lines.push(`| ${row2.id} | ${row2.title} | ${row2.checks.join(", ") || "\u2014"} | ${status} |`);
  }
  lines.push("");
  return lines.join("\n");
}
var OWASP_MCP_TITLES, CHECK_OWASP_MAP;
var init_owasp_mcp = __esm({
  "src/reporting/owasp-mcp.ts"() {
    "use strict";
    OWASP_MCP_TITLES = {
      MCP01: "Token Mismanagement & Secret Exposure",
      MCP02: "Privilege Escalation via Scope Creep",
      MCP03: "Tool Poisoning",
      MCP04: "Supply Chain & Dependency Tampering",
      MCP05: "Command Injection & Execution",
      MCP06: "Prompt Injection via Contextual Payloads",
      MCP07: "Insufficient Authentication & Authorization",
      MCP08: "Lack of Audit & Telemetry",
      MCP09: "Shadow MCP Servers",
      MCP10: "Context Injection & Over-Sharing"
    };
    CHECK_OWASP_MAP = {
      // Dedicated MCP scanner (mcp category)
      "MCP-001": "MCP09",
      "MCP-002": "MCP07",
      "MCP-003": "MCP01",
      "MCP-004": "MCP05",
      "MCP-005": "MCP05",
      "MCP-006": "MCP10",
      "MCP-007": "MCP06",
      "MCP-008": "MCP04",
      "MCP-009": "MCP02",
      "MCP-010": "MCP04",
      "MCP-011": "MCP07",
      "MCP-012": "MCP01",
      "MCP-013": "MCP07",
      "MCP-014": "MCP01",
      "MCP-015": "MCP07",
      "MCP-016": "MCP07",
      "MCP-017": "MCP02",
      "MCP-018": "MCP07",
      "MCP-019": "MCP10",
      "MCP-020": "MCP03",
      "MCP-021": "MCP05",
      "MCP-022": "MCP05",
      "MCP-023": "MCP07",
      "MCP-024": "MCP03",
      "MCP-025": "MCP03",
      "MCP-026": "MCP03",
      "MCP-027": "MCP04",
      "MCP-028": "MCP09",
      "MCP-029": "MCP07",
      "MCP-030": "MCP04",
      "MCP-031": "MCP10",
      "MCP-032": "MCP01",
      "MCP-033": "MCP01",
      "MCP-034": "MCP06",
      "MCP-035": "MCP04",
      // Per-agent MCP integration checks
      "CC-005": "MCP04",
      "CC-006": "MCP09",
      "CD-003": "MCP04",
      "CD-004": "MCP07",
      "CDX-004": "MCP04",
      "CUR-006": "MCP07",
      "GEM-007": "MCP04",
      "GEM-008": "MCP07"
    };
  }
});

// src/reporting/terminal.ts
import chalk from "chalk";
var SEVERITY_COLORS, SEVERITY_ICONS, TerminalReporter;
var init_terminal = __esm({
  "src/reporting/terminal.ts"() {
    "use strict";
    SEVERITY_COLORS = {
      critical: chalk.red,
      warning: chalk.yellow,
      info: chalk.blue
    };
    SEVERITY_ICONS = {
      critical: "x",
      warning: "!",
      info: "i"
    };
    TerminalReporter = class {
      format = "terminal";
      render(result) {
        const lines = [];
        lines.push("");
        lines.push(chalk.bold("VASO Security Scan Report"));
        lines.push(chalk.dim(`Timestamp: ${result.timestamp}`));
        lines.push("");
        if (result.agents.length === 0) {
          lines.push(chalk.yellow("No agents detected. Nothing to scan."));
          return lines.join("\n");
        }
        for (const agent of result.agents) {
          const inst = agent.installation;
          const headerParts = [agent.agent];
          if (inst.user) headerParts.push(`user: ${inst.user}`);
          if (inst.agentName) headerParts.push(`agent: ${inst.agentName}`);
          if (inst.profile) headerParts.push(`profile: ${inst.profile}`);
          const agentHeader = headerParts.length > 1 ? `${headerParts[0]} (${headerParts.slice(1).join(", ")})` : headerParts[0];
          lines.push(chalk.bold.cyan(`Agent: ${agentHeader}`));
          lines.push(`  Install: ${inst.installDir}`);
          lines.push(`  Score: ${this.formatScore(agent.score)} (${agent.grade})`);
          lines.push("");
          const failed = agent.results.filter((r) => !r.passed);
          const passed = agent.results.filter((r) => r.passed);
          if (failed.length > 0) {
            lines.push(chalk.bold("  Findings:"));
            for (const result2 of failed) {
              lines.push(this.formatFinding(result2));
            }
            lines.push("");
          }
          if (passed.length > 0) {
            lines.push(chalk.bold("  Passed:"));
            for (const result2 of passed) {
              lines.push(`    ${chalk.green("+")} ${result2.id}: ${result2.name}`);
            }
            lines.push("");
          }
        }
        lines.push(chalk.bold("Summary"));
        lines.push(`  Agents scanned: ${result.agents.length}`);
        lines.push(`  Total checks: ${result.summary.total}`);
        lines.push(`  Critical: ${chalk.red(String(result.summary.critical))}`);
        lines.push(`  Warnings: ${chalk.yellow(String(result.summary.warning))}`);
        lines.push(`  Info: ${chalk.blue(String(result.summary.info))}`);
        lines.push(`  Passed: ${chalk.green(String(result.summary.passed))}`);
        lines.push(`  Overall: ${this.formatScore(result.totalScore)} (${result.totalGrade})`);
        if (result.agents.length > 1) {
          lines.push(`  Fleet average: ${result.fleetAverage}/100`);
        }
        lines.push("");
        return lines.join("\n");
      }
      formatFinding(result) {
        const colorFn = SEVERITY_COLORS[result.severity];
        const icon = SEVERITY_ICONS[result.severity];
        let line = `    ${colorFn(`[${icon}]`)} ${result.id}: ${result.name}`;
        line += `
      ${result.message}`;
        if (result.evidence) {
          for (const e of result.evidence) {
            line += `
      ${chalk.dim(`${e.file}${e.line ? `:${e.line}` : ""}`)}`;
            if (e.snippet) {
              line += `
      ${chalk.dim(e.snippet)}`;
            }
          }
        }
        if (result.fixable) {
          line += `
      ${chalk.green("Fixable:")} ${result.fixDescription ?? "run vaso fix"}`;
        }
        return line;
      }
      formatScore(score) {
        if (score >= 90) return chalk.green(String(score));
        if (score >= 70) return chalk.yellow(String(score));
        return chalk.red(String(score));
      }
    };
  }
});

// src/reporting/json.ts
var JsonReporter;
var init_json = __esm({
  "src/reporting/json.ts"() {
    "use strict";
    JsonReporter = class {
      format = "json";
      render(result) {
        return JSON.stringify(result, null, 2);
      }
    };
  }
});

// src/version.ts
import { readFileSync as readFileSync3 } from "fs";
import { dirname as dirname7, join as join83 } from "path";
import { fileURLToPath } from "url";
var VERSION;
var init_version = __esm({
  "src/version.ts"() {
    "use strict";
    VERSION = JSON.parse(
      readFileSync3(
        join83(dirname7(fileURLToPath(import.meta.url)), "..", "package.json"),
        "utf8"
      )
    ).version;
  }
});

// src/reporting/sarif.ts
import { createHash as createHash4 } from "crypto";
var SARIF_SEVERITY_MAP, SARIF_LEVEL_MAP, SarifReporter;
var init_sarif = __esm({
  "src/reporting/sarif.ts"() {
    "use strict";
    init_version();
    init_check_registry();
    init_owasp_agentic();
    init_owasp_mcp();
    SARIF_SEVERITY_MAP = {
      critical: "error",
      warning: "warning",
      info: "note"
    };
    SARIF_LEVEL_MAP = {
      critical: "error",
      warning: "warning",
      info: "note"
    };
    SarifReporter = class {
      format = "sarif";
      render(result) {
        const executionSuccessful = !this.hadExecutionError(result);
        const sarifLog = {
          $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
          version: "2.1.0",
          runs: [{
            tool: {
              driver: {
                name: "VASO",
                fullName: "VULNEX Agent Security Observer",
                version: VERSION,
                informationUri: "https://github.com/vulnex/vaso",
                rules: this.buildRules()
              }
            },
            results: this.buildResults(result),
            invocations: [{
              executionSuccessful,
              startTimeUtc: result.timestamp,
              ...executionSuccessful ? {} : {
                toolExecutionNotifications: this.buildNotifications(result)
              }
            }]
          }]
        };
        return JSON.stringify(sarifLog, null, 2);
      }
      /** A scan is only "successful" if every check produced a real verdict. The
       *  engine flags any check it couldn't evaluate (threw, or adapter failed to
       *  detect/parse) with `errored: true`; presence of any such result means the
       *  scan was partial, and SARIF should say so rather than claim a clean run. */
      hadExecutionError(result) {
        return result.agents.some((a) => a.results.some((r) => r.errored));
      }
      buildNotifications(result) {
        const notes = [];
        for (const agent of result.agents) {
          for (const check of agent.results) {
            if (!check.errored) continue;
            notes.push({
              level: "error",
              message: { text: check.message },
              associatedRule: { id: check.id }
            });
          }
        }
        return notes;
      }
      /** Advertise the full check catalogue, not just the checks that happened to
       *  run on the scanned host(s) — so consumers can browse every rule VASO
       *  enforces and `result.ruleId` always resolves. Assumes `registerAllChecks()`
       *  has populated the registry (the CLI does this at startup). */
      buildRules() {
        return checkRegistry.getAll().map((check) => {
          const owasp = owaspMcpForCheckId(check.id);
          const properties = { category: check.category };
          const tags = [];
          if (owasp) {
            properties.owaspMcp = owasp;
            tags.push(`owasp-mcp/${owasp}`, `OWASP MCP Top 10: ${owasp} ${OWASP_MCP_TITLES[owasp]}`);
          }
          const agentic = owaspAgenticForCheckId(check.id);
          if (agentic.length > 0) {
            properties.owaspAgentic = agentic;
            for (const a of agentic) {
              tags.push(`owasp-agentic/${a}`, `OWASP Agentic AI Top 10: ${a} ${OWASP_AGENTIC_TITLES[a]}`);
            }
          }
          if (tags.length > 0) {
            properties.tags = tags;
          }
          return {
            id: check.id,
            name: check.name,
            shortDescription: { text: check.name },
            fullDescription: { text: check.description },
            defaultConfiguration: {
              level: SARIF_LEVEL_MAP[check.severity]
            },
            properties
          };
        });
      }
      buildResults(result) {
        const results = [];
        for (const agent of result.agents) {
          for (const check of agent.results) {
            if (check.passed) continue;
            const sarifResult = {
              ruleId: check.id,
              level: SARIF_SEVERITY_MAP[check.severity],
              message: { text: check.message },
              locations: [],
              partialFingerprints: { "vaso/v1": this.fingerprint(agent, check) },
              ...agent.installation.agentName ? {
                properties: { agentName: agent.installation.agentName }
              } : {}
            };
            if (check.evidence) {
              sarifResult.locations = check.evidence.map((e) => ({
                physicalLocation: {
                  artifactLocation: { uri: e.file },
                  ...e.line ? {
                    region: {
                      startLine: e.line,
                      snippet: e.snippet ? { text: e.snippet } : void 0
                    }
                  } : {}
                }
              }));
            }
            results.push(sarifResult);
          }
        }
        return results;
      }
      /** Stable cross-run identity for a finding. Keyed on the *logical* identity
       *  (agent install + rule + evidence file), deliberately excluding line number
       *  and snippet so the fingerprint survives unrelated edits that shift the
       *  finding's position — the line still travels in `locations` for display.
       *  Versioned key (`vaso/v1`) so the scheme can evolve without silently
       *  invalidating every existing alert's identity in one release. */
      fingerprint(agent, check) {
        const firstFile = check.evidence?.[0]?.file ?? "";
        const identity = [
          agent.installation.agent,
          agent.installation.installDir,
          check.id,
          firstFile
        ].join("\0");
        return createHash4("sha256").update(identity).digest("hex");
      }
    };
  }
});

// src/reporting/markdown.ts
var MarkdownReporter;
var init_markdown = __esm({
  "src/reporting/markdown.ts"() {
    "use strict";
    init_owasp_agentic();
    init_owasp_mcp();
    MarkdownReporter = class {
      format = "markdown";
      render(result) {
        const lines = [];
        lines.push("# VASO Security Scan Report");
        lines.push("");
        lines.push(`**Date:** ${result.timestamp}`);
        lines.push(`**Score:** ${result.totalScore}/100 (${result.totalGrade})`);
        if (result.agents.length > 1) {
          lines.push(`**Fleet average:** ${result.fleetAverage}/100`);
        }
        lines.push(`**Agents scanned:** ${result.agents.length}`);
        lines.push("");
        lines.push("## Summary");
        lines.push("");
        lines.push(`| Severity | Count |`);
        lines.push(`|----------|-------|`);
        lines.push(`| Critical | ${result.summary.critical} |`);
        lines.push(`| Warning | ${result.summary.warning} |`);
        lines.push(`| Info | ${result.summary.info} |`);
        lines.push(`| Passed | ${result.summary.passed} |`);
        lines.push(`| **Total** | **${result.summary.total}** |`);
        lines.push("");
        for (const agent of result.agents) {
          const agentLabel3 = agent.installation.agentName ? `${agent.agent} (agent: ${agent.installation.agentName})` : agent.agent;
          lines.push(`## ${agentLabel3} (Score: ${agent.score}, Grade: ${agent.grade})`);
          lines.push("");
          const failed = agent.results.filter((r) => !r.passed);
          const passed = agent.results.filter((r) => r.passed);
          if (failed.length > 0) {
            lines.push("### Findings");
            lines.push("");
            lines.push("| ID | Name | Severity | Message |");
            lines.push("|----|------|----------|---------|");
            for (const r of failed) {
              lines.push(`| ${r.id} | ${r.name} | ${r.severity} | ${r.message} |`);
            }
            lines.push("");
          }
          if (passed.length > 0) {
            lines.push(`### Passed (${passed.length})`);
            lines.push("");
            for (const r of passed) {
              lines.push(`- **${r.id}**: ${r.name}`);
            }
            lines.push("");
          }
        }
        const owasp = renderOwaspMcpCoverageMarkdown(result);
        if (owasp) {
          lines.push(owasp);
        }
        const owaspAgentic = renderOwaspAgenticCoverageMarkdown(result);
        if (owaspAgentic) {
          lines.push(owaspAgentic);
        }
        lines.push("---");
        lines.push("*Generated by VASO (VULNEX Agent Security Observer)*");
        return lines.join("\n");
      }
    };
  }
});

// src/reporting/html.ts
function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function gradeColor(grade) {
  switch (grade) {
    case "A":
    case "B":
      return "#16a34a";
    case "C":
      return "#d97706";
    case "D":
    case "F":
      return "#dc2626";
  }
}
function severityColor(severity) {
  switch (severity) {
    case "critical":
      return "#dc2626";
    case "warning":
      return "#d97706";
    case "info":
      return "#2563eb";
  }
}
var CSS, HtmlReporter;
var init_html = __esm({
  "src/reporting/html.ts"() {
    "use strict";
    init_owasp_agentic();
    init_owasp_mcp();
    CSS = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #f8fafc;
    color: #1e293b;
    line-height: 1.6;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
  }
  .header {
    text-align: center;
    margin-bottom: 2rem;
    padding: 2rem;
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  }
  .header h1 {
    font-size: 1.8rem;
    color: #0f172a;
    margin-bottom: 0.5rem;
  }
  .header .timestamp {
    color: #64748b;
    font-size: 0.9rem;
  }
  .score {
    display: inline-block;
    font-size: 3rem;
    font-weight: 700;
    margin: 1rem 0 0.25rem;
  }
  .grade {
    font-size: 1.5rem;
    font-weight: 600;
  }
  .summary-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }
  .card {
    background: #fff;
    border-radius: 8px;
    padding: 1.25rem;
    text-align: center;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  }
  .card .count {
    font-size: 2rem;
    font-weight: 700;
  }
  .card .label {
    font-size: 0.85rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .agent-section {
    background: #fff;
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  }
  .agent-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 1rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid #e2e8f0;
  }
  .agent-header h2 {
    font-size: 1.3rem;
    color: #0f172a;
  }
  .agent-meta {
    color: #64748b;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }
  .agent-meta span {
    margin-right: 1.5rem;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 1rem;
    font-size: 0.9rem;
  }
  th {
    background: #f1f5f9;
    text-align: left;
    padding: 0.6rem 0.75rem;
    font-weight: 600;
    color: #475569;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  td {
    padding: 0.6rem 0.75rem;
    border-bottom: 1px solid #f1f5f9;
  }
  tr:nth-child(even) td {
    background: #fafbfc;
  }
  .severity-badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    color: #fff;
    text-transform: uppercase;
  }
  .evidence {
    font-size: 0.8rem;
    color: #64748b;
    font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  }
  .passed-list {
    margin-top: 1rem;
  }
  .passed-list h3 {
    font-size: 0.95rem;
    color: #16a34a;
    margin-bottom: 0.5rem;
  }
  .passed-list ul {
    list-style: none;
    padding: 0;
    columns: 2;
  }
  .passed-list li {
    padding: 0.2rem 0;
    font-size: 0.85rem;
    color: #64748b;
  }
  .passed-list li::before {
    content: "\\2713 ";
    color: #16a34a;
  }
  .owasp-section {
    background: #fff;
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  }
  .owasp-section h2 {
    font-size: 1.3rem;
    color: #0f172a;
    margin-bottom: 0.25rem;
  }
  .owasp-section .subtitle {
    color: #64748b;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }
  .owasp-section td.risk-id {
    font-weight: 700;
    color: #0f172a;
    white-space: nowrap;
  }
  .owasp-section td.checks {
    font-size: 0.78rem;
    color: #475569;
    font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  }
  .cov-badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    white-space: nowrap;
  }
  .cov-fail { background: #fef2f2; color: #dc2626; }
  .cov-pass { background: #f0fdf4; color: #16a34a; }
  .cov-none { background: #f1f5f9; color: #64748b; }
  .cov-gap  { background: #f8fafc; color: #94a3b8; border: 1px dashed #cbd5e1; }
  .footer {
    text-align: center;
    padding: 1.5rem;
    color: #94a3b8;
    font-size: 0.8rem;
  }
  @media (max-width: 600px) {
    body { padding: 1rem; }
    .summary-cards { grid-template-columns: repeat(2, 1fr); }
    .passed-list ul { columns: 1; }
    .agent-header { flex-direction: column; align-items: flex-start; }
  }
`;
    HtmlReporter = class {
      format = "html";
      render(result) {
        const lines = [];
        lines.push("<!DOCTYPE html>");
        lines.push('<html lang="en">');
        lines.push("<head>");
        lines.push('<meta charset="UTF-8">');
        lines.push('<meta name="viewport" content="width=device-width, initial-scale=1.0">');
        lines.push(`<title>VASO Security Scan Report \u2014 ${escapeHtml(result.timestamp)}</title>`);
        lines.push(`<style>${CSS}</style>`);
        lines.push("</head>");
        lines.push("<body>");
        lines.push('<div class="header">');
        lines.push("<h1>VASO Security Scan Report</h1>");
        lines.push(`<div class="timestamp">${escapeHtml(result.timestamp)}</div>`);
        lines.push(`<div class="score" style="color:${gradeColor(result.totalGrade)}">${result.totalScore}/100</div>`);
        lines.push(`<div class="grade" style="color:${gradeColor(result.totalGrade)}">Grade: ${escapeHtml(result.totalGrade)}</div>`);
        if (result.agents.length > 1) {
          lines.push(`<div class="fleet-average">Fleet average: ${result.fleetAverage}/100</div>`);
        }
        lines.push("</div>");
        lines.push('<div class="summary-cards">');
        lines.push(this.renderCard(result.summary.critical, "Critical", "#dc2626"));
        lines.push(this.renderCard(result.summary.warning, "Warning", "#d97706"));
        lines.push(this.renderCard(result.summary.info, "Info", "#2563eb"));
        lines.push(this.renderCard(result.summary.passed, "Passed", "#16a34a"));
        lines.push("</div>");
        for (const agent of result.agents) {
          lines.push(this.renderAgent(agent));
        }
        if (hasOwaspMcpFindings(result)) {
          lines.push(this.renderOwaspMcpCoverage(result));
        }
        if (hasOwaspAgenticFindings(result)) {
          lines.push(this.renderOwaspAgenticCoverage(result));
        }
        lines.push('<div class="footer">Generated by VASO (VULNEX Agent Security Observer)</div>');
        lines.push("</body>");
        lines.push("</html>");
        return lines.join("\n");
      }
      renderCard(count, label, color) {
        return `<div class="card"><div class="count" style="color:${color}">${count}</div><div class="label">${label}</div></div>`;
      }
      renderAgent(agent) {
        const lines = [];
        const inst = agent.installation;
        const agentLabel3 = inst.agentName ? `${escapeHtml(agent.agent)} \u2014 ${escapeHtml(inst.agentName)}` : escapeHtml(agent.agent);
        lines.push('<div class="agent-section">');
        lines.push('<div class="agent-header">');
        lines.push(`<h2>${agentLabel3}</h2>`);
        lines.push(`<span class="grade" style="color:${gradeColor(agent.grade)}">Score: ${agent.score}/100 (${escapeHtml(agent.grade)})</span>`);
        lines.push("</div>");
        const metaParts = [];
        if (inst.user) metaParts.push(`<span>User: ${escapeHtml(inst.user)}</span>`);
        if (inst.profile) metaParts.push(`<span>Profile: ${escapeHtml(inst.profile)}</span>`);
        metaParts.push(`<span>Install: ${escapeHtml(inst.installDir)}</span>`);
        lines.push(`<div class="agent-meta">${metaParts.join("")}</div>`);
        const failed = agent.results.filter((r) => !r.passed);
        const passed = agent.results.filter((r) => r.passed);
        if (failed.length > 0) {
          lines.push("<table>");
          lines.push("<thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>Message</th><th>Evidence</th><th>Fixable</th></tr></thead>");
          lines.push("<tbody>");
          for (const r of failed) {
            lines.push("<tr>");
            lines.push(`<td>${escapeHtml(r.id)}</td>`);
            lines.push(`<td>${escapeHtml(r.name)}</td>`);
            lines.push(`<td><span class="severity-badge" style="background:${severityColor(r.severity)}">${escapeHtml(r.severity)}</span></td>`);
            lines.push(`<td>${escapeHtml(r.message)}</td>`);
            lines.push(`<td>${this.renderEvidence(r.evidence)}</td>`);
            lines.push(`<td>${r.fixable ? escapeHtml(r.fixDescription ?? "Yes") : "\u2014"}</td>`);
            lines.push("</tr>");
          }
          lines.push("</tbody>");
          lines.push("</table>");
        }
        if (passed.length > 0) {
          lines.push('<div class="passed-list">');
          lines.push(`<h3>Passed (${passed.length})</h3>`);
          lines.push("<ul>");
          for (const r of passed) {
            lines.push(`<li>${escapeHtml(r.id)}: ${escapeHtml(r.name)}</li>`);
          }
          lines.push("</ul>");
          lines.push("</div>");
        }
        lines.push("</div>");
        return lines.join("\n");
      }
      renderOwaspAgenticCoverage(result) {
        const rows = computeOwaspAgenticCoverage(result);
        const lines = ['<div class="owasp-section">'];
        lines.push("<h2>OWASP Agentic AI Top 10 Coverage</h2>");
        lines.push(
          `<div class="subtitle">How VASO's checks map to the OWASP Agentic AI Top 10 (precize list). Risks with no static signal appear as gaps.</div>`
        );
        lines.push("<table>");
        lines.push("<thead><tr><th>Risk</th><th>Title</th><th>Checks</th><th>Status</th></tr></thead>");
        lines.push("<tbody>");
        for (const row2 of rows) {
          lines.push("<tr>");
          lines.push(`<td class="risk-id">${escapeHtml(row2.id)}</td>`);
          lines.push(`<td>${escapeHtml(row2.title)}</td>`);
          lines.push(`<td class="checks">${row2.checks.length > 0 ? escapeHtml(row2.checks.join(", ")) : "\u2014"}</td>`);
          lines.push(`<td>${this.agenticStatusBadge(row2)}</td>`);
          lines.push("</tr>");
        }
        lines.push("</tbody></table>");
        lines.push("</div>");
        return lines.join("\n");
      }
      agenticStatusBadge(row2) {
        if (!row2.inCatalog) {
          return '<span class="cov-badge cov-gap">not covered (runtime/behavioral)</span>';
        }
        if (!row2.covered) {
          return '<span class="cov-badge cov-none">no findings in this scan</span>';
        }
        if (row2.failed > 0) {
          return `<span class="cov-badge cov-fail">\u26A0\uFE0F ${row2.failed} finding(s)</span>`;
        }
        return '<span class="cov-badge cov-pass">\u2705 pass</span>';
      }
      renderOwaspMcpCoverage(result) {
        const rows = computeOwaspMcpCoverage(result);
        const lines = ['<div class="owasp-section">'];
        lines.push("<h2>OWASP MCP Top 10 Coverage</h2>");
        lines.push(
          `<div class="subtitle">How VASO's MCP checks map to the OWASP MCP Top 10 (2025).</div>`
        );
        lines.push("<table>");
        lines.push("<thead><tr><th>Risk</th><th>Title</th><th>Checks</th><th>Status</th></tr></thead>");
        lines.push("<tbody>");
        for (const row2 of rows) {
          lines.push("<tr>");
          lines.push(`<td class="risk-id">${escapeHtml(row2.id)}</td>`);
          lines.push(`<td>${escapeHtml(row2.title)}</td>`);
          lines.push(`<td class="checks">${row2.checks.length > 0 ? escapeHtml(row2.checks.join(", ")) : "\u2014"}</td>`);
          lines.push(`<td>${this.mcpStatusBadge(row2)}</td>`);
          lines.push("</tr>");
        }
        lines.push("</tbody></table>");
        lines.push("</div>");
        return lines.join("\n");
      }
      mcpStatusBadge(row2) {
        if (!row2.covered) {
          return '<span class="cov-badge cov-gap">not covered (runtime/operational)</span>';
        }
        if (row2.failed > 0) {
          return `<span class="cov-badge cov-fail">\u26A0\uFE0F ${row2.failed} finding(s)</span>`;
        }
        return '<span class="cov-badge cov-pass">\u2705 pass</span>';
      }
      renderEvidence(evidence) {
        if (!evidence || evidence.length === 0) return "\u2014";
        return evidence.map((e) => {
          let text = escapeHtml(e.file);
          if (e.line) text += `:${e.line}`;
          return `<span class="evidence">${text}</span>`;
        }).join("<br>");
      }
    };
  }
});

// src/reporting/csv.ts
function csvEscape(value) {
  if (value === "") return "";
  if (/[",\r\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}
function row(values) {
  return values.map((v) => v === void 0 || v === null ? "" : csvEscape(String(v))).join(",");
}
var COLUMNS, CsvReporter;
var init_csv = __esm({
  "src/reporting/csv.ts"() {
    "use strict";
    COLUMNS = [
      "timestamp",
      "agent",
      "agent_name",
      "check_id",
      "check_name",
      "category",
      "severity",
      "passed",
      "message",
      "file",
      "line",
      "snippet",
      "detail"
    ];
    CsvReporter = class {
      format = "csv";
      render(result) {
        const lines = [];
        lines.push(row(COLUMNS));
        for (const agent of result.agents) {
          const agentName = agent.installation.agentName ?? "";
          for (const r of agent.results) {
            const evidences = r.evidence && r.evidence.length > 0 ? r.evidence : [void 0];
            for (const e of evidences) {
              lines.push(row([
                result.timestamp,
                agent.agent,
                agentName,
                r.id,
                r.name,
                r.category,
                r.severity,
                r.passed,
                r.message,
                e?.file ?? "",
                e?.line ?? "",
                e?.snippet ?? "",
                e?.detail ?? ""
              ]));
            }
          }
        }
        return lines.join("\n") + "\n";
      }
    };
  }
});

// src/reporting/junit.ts
function xmlEscape(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}
function attr(name, value) {
  return `${name}="${xmlEscape(String(value))}"`;
}
function evidenceText(r) {
  if (!r.evidence || r.evidence.length === 0) return r.message;
  const parts = [r.message, ""];
  for (const e of r.evidence) {
    let line = e.file;
    if (e.line !== void 0) line += `:${e.line}`;
    if (e.detail) line += ` \u2014 ${e.detail}`;
    if (e.snippet) line += `
  ${e.snippet}`;
    parts.push(line);
  }
  return parts.join("\n");
}
function suiteCounts(agent) {
  let tests = 0;
  let failures = 0;
  for (const r of agent.results) {
    tests++;
    if (!r.passed) failures++;
  }
  return { tests, failures };
}
function agentLabel(agent) {
  return agent.installation.agentName ? `${agent.agent}.${agent.installation.agentName}` : agent.agent;
}
var JunitReporter;
var init_junit = __esm({
  "src/reporting/junit.ts"() {
    "use strict";
    JunitReporter = class {
      format = "junit";
      render(result) {
        const lines = [];
        lines.push('<?xml version="1.0" encoding="UTF-8"?>');
        let totalTests = 0;
        let totalFailures = 0;
        for (const a of result.agents) {
          const c = suiteCounts(a);
          totalTests += c.tests;
          totalFailures += c.failures;
        }
        lines.push(
          `<testsuites ${attr("name", "vaso")} ${attr("tests", totalTests)} ${attr("failures", totalFailures)} ${attr("errors", 0)} ${attr("timestamp", result.timestamp)}>`
        );
        for (const agent of result.agents) {
          const label = agentLabel(agent);
          const c = suiteCounts(agent);
          lines.push(
            `  <testsuite ${attr("name", label)} ${attr("tests", c.tests)} ${attr("failures", c.failures)} ${attr("errors", 0)} ${attr("timestamp", result.timestamp)}>`
          );
          for (const r of agent.results) {
            const classname = `${label}.${r.category}`;
            const testname = `${r.id} \u2014 ${r.name}`;
            const open = `    <testcase ${attr("classname", classname)} ${attr("name", testname)}>`;
            if (r.passed) {
              lines.push(`${open}</testcase>`);
            } else {
              lines.push(open);
              lines.push(
                `      <failure ${attr("message", r.message)} ${attr("type", r.severity)}>${xmlEscape(evidenceText(r))}</failure>`
              );
              lines.push("    </testcase>");
            }
          }
          lines.push("  </testsuite>");
        }
        lines.push("</testsuites>");
        return lines.join("\n") + "\n";
      }
    };
  }
});

// src/reporting/index.ts
function getReporter(format) {
  const factory = reporters[format];
  if (!factory) {
    throw new Error(`Unknown report format: "${format}". Available: ${Object.keys(reporters).join(", ")}`);
  }
  return factory();
}
function registerReporter(format, factory) {
  reporters[format] = factory;
}
var reporters;
var init_reporting = __esm({
  "src/reporting/index.ts"() {
    "use strict";
    init_terminal();
    init_json();
    init_sarif();
    init_markdown();
    init_html();
    init_csv();
    init_junit();
    reporters = {
      terminal: () => new TerminalReporter(),
      json: () => new JsonReporter(),
      sarif: () => new SarifReporter(),
      markdown: () => new MarkdownReporter(),
      html: () => new HtmlReporter(),
      csv: () => new CsvReporter(),
      junit: () => new JunitReporter()
    };
  }
});

// src/user-plugins/loader.ts
import { readdir as readdir2, stat as stat2, readFile as readFile7 } from "fs/promises";
import { join as join84, basename as basename17, extname as extname7 } from "path";
import { homedir as homedir5 } from "os";
import { pathToFileURL } from "url";
function defaultPluginDir() {
  return join84(homedir5(), ".vaso", "plugins");
}
async function resolveDirectoryEntry(dirPath) {
  try {
    const pkgPath = join84(dirPath, "package.json");
    const pkgJson = JSON.parse(await readFile7(pkgPath, "utf-8"));
    if (pkgJson.main) {
      const mainPath = join84(dirPath, pkgJson.main);
      const mainStat = await stat2(mainPath);
      if (mainStat.isFile()) return mainPath;
    }
  } catch {
  }
  for (const name of ["index.mjs", "index.js"]) {
    try {
      const candidate = join84(dirPath, name);
      const s = await stat2(candidate);
      if (s.isFile()) return candidate;
    } catch {
    }
  }
  return null;
}
function buildPluginAPI(plugin) {
  return {
    version: VERSION2,
    registerCheck(check) {
      try {
        checkRegistry.register(check);
        plugin.registered.checks.push(check.id);
      } catch (err) {
        plugin.status = "error";
        plugin.error = (plugin.error ? plugin.error + "; " : "") + `Failed to register check "${check.id}": ${err.message}`;
      }
    },
    registerChecks(checks) {
      for (const check of checks) {
        this.registerCheck(check);
      }
    },
    registerAdapter(adapter) {
      try {
        adapterRegistry.register(adapter);
        plugin.registered.adapters.push(adapter.displayName);
      } catch (err) {
        plugin.status = "error";
        plugin.error = (plugin.error ? plugin.error + "; " : "") + `Failed to register adapter "${adapter.displayName}": ${err.message}`;
      }
    },
    registerReporter(format, factory) {
      try {
        registerReporter(format, factory);
        plugin.registered.reporters.push(format);
      } catch (err) {
        plugin.status = "error";
        plugin.error = (plugin.error ? plugin.error + "; " : "") + `Failed to register reporter "${format}": ${err.message}`;
      }
    }
  };
}
async function loadUserPlugins(dir) {
  const pluginDir = dir ?? defaultPluginDir();
  loadedPlugins = [];
  let entries;
  try {
    entries = await readdir2(pluginDir);
  } catch {
    return loadedPlugins;
  }
  for (const entry of entries.sort()) {
    if (entry.startsWith(".") || entry.startsWith("_")) continue;
    const fullPath = join84(pluginDir, entry);
    let entryPoint;
    try {
      const entryStat = await stat2(fullPath);
      if (entryStat.isDirectory()) {
        const resolved = await resolveDirectoryEntry(fullPath);
        if (!resolved) continue;
        entryPoint = resolved;
      } else if (entryStat.isFile()) {
        const ext = extname7(entry);
        if (ext !== ".js" && ext !== ".mjs") continue;
        entryPoint = fullPath;
      } else {
        continue;
      }
    } catch {
      continue;
    }
    const plugin = {
      path: fullPath,
      name: basename17(entry, extname7(entry)),
      status: "loaded",
      registered: { checks: [], adapters: [], reporters: [] }
    };
    try {
      const fileUrl = pathToFileURL(entryPoint).href;
      const mod = await import(fileUrl);
      const pluginExport = mod.default ?? mod;
      if (pluginExport.meta) {
        if (pluginExport.meta.name) plugin.name = pluginExport.meta.name;
        if (pluginExport.meta.version) plugin.version = pluginExport.meta.version;
        if (pluginExport.meta.description) plugin.description = pluginExport.meta.description;
      }
      if (typeof pluginExport.register !== "function") {
        plugin.status = "error";
        plugin.error = "Plugin does not export a register() function";
        loadedPlugins.push(plugin);
        continue;
      }
      const api = buildPluginAPI(plugin);
      await pluginExport.register(api);
    } catch (err) {
      plugin.status = "error";
      plugin.error = `Failed to load plugin: ${err.message}`;
    }
    loadedPlugins.push(plugin);
  }
  return loadedPlugins;
}
function getLoadedPlugins() {
  return [...loadedPlugins];
}
var VERSION2, loadedPlugins;
var init_loader = __esm({
  "src/user-plugins/loader.ts"() {
    "use strict";
    init_check_registry();
    init_registry();
    init_reporting();
    VERSION2 = "0.2.1";
    loadedPlugins = [];
  }
});

// src/rules/operators.ts
function deepEqual(a, b) {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  if (typeof a === "object" && typeof b === "object") {
    const aKeys = Object.keys(a);
    const bKeys = Object.keys(b);
    if (aKeys.length !== bKeys.length) return false;
    return aKeys.every(
      (k) => deepEqual(a[k], b[k])
    );
  }
  return false;
}
function evaluateOperator(actual, operator, expected) {
  switch (operator) {
    case "eq":
      return deepEqual(actual, expected);
    case "neq":
      return !deepEqual(actual, expected);
    case "in":
      if (!Array.isArray(expected)) return false;
      return expected.some((item) => deepEqual(actual, item));
    case "not-in":
      if (!Array.isArray(expected)) return true;
      return !expected.some((item) => deepEqual(actual, item));
    case "exists":
      return actual !== void 0;
    case "not-exists":
      return actual === void 0;
    case "gt":
      return typeof actual === "number" && typeof expected === "number" && actual > expected;
    case "lt":
      return typeof actual === "number" && typeof expected === "number" && actual < expected;
    case "matches":
      if (typeof actual !== "string" || typeof expected !== "string") return false;
      try {
        return new RegExp(expected).test(actual);
      } catch {
        return false;
      }
    case "contains":
      if (Array.isArray(actual)) return actual.some((item) => deepEqual(item, expected));
      if (typeof actual === "string" && typeof expected === "string") return actual.includes(expected);
      return false;
    default:
      return false;
  }
}
var VALID_OPERATORS;
var init_operators = __esm({
  "src/rules/operators.ts"() {
    "use strict";
    VALID_OPERATORS = [
      "eq",
      "neq",
      "in",
      "not-in",
      "exists",
      "not-exists",
      "gt",
      "lt",
      "matches",
      "contains"
    ];
  }
});

// src/rules/schema.ts
function validateRuleFile(data) {
  const errors = [];
  const rules = [];
  if (!data || typeof data !== "object") {
    errors.push({ message: 'Rule file must be a YAML object with a "rules" array' });
    return { rules, errors };
  }
  const doc = data;
  if (!Array.isArray(doc.rules)) {
    errors.push({ message: 'Rule file must contain a "rules" array at the top level' });
    return { rules, errors };
  }
  for (let i = 0; i < doc.rules.length; i++) {
    const raw = doc.rules[i];
    const label = raw?.id ? String(raw.id) : `rules[${i}]`;
    if (!raw || typeof raw !== "object") {
      errors.push({ rule: label, message: "Rule must be an object" });
      continue;
    }
    const r = raw;
    const ruleErrors = [];
    for (const field of ["id", "name", "description"]) {
      if (typeof r[field] !== "string" || r[field].trim() === "") {
        ruleErrors.push({ rule: label, field, message: `"${field}" is required and must be a non-empty string` });
      }
    }
    if (!VALID_CATEGORIES.includes(r.category)) {
      ruleErrors.push({ rule: label, field: "category", message: `"category" must be one of: ${VALID_CATEGORIES.join(", ")}` });
    }
    if (!VALID_SEVERITIES.includes(r.severity)) {
      ruleErrors.push({ rule: label, field: "severity", message: `"severity" must be one of: ${VALID_SEVERITIES.join(", ")}` });
    }
    if (r.agents !== void 0) {
      if (!Array.isArray(r.agents) || !r.agents.every((a) => VALID_AGENTS.includes(a))) {
        ruleErrors.push({ rule: label, field: "agents", message: `"agents" must be an array of valid agent types: ${VALID_AGENTS.join(", ")}` });
      }
    }
    if (r.platforms !== void 0) {
      if (!Array.isArray(r.platforms) || !r.platforms.every((p) => typeof p === "string")) {
        ruleErrors.push({ rule: label, field: "platforms", message: '"platforms" must be an array of strings' });
      }
    }
    const hasConfig = r.config !== void 0;
    const hasPattern = r.pattern !== void 0;
    const hasFileExists = r.file_exists !== void 0;
    const typeCount = [hasConfig, hasPattern, hasFileExists].filter(Boolean).length;
    if (typeCount !== 1) {
      ruleErrors.push({ rule: label, message: 'Rule must have exactly one of: "config", "pattern", "file_exists"' });
    }
    if (hasConfig) {
      const c = r.config;
      if (!c || typeof c !== "object") {
        ruleErrors.push({ rule: label, field: "config", message: '"config" must be an object' });
      } else {
        if (typeof c.path !== "string" || c.path.trim() === "") {
          ruleErrors.push({ rule: label, field: "config.path", message: '"config.path" is required' });
        }
        if (!VALID_OPERATORS.includes(c.operator)) {
          ruleErrors.push({ rule: label, field: "config.operator", message: `"config.operator" must be one of: ${VALID_OPERATORS.join(", ")}` });
        }
        if (c.pass_when !== void 0 && c.pass_when !== "match" && c.pass_when !== "no-match") {
          ruleErrors.push({ rule: label, field: "config.pass_when", message: '"config.pass_when" must be "match" or "no-match"' });
        }
      }
    }
    if (hasPattern) {
      const p = r.pattern;
      if (!p || typeof p !== "object") {
        ruleErrors.push({ rule: label, field: "pattern", message: '"pattern" must be an object' });
      } else {
        if (typeof p.regex !== "string" || p.regex.trim() === "") {
          ruleErrors.push({ rule: label, field: "pattern.regex", message: '"pattern.regex" is required' });
        } else if (p.regex.length > 500) {
          ruleErrors.push({ rule: label, field: "pattern.regex", message: '"pattern.regex" must be 500 characters or less' });
        } else {
          try {
            new RegExp(p.regex);
          } catch {
            ruleErrors.push({ rule: label, field: "pattern.regex", message: `"pattern.regex" is not a valid regular expression` });
          }
        }
        if (p.target !== void 0 && !VALID_TARGETS.includes(p.target)) {
          ruleErrors.push({ rule: label, field: "pattern.target", message: `"pattern.target" must be one of: ${VALID_TARGETS.join(", ")}` });
        }
        if (p.message !== void 0 && typeof p.message !== "string") {
          ruleErrors.push({ rule: label, field: "pattern.message", message: '"pattern.message" must be a string' });
        }
      }
    }
    if (hasFileExists) {
      const f = r.file_exists;
      if (!f || typeof f !== "object") {
        ruleErrors.push({ rule: label, field: "file_exists", message: '"file_exists" must be an object' });
      } else {
        if (typeof f.path !== "string" || f.path.trim() === "") {
          ruleErrors.push({ rule: label, field: "file_exists.path", message: '"file_exists.path" is required' });
        }
        if (f.pass_when !== void 0 && f.pass_when !== "exists" && f.pass_when !== "not-exists") {
          ruleErrors.push({ rule: label, field: "file_exists.pass_when", message: '"file_exists.pass_when" must be "exists" or "not-exists"' });
        }
      }
    }
    if (r.fix !== void 0) {
      const f = r.fix;
      if (!f || typeof f !== "object") {
        ruleErrors.push({ rule: label, field: "fix", message: '"fix" must be an object' });
      } else {
        const hasSet = f.set !== void 0;
        const hasGuidance = f.guidance !== void 0;
        if (!hasSet && !hasGuidance) {
          ruleErrors.push({ rule: label, field: "fix", message: '"fix" must have either "set" + "value" or "guidance"' });
        }
        if (hasSet && typeof f.set !== "string") {
          ruleErrors.push({ rule: label, field: "fix.set", message: '"fix.set" must be a string (config path)' });
        }
        if (hasGuidance && typeof f.guidance !== "string") {
          ruleErrors.push({ rule: label, field: "fix.guidance", message: '"fix.guidance" must be a string' });
        }
      }
    }
    if (ruleErrors.length > 0) {
      errors.push(...ruleErrors);
    } else {
      rules.push({
        id: r.id,
        name: r.name,
        category: r.category,
        severity: r.severity,
        description: r.description,
        agents: r.agents,
        platforms: r.platforms,
        config: r.config,
        pattern: r.pattern,
        file_exists: r.file_exists,
        fix: r.fix
      });
    }
  }
  return { rules, errors };
}
var VALID_CATEGORIES, VALID_AGENTS, VALID_SEVERITIES, VALID_TARGETS;
var init_schema = __esm({
  "src/rules/schema.ts"() {
    "use strict";
    init_operators();
    init_types();
    VALID_CATEGORIES = CHECK_CATEGORIES;
    VALID_AGENTS = AGENT_TYPES;
    VALID_SEVERITIES = ["critical", "warning", "info"];
    VALID_TARGETS = ["configs", "skills", "all"];
  }
});

// src/rules/loader.ts
import { join as join85, extname as extname8 } from "path";
import YAML3 from "yaml";
async function discoverRuleFiles(dir, fs) {
  if (!await pathExists(dir, fs)) return [];
  const entries = await fs.readdirEntries(dir);
  return entries.filter((e) => e.isFile && YAML_EXTENSIONS.has(extname8(e.name)) && !e.name.startsWith(".")).map((e) => join85(dir, e.name)).sort();
}
async function parseRuleFile(filePath, fs) {
  try {
    const content = await fs.readFile(filePath);
    const data = YAML3.parse(content);
    const { rules, errors } = validateRuleFile(data);
    return { filePath, rules, errors };
  } catch (err) {
    return {
      filePath,
      rules: [],
      errors: [{ message: `Failed to parse: ${err instanceof Error ? err.message : String(err)}` }]
    };
  }
}
async function loadRules(options) {
  const provider = options?.fs ?? new LocalFSProvider();
  const files = [];
  const allErrors = [];
  const ruleMap = /* @__PURE__ */ new Map();
  if (!options?.skipGlobal) {
    const globalDir = join85(provider.homedir(), ".vaso", "rules");
    const globalFiles = await discoverRuleFiles(globalDir, provider);
    for (const f of globalFiles) {
      const result = await parseRuleFile(f, provider);
      files.push(result);
    }
  }
  if (!options?.skipProject) {
    const projectDir = join85(process.cwd(), ".vaso", "rules");
    const projectFiles = await discoverRuleFiles(projectDir, provider);
    for (const f of projectFiles) {
      const result = await parseRuleFile(f, provider);
      files.push(result);
    }
  }
  if (options?.extraPaths) {
    for (const p of options.extraPaths) {
      const result = await parseRuleFile(p, provider);
      files.push(result);
    }
  }
  for (const file of files) {
    for (const err of file.errors) {
      allErrors.push({ ...err, file: file.filePath });
    }
    for (const rule of file.rules) {
      ruleMap.set(rule.id, rule);
    }
  }
  return {
    files,
    allRules: [...ruleMap.values()],
    allErrors
  };
}
var YAML_EXTENSIONS;
var init_loader2 = __esm({
  "src/rules/loader.ts"() {
    "use strict";
    init_schema();
    init_utils();
    init_local_fs_provider();
    YAML_EXTENSIONS = /* @__PURE__ */ new Set([".yaml", ".yml"]);
  }
});

// src/rules/compiler.ts
import { join as join86, resolve as resolve2 } from "path";
function interpolateMessage(template, vars) {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key) => vars[key] ?? "");
}
function compileConfigRule(rule) {
  const { config } = rule;
  if (!config) throw new Error("No config block");
  return async (ctx) => {
    const evidence = [];
    for (const cfg of ctx.configs) {
      const actual = getNestedValue(cfg.data, config.path);
      const conditionMatches = evaluateOperator(actual, config.operator, config.value);
      const passWhen = config.pass_when ?? "no-match";
      const passed = passWhen === "match" ? conditionMatches : !conditionMatches;
      if (!passed) {
        evidence.push({
          file: cfg.filePath,
          detail: `${config.path} = ${JSON.stringify(actual)}`
        });
      }
    }
    return {
      id: rule.id,
      name: rule.name,
      category: rule.category,
      severity: rule.severity,
      passed: evidence.length === 0,
      message: evidence.length === 0 ? `${rule.name}: passed` : `${rule.name}: ${evidence.length} config(s) failed \u2014 ${rule.description}`,
      evidence: evidence.length > 0 ? evidence : void 0,
      fixable: rule.fix?.set !== void 0,
      fixDescription: rule.fix?.guidance ?? (rule.fix?.set ? `Set ${rule.fix.set} to ${JSON.stringify(rule.fix.value)}` : void 0)
    };
  };
}
function compilePatternRule(rule) {
  const { pattern } = rule;
  if (!pattern) throw new Error("No pattern block");
  const re = new RegExp(pattern.regex);
  const target = pattern.target ?? "configs";
  const msgTemplate = pattern.message ?? `Pattern match in {{file}}:{{line}} \u2014 {{snippet}}`;
  return async (ctx) => {
    const evidence = [];
    const entries = [];
    if (target === "configs" || target === "all") {
      for (const cfg of ctx.configs) {
        entries.push({ filePath: cfg.filePath, content: cfg.raw });
      }
    }
    if (target === "skills" || target === "all") {
      if (ctx.skillFiles) {
        for (const f of ctx.skillFiles) {
          entries.push({ filePath: f, content: null });
        }
      }
    }
    for (const entry of entries) {
      let content;
      if (entry.content !== null) {
        content = entry.content;
      } else {
        try {
          content = await ctx.fs.readFile(entry.filePath);
        } catch {
          continue;
        }
      }
      const filePath = entry.filePath;
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const match = re.exec(lines[i]);
        if (match) {
          const snippet = lines[i].trim().slice(0, 120);
          evidence.push({
            file: filePath,
            line: i + 1,
            snippet,
            detail: interpolateMessage(msgTemplate, {
              file: filePath,
              line: String(i + 1),
              snippet,
              match: match[0]
            })
          });
        }
      }
    }
    return {
      id: rule.id,
      name: rule.name,
      category: rule.category,
      severity: rule.severity,
      passed: evidence.length === 0,
      message: evidence.length === 0 ? `${rule.name}: no matches found` : `${rule.name}: ${evidence.length} match(es) \u2014 ${rule.description}`,
      evidence: evidence.length > 0 ? evidence : void 0,
      fixable: false,
      fixDescription: rule.fix?.guidance
    };
  };
}
function compileFileExistsRule(rule) {
  const { file_exists } = rule;
  if (!file_exists) throw new Error("No file_exists block");
  const passWhen = file_exists.pass_when ?? "not-exists";
  return async (ctx) => {
    const targetPath = file_exists.path.startsWith("/") ? file_exists.path : resolve2(join86(ctx.installation.installDir, file_exists.path));
    const exists2 = await pathExists(targetPath, ctx.fs);
    const passed = passWhen === "exists" ? exists2 : !exists2;
    const evidence = passed ? [] : [{
      file: targetPath,
      detail: exists2 ? "File exists but should not" : "File does not exist but should"
    }];
    return {
      id: rule.id,
      name: rule.name,
      category: rule.category,
      severity: rule.severity,
      passed,
      message: passed ? `${rule.name}: passed` : `${rule.name}: ${rule.description}`,
      evidence: evidence.length > 0 ? evidence : void 0,
      fixable: false,
      fixDescription: rule.fix?.guidance
    };
  };
}
function compileFix(rule) {
  if (!rule.fix?.set) return void 0;
  const { set: keyPath, value } = rule.fix;
  return async (ctx) => {
    let applied = false;
    for (const cfg of ctx.configs) {
      try {
        await updateConfigValue(cfg, keyPath, value);
        applied = true;
      } catch {
      }
    }
    return {
      checkId: rule.id,
      applied,
      message: applied ? `Set ${keyPath} to ${JSON.stringify(value)}` : `Could not apply fix for ${rule.id}`
    };
  };
}
function compileRule(rule) {
  let run;
  if (rule.config) {
    run = compileConfigRule(rule);
  } else if (rule.pattern) {
    run = compilePatternRule(rule);
  } else if (rule.file_exists) {
    run = compileFileExistsRule(rule);
  } else {
    throw new Error(`Rule ${rule.id}: no rule type (config, pattern, file_exists)`);
  }
  return {
    id: rule.id,
    name: rule.name,
    category: rule.category,
    severity: rule.severity,
    description: rule.description,
    supportedAgents: rule.agents,
    supportedPlatforms: rule.platforms,
    run,
    fix: compileFix(rule)
  };
}
var init_compiler = __esm({
  "src/rules/compiler.ts"() {
    "use strict";
    init_utils();
    init_utils();
    init_operators();
    init_config_writer();
  }
});

// src/rules/index.ts
async function loadAndRegisterRules(registry, options) {
  const loadResult = await loadRules(options);
  const registered = [];
  const skipped = [];
  for (const rule of loadResult.allRules) {
    try {
      const check = compileRule(rule);
      const existing = registry.getAll().find((c) => c.id === check.id);
      if (existing) {
        skipped.push({ id: rule.id, reason: `ID "${rule.id}" conflicts with existing check` });
        continue;
      }
      registry.register(check);
      registered.push(check);
    } catch (err) {
      skipped.push({
        id: rule.id,
        reason: `Compile error: ${err instanceof Error ? err.message : String(err)}`
      });
    }
  }
  return { registered, skipped, loadResult };
}
var init_rules = __esm({
  "src/rules/index.ts"() {
    "use strict";
    init_loader2();
    init_compiler();
    init_loader2();
    init_compiler();
    init_schema();
  }
});

// src/core/debug.ts
function setDebug(enabled) {
  debugEnabled = enabled;
}
function logError(prefix, err) {
  if (err instanceof Error) {
    if (debugEnabled && err.stack) {
      console.error(prefix, err.stack);
    } else {
      console.error(prefix, err.message);
    }
  } else {
    console.error(prefix, String(err));
  }
}
var debugEnabled;
var init_debug = __esm({
  "src/core/debug.ts"() {
    "use strict";
    debugEnabled = false;
  }
});

// src/core/default-zone-graph.ts
function defaultZoneGraph() {
  return {
    zones: [
      { id: "net", label: "Network", trustLevel: 0 },
      { id: "gw", label: "Gateway", trustLevel: 1 },
      { id: "sbx", label: "Sandbox", trustLevel: 2 },
      { id: "host", label: "Host FS", trustLevel: 3 }
    ],
    components: [
      {
        id: "inbound",
        label: "Network Ingress",
        zone: "net"
      },
      {
        id: "gateway",
        label: "Agent Gateway",
        zone: "gw",
        guardCheckIds: ["CFG-001", "CFG-004", "NET-001"]
      },
      {
        id: "sandbox",
        label: "Sandbox Boundary",
        zone: "sbx",
        guardCheckIds: ["CFG-005"]
      },
      {
        id: "fs",
        label: "Host Filesystem",
        zone: "host",
        guardCheckIds: ["RUN-001", "POL-001"]
      }
    ],
    edges: [
      { from: "inbound", to: "gateway", kind: "data" },
      { from: "gateway", to: "sandbox", kind: "control" },
      { from: "sandbox", to: "fs", kind: "data" }
    ]
  };
}
var init_default_zone_graph = __esm({
  "src/core/default-zone-graph.ts"() {
    "use strict";
  }
});

// src/core/scoring.ts
function computeScore(results) {
  let score = BASE_SCORE;
  for (const result of results) {
    if (result.passed) continue;
    switch (result.severity) {
      case "critical":
        score -= CRITICAL_PENALTY;
        break;
      case "warning":
        score -= WARNING_PENALTY;
        break;
    }
  }
  return Math.max(0, Math.min(100, score));
}
function aggregateScore(scores) {
  if (scores.length === 0) return 100;
  return Math.min(...scores);
}
function meanScore(scores) {
  if (scores.length === 0) return 100;
  return Math.round(scores.reduce((sum, s) => sum + s, 0) / scores.length);
}
function scoreToGrade(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}
function summarizeResults(results) {
  let critical = 0;
  let warning = 0;
  let info = 0;
  let passed = 0;
  for (const result of results) {
    if (result.passed) {
      passed++;
    } else {
      switch (result.severity) {
        case "critical":
          critical++;
          break;
        case "warning":
          warning++;
          break;
        case "info":
          info++;
          break;
      }
    }
  }
  return { critical, warning, info, passed, total: results.length };
}
var CRITICAL_PENALTY, WARNING_PENALTY, BASE_SCORE;
var init_scoring = __esm({
  "src/core/scoring.ts"() {
    "use strict";
    CRITICAL_PENALTY = 12;
    WARNING_PENALTY = 5;
    BASE_SCORE = 100;
  }
});

// src/core/engine.ts
var engine_exports = {};
__export(engine_exports, {
  ScanEngine: () => ScanEngine
});
var ScanEngine;
var init_engine = __esm({
  "src/core/engine.ts"() {
    "use strict";
    init_local_fs_provider();
    init_scoring();
    init_utils();
    init_tool_baseline();
    ScanEngine = class {
      constructor(adapters, checks, fs) {
        this.adapters = adapters;
        this.checks = checks;
        this.fs = fs ?? new LocalFSProvider();
      }
      fs;
      async scan(options) {
        const detection = await this.adapters.detectAllDetailed({
          allUsers: options.allUsers,
          fs: this.fs
        });
        const installations = detection.installations;
        const filtered = options.agentFilter ? installations.filter((i) => i.agent === options.agentFilter) : installations;
        const detectionErrors = options.agentFilter ? detection.errors.filter((e) => e.agent === options.agentFilter) : detection.errors;
        const configLoadErrors = options.agentFilter ? detection.configLoadErrors.filter((e) => e.agent === options.agentFilter) : detection.configLoadErrors;
        if (filtered.length === 0 && detectionErrors.length === 0 && configLoadErrors.length === 0) {
          return this.emptyResult(options.agentFilter);
        }
        const agentResults = await Promise.allSettled(
          filtered.map((installation) => this.scanAgent(installation))
        );
        const agents = [];
        for (const result of agentResults) {
          if (result.status === "fulfilled") {
            agents.push(result.value);
          }
        }
        agents.push(...detectionErrors.map((e) => this.adapterErrorResult(e)));
        this.foldConfigLoadErrors(agents, configLoadErrors);
        const allResults = agents.flatMap((a) => a.results);
        const scores = agents.map((a) => a.score);
        const totalScore = aggregateScore(scores);
        const summary = summarizeResults(allResults);
        return {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          agents,
          totalScore,
          totalGrade: scoreToGrade(totalScore),
          fleetAverage: meanScore(scores),
          summary
        };
      }
      async scanAgent(installation) {
        const skillsDirs = getAllSkillsDirs(installation);
        const skillFiles = skillsDirs.length > 0 ? (await Promise.all(skillsDirs.map((d) => getSkillFiles(d, this.fs)))).flat() : void 0;
        const adapter = this.adapters.getAdapter(installation.agent);
        const credentialPaths = adapter?.getCredentialPaths?.(installation.installDir);
        const context = {
          installation,
          configs: installation.configFiles,
          platform: this.fs.platform,
          fs: this.fs,
          skillFiles,
          credentialPaths
        };
        const applicable = this.checks.getApplicable(installation.agent, this.fs.platform);
        const settled = await Promise.allSettled(
          applicable.map((check) => check.run(context))
        );
        const results = settled.map((r, index) => {
          if (r.status === "fulfilled") return r.value;
          const check = applicable[index];
          return {
            id: check.id,
            name: check.name,
            category: check.category,
            severity: "warning",
            passed: false,
            errored: true,
            message: `Check errored and was not completed: ${r.reason instanceof Error ? r.reason.message : String(r.reason)}`
          };
        });
        const score = computeScore(results);
        return {
          agent: installation.agent,
          version: installation.version,
          installation,
          results,
          score,
          grade: scoreToGrade(score)
        };
      }
      /** Surface config files that exist but could not be read/parsed during
       *  detection. Adapters swallow those failures (a broken file must not abort
       *  detection), which used to make a corrupted config indistinguishable from
       *  a clean or absent one. Each failure becomes an `errored` result — the
       *  same partial-scan channel as thrown checks — attached to the agent it
       *  belongs to, or to a synthetic entry when the broken config prevented the
       *  agent from being detected at all. */
      foldConfigLoadErrors(agents, loadErrors) {
        for (const error of loadErrors) {
          const result = {
            id: "CONFIG-LOAD",
            name: `${error.displayName} Config Load Error`,
            category: "config",
            severity: "warning",
            passed: false,
            errored: true,
            message: `Config file could not be ${error.stage === "read" ? "read" : "parsed"}: ${error.filePath} \u2014 ${error.message}. Findings for this agent may be incomplete.`,
            evidence: [{ file: error.filePath, detail: error.message }]
          };
          const agent = agents.find((a) => a.agent === error.agent);
          if (agent) {
            agent.results.push(result);
            agent.score = computeScore(agent.results);
            agent.grade = scoreToGrade(agent.score);
          } else {
            const score = computeScore([result]);
            agents.push({
              agent: error.agent,
              installation: { agent: error.agent, installDir: "", configFiles: [] },
              results: [result],
              score,
              grade: scoreToGrade(score)
            });
          }
        }
      }
      adapterErrorResult(error) {
        const result = {
          id: "ADAPTER-DETECT",
          name: `${error.displayName} Detection Error`,
          category: "config",
          severity: "warning",
          passed: false,
          errored: true,
          message: `Adapter detection failed: ${error.message}`
        };
        const score = computeScore([result]);
        return {
          agent: error.agent,
          installation: {
            agent: error.agent,
            installDir: "",
            configFiles: []
          },
          results: [result],
          score,
          grade: scoreToGrade(score)
        };
      }
      async scanMCP(mcpConfigs, serverSources, options) {
        const sourcesWithTools = serverSources.map((source) => ({
          ...source,
          tools: source.tools ?? (source.sourceCode ? extractToolDefinitions(source.sourceCode) : void 0)
        }));
        const context = {
          installation: {
            agent: "mcp",
            installDir: process.cwd(),
            configFiles: []
          },
          configs: [],
          platform: this.fs.platform,
          fs: this.fs,
          mcpConfigs,
          mcpServerSources: sourcesWithTools
        };
        const mcpChecks2 = this.checks.getByCategory("mcp");
        const settled = await Promise.allSettled(
          mcpChecks2.map((check) => check.run(context))
        );
        const results = settled.map((r, index) => {
          if (r.status === "fulfilled") return r.value;
          const check = mcpChecks2[index];
          return {
            id: check.id,
            name: check.name,
            category: check.category,
            severity: "warning",
            passed: false,
            errored: true,
            message: `Check errored and was not completed: ${r.reason instanceof Error ? r.reason.message : String(r.reason)}`
          };
        });
        const score = computeScore(results);
        const agentResult = {
          agent: "mcp",
          installation: context.installation,
          results,
          score,
          grade: scoreToGrade(score)
        };
        const summary = summarizeResults(results);
        return {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          agents: [agentResult],
          totalScore: score,
          totalGrade: scoreToGrade(score),
          fleetAverage: score,
          summary
        };
      }
      async scanSkill(skillPath, skillFiles, options) {
        const context = {
          installation: {
            agent: "skill-audit",
            installDir: skillPath,
            skillsDir: skillPath,
            configFiles: []
          },
          configs: [],
          platform: this.fs.platform,
          fs: this.fs,
          skillFiles
        };
        const skillChecks2 = [
          ...this.checks.getByCategory("skills"),
          ...this.checks.getByCategory("ioc")
        ];
        const settled = await Promise.allSettled(
          skillChecks2.map((check) => check.run(context))
        );
        const results = settled.map((r, index) => {
          if (r.status === "fulfilled") return r.value;
          const check = skillChecks2[index];
          return {
            id: check.id,
            name: check.name,
            category: check.category,
            severity: "warning",
            passed: false,
            errored: true,
            message: `Check errored and was not completed: ${r.reason instanceof Error ? r.reason.message : String(r.reason)}`
          };
        });
        const score = computeScore(results);
        const agentResult = {
          agent: "skill-audit",
          installation: context.installation,
          results,
          score,
          grade: scoreToGrade(score)
        };
        const summary = summarizeResults(results);
        return {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          agents: [agentResult],
          totalScore: score,
          totalGrade: scoreToGrade(score),
          fleetAverage: score,
          summary
        };
      }
      emptyResult(agentFilter) {
        return {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          agents: [],
          totalScore: 100,
          totalGrade: "A",
          fleetAverage: 100,
          summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 }
        };
      }
    };
  }
});

// src/core/baseline.ts
import { readFile as readFile8, writeFile as writeFile7, mkdir as mkdir6 } from "fs/promises";
import { join as join87 } from "path";
import { homedir as homedir6 } from "os";
async function saveBaseline(result) {
  await mkdir6(BASELINES_DIR, { recursive: true });
  const filename = `baseline-${(/* @__PURE__ */ new Date()).toISOString().replace(/[:.]/g, "-")}.json`;
  const filePath = join87(BASELINES_DIR, filename);
  await writeFile7(filePath, JSON.stringify(result, null, 2), "utf-8");
  const latestPath = join87(BASELINES_DIR, "latest.json");
  await writeFile7(latestPath, JSON.stringify(result, null, 2), "utf-8");
  return filePath;
}
async function loadBaseline() {
  const latestPath = join87(BASELINES_DIR, "latest.json");
  try {
    const content = await readFile8(latestPath, "utf-8");
    return JSON.parse(content);
  } catch {
    return null;
  }
}
function installationKey(agent) {
  const inst = agent.installation;
  return [
    agent.agent,
    inst.user ?? "",
    inst.profile ?? "",
    inst.agentName ?? "",
    inst.installDir
  ].join(":");
}
function evidenceKey(finding) {
  if (!finding.evidence || finding.evidence.length === 0) return "";
  return finding.evidence.map((e) => `${e.file}:${e.line ?? ""}:${e.detail ?? e.snippet ?? ""}`).sort().join("|");
}
function findingKey(agent, finding) {
  return `${installationKey(agent)}:${finding.id}:${evidenceKey(finding)}`;
}
function diffResults(current, baseline) {
  const currentFindings = /* @__PURE__ */ new Map();
  const baselineFindings = /* @__PURE__ */ new Map();
  for (const agent of current.agents) {
    for (const r of agent.results) {
      if (!r.passed) currentFindings.set(findingKey(agent, r), r);
    }
  }
  for (const agent of baseline.agents) {
    for (const r of agent.results) {
      if (!r.passed) baselineFindings.set(findingKey(agent, r), r);
    }
  }
  const newFindings = [];
  const resolvedFindings = [];
  const unchangedFindings = [];
  for (const [key, finding] of currentFindings) {
    if (baselineFindings.has(key)) {
      unchangedFindings.push(finding);
    } else {
      newFindings.push(finding);
    }
  }
  for (const [key, finding] of baselineFindings) {
    if (!currentFindings.has(key)) {
      resolvedFindings.push(finding);
    }
  }
  return { newFindings, resolvedFindings, unchangedFindings };
}
var BASELINES_DIR;
var init_baseline = __esm({
  "src/core/baseline.ts"() {
    "use strict";
    BASELINES_DIR = join87(homedir6(), ".vaso", "baselines");
  }
});

// src/core/snapshot-fs-provider.ts
var snapshot_fs_provider_exports = {};
__export(snapshot_fs_provider_exports, {
  SnapshotFSProvider: () => SnapshotFSProvider
});
import { join as join88, basename as basename18 } from "path";
function stripTrailingSlash(name) {
  return name.endsWith("/") ? name.slice(0, -1) : name;
}
var SnapshotFSProvider;
var init_snapshot_fs_provider = __esm({
  "src/core/snapshot-fs-provider.ts"() {
    "use strict";
    SnapshotFSProvider = class {
      platform;
      snapshot;
      constructor(snapshot) {
        this.snapshot = snapshot;
        this.platform = snapshot.platform;
      }
      async readFile(path) {
        const entry = this.snapshot.files[path];
        if (!entry || !entry.exists) {
          throw new Error(`ENOENT: file not collected in snapshot: ${path}`);
        }
        return entry.content;
      }
      async readBytes(path) {
        const entry = this.snapshot.files[path];
        if (!entry || !entry.exists) {
          throw new Error(`ENOENT: file not collected in snapshot: ${path}`);
        }
        return Buffer.from(entry.content, "utf-8");
      }
      async readdir(path) {
        const listing = this.snapshot.directories[path];
        if (listing) {
          return listing.map(stripTrailingSlash);
        }
        const entries = /* @__PURE__ */ new Set();
        const prefix = path.endsWith("/") ? path : path + "/";
        for (const filePath of Object.keys(this.snapshot.files)) {
          if (filePath.startsWith(prefix)) {
            const relative4 = filePath.slice(prefix.length);
            const firstSegment = relative4.split("/")[0];
            if (firstSegment) entries.add(firstSegment);
          }
        }
        for (const dirPath of Object.keys(this.snapshot.directories)) {
          if (dirPath.startsWith(prefix) && dirPath !== path) {
            const relative4 = dirPath.slice(prefix.length);
            const firstSegment = relative4.split("/")[0];
            if (firstSegment) entries.add(firstSegment);
          }
        }
        if (entries.size > 0) return [...entries];
        throw new Error(`ENOENT: directory not collected in snapshot: ${path}`);
      }
      async readdirEntries(path, options) {
        if (options?.recursive) {
          return this.readdirRecursive(path);
        }
        const names = await this.readdir(path);
        return names.map((name) => {
          const fullPath = join88(path, name);
          const isFile2 = fullPath in this.snapshot.files && this.snapshot.files[fullPath].exists;
          const isDir = fullPath in this.snapshot.directories || this.hasChildPaths(fullPath);
          return {
            name,
            isFile: isFile2 && !isDir,
            isDirectory: isDir,
            parentPath: path
          };
        });
      }
      async access(path) {
        const fileEntry = this.snapshot.files[path];
        if (fileEntry?.exists) return true;
        if (this.directoryExists(path)) return true;
        if (this.hasChildPaths(path)) return true;
        return false;
      }
      async stat(path) {
        const fileEntry = this.snapshot.files[path];
        if (fileEntry?.exists) {
          return {
            mode: fileEntry.mode,
            isFile: () => true,
            isDirectory: () => false
          };
        }
        if (this.directoryExists(path) || this.hasChildPaths(path)) {
          return {
            mode: 493,
            isFile: () => false,
            isDirectory: () => true
          };
        }
        throw new Error(`ENOENT: path not collected in snapshot: ${path}`);
      }
      async realpath(path) {
        if (await this.access(path)) return path;
        throw new Error(`ENOENT: path not collected in snapshot: ${path}`);
      }
      async readlink(path) {
        throw new Error(`EINVAL: symlink targets not collected in snapshot: ${path}`);
      }
      async exec(cmd, args, _options) {
        const output = this.findCommandOutput(cmd, args);
        if (!output) {
          return {
            stdout: "",
            stderr: `Command not collected in snapshot: ${cmd} ${args.join(" ")}`,
            exitCode: 127
          };
        }
        return {
          stdout: output.stdout,
          stderr: output.stderr,
          exitCode: output.exitCode
        };
      }
      execSync(cmd, args, _options) {
        const output = this.findCommandOutput(cmd, args);
        if (!output) {
          throw new Error(`Command not collected in snapshot: ${cmd} ${args.join(" ")}`);
        }
        if (output.exitCode !== 0) {
          throw new Error(`Command failed (exit ${output.exitCode}): ${output.stderr}`);
        }
        return output.stdout;
      }
      homedir() {
        return this.snapshot.homedir;
      }
      hostname() {
        return this.snapshot.hostname;
      }
      getEnv(key) {
        return this.snapshot.env?.[key];
      }
      get privilege() {
        return this.snapshot.privilege;
      }
      /**
       * Returns true only when the snapshot has an explicit, non-null listing for
       * the given directory. Older probes (and the Go zero-value behaviour) could
       * insert keys with `null` listings when `os.ReadDir` failed for a missing
       * directory; treating those as "exists" produces false-positive agent
       * detections, so they're filtered out here.
       */
      directoryExists(path) {
        if (!(path in this.snapshot.directories)) return false;
        const listing = this.snapshot.directories[path];
        return Array.isArray(listing);
      }
      hasChildPaths(path) {
        const prefix = path.endsWith("/") ? path : path + "/";
        for (const [key, entry] of Object.entries(this.snapshot.files)) {
          if (key.startsWith(prefix) && entry.exists) return true;
        }
        for (const [key, listing] of Object.entries(this.snapshot.directories)) {
          if (key.startsWith(prefix) && Array.isArray(listing)) return true;
        }
        return false;
      }
      readdirRecursive(basePath) {
        const results = [];
        const prefix = basePath.endsWith("/") ? basePath : basePath + "/";
        for (const [filePath, entry] of Object.entries(this.snapshot.files)) {
          if (!filePath.startsWith(prefix) || !entry.exists) continue;
          const relative4 = filePath.slice(prefix.length);
          const name = relative4.split("/").pop() || relative4;
          const parentPath = filePath.slice(0, filePath.length - name.length - 1) || basePath;
          results.push({
            name,
            isFile: true,
            isDirectory: false,
            parentPath
          });
        }
        return results;
      }
      findCommandOutput(cmd, args) {
        const cmdBase = basename18(cmd);
        const fullKey = `${cmd} ${args.join(" ")}`.trim();
        if (this.snapshot.commandOutputs[fullKey]) {
          return this.snapshot.commandOutputs[fullKey];
        }
        if (cmdBase !== cmd) {
          const baseKey = `${cmdBase} ${args.join(" ")}`.trim();
          if (this.snapshot.commandOutputs[baseKey]) {
            return this.snapshot.commandOutputs[baseKey];
          }
        }
        if (cmdBase === "which" && args.length > 0) {
          const target = basename18(args[0]);
          const whichId = `${target}-which`;
          if (this.snapshot.commandOutputs[whichId]) {
            return this.snapshot.commandOutputs[whichId];
          }
        }
        for (const [id, output] of Object.entries(this.snapshot.commandOutputs)) {
          const idParts = id.split("-");
          if (idParts[0] === cmdBase || id.startsWith(cmdBase)) {
            const idLower = id.toLowerCase();
            if (idLower.includes(cmdBase) && (args.length === 0 || this.argsMatchId(id, cmdBase, args))) {
              return output;
            }
          }
        }
        return void 0;
      }
      argsMatchId(id, cmd, args) {
        const suffix = id.slice(cmd.length).replace(/^[-_]/, "");
        if (!suffix) return true;
        return args.some((arg) => {
          const cleaned = arg.replace(/^-+/, "");
          return suffix.toLowerCase().includes(cleaned.toLowerCase());
        });
      }
    };
  }
});

// src/core/exit-criteria.ts
function isValidFailOn(value) {
  return FAIL_ON_LEVELS.includes(value);
}
function shouldFailScan(results, failOn) {
  if (failOn === "none") return false;
  const threshold = SEVERITY_RANK[failOn];
  for (const r of results) {
    if (r.passed) continue;
    if (SEVERITY_RANK[r.severity] >= threshold) return true;
  }
  return false;
}
var FAIL_ON_LEVELS, SEVERITY_RANK;
var init_exit_criteria = __esm({
  "src/core/exit-criteria.ts"() {
    "use strict";
    FAIL_ON_LEVELS = ["critical", "warning", "info", "none"];
    SEVERITY_RANK = {
      info: 1,
      warning: 2,
      critical: 3
    };
  }
});

// src/transport/probe-fetch.ts
import { createHash as createHash5 } from "crypto";
import { readFile as readFile9, writeFile as writeFile8, mkdir as mkdir7, access, chmod as chmod2 } from "fs/promises";
import { constants as FS } from "fs";
import { homedir as homedir7 } from "os";
import { join as join89, dirname as dirname8 } from "path";
async function isFile(p) {
  try {
    await access(p, FS.F_OK);
    return true;
  } catch {
    return false;
  }
}
function sha256(buf) {
  return "sha256:" + createHash5("sha256").update(buf).digest("hex");
}
async function loadChecksums(pkgRoot) {
  const path = join89(pkgRoot, "probe", "checksums.json");
  let raw;
  try {
    raw = await readFile9(path, "utf-8");
  } catch {
    throw new Error(
      "probe/checksums.json is missing from this VASO install, so a fetched probe binary cannot be verified.\n  Reinstall VASO, or build the probe locally: cd probe && make"
    );
  }
  return JSON.parse(raw);
}
async function resolveProbeBinary(os, arch, opts) {
  const name = `vaso-probe-${os}-${arch}`;
  const pkgRoot = opts.pkgRoot ?? join89(opts.probeBinDir, "..", "..");
  const cacheRoot = opts.cacheRoot ?? join89(homedir7(), ".vaso", "probe");
  const repo = opts.repo ?? "vulnex/vaso";
  const fetchImpl = opts.fetchImpl ?? fetch;
  const local = join89(opts.probeBinDir, name);
  if (await isFile(local)) return local;
  const sums = await loadChecksums(pkgRoot);
  const expected = sums.binaries[name];
  if (!expected) {
    throw new Error(
      `This VASO build (${sums.version}) ships no probe checksum for ${os}/${arch}, so remote scanning of that platform is unsupported.
  Build a probe locally if needed: cd probe && make`
    );
  }
  const cached = join89(cacheRoot, sums.version, name);
  if (await isFile(cached)) {
    const buf2 = await readFile9(cached);
    if (sha256(buf2) === expected) return cached;
  }
  const url = `https://github.com/${repo}/releases/download/v${sums.version}/${name}`;
  let res;
  try {
    res = await fetchImpl(url);
  } catch (err) {
    throw new Error(
      `Failed to download vaso-probe for ${os}/${arch} from ${url}: ${err.message}
  Build it locally instead: cd probe && make`
    );
  }
  if (!res.ok) {
    throw new Error(
      `vaso-probe asset for ${os}/${arch} not found (HTTP ${res.status} at ${url}).
  This VASO release may not publish probe binaries; build one locally: cd probe && make`
    );
  }
  const buf = Buffer.from(await res.arrayBuffer());
  const got = sha256(buf);
  if (got !== expected) {
    throw new Error(
      `Checksum mismatch for downloaded ${name}: expected ${expected}, got ${got}. Refusing to use it.`
    );
  }
  await mkdir7(dirname8(cached), { recursive: true });
  await writeFile8(cached, buf);
  await chmod2(cached, 493);
  return cached;
}
var init_probe_fetch = __esm({
  "src/transport/probe-fetch.ts"() {
    "use strict";
  }
});

// src/transport/ssh.ts
var ssh_exports = {};
__export(ssh_exports, {
  executeRemoteProbe: () => executeRemoteProbe,
  executeRemoteProbeWithRetry: () => executeRemoteProbeWithRetry,
  parseSSHTarget: () => parseSSHTarget,
  withRetry: () => withRetry
});
import { spawn, execFileSync as execFileSync2 } from "child_process";
import { randomUUID } from "crypto";
import { writeFile as writeFile9, unlink as unlink3 } from "fs/promises";
function parseSSHTarget(target) {
  const atIdx = target.indexOf("@");
  if (atIdx === -1) {
    throw new Error(`Invalid SSH target "${target}": expected user@host[:port]`);
  }
  const user = target.slice(0, atIdx);
  const rest = target.slice(atIdx + 1);
  let host;
  let port = 22;
  const colonIdx = rest.lastIndexOf(":");
  if (colonIdx !== -1) {
    const maybePart = rest.slice(colonIdx + 1);
    const parsed = parseInt(maybePart, 10);
    if (!isNaN(parsed) && parsed > 0 && parsed <= 65535) {
      host = rest.slice(0, colonIdx);
      port = parsed;
    } else {
      host = rest;
    }
  } else {
    host = rest;
  }
  if (!host) {
    throw new Error(`Invalid SSH target "${target}": missing hostname`);
  }
  const label = port === 22 ? `${user}@${host}` : `${user}@${host}:${port}`;
  return { user, host, port, label };
}
function establishControlMaster(target, controlPath, timeout) {
  return new Promise((resolve6, reject) => {
    const args = [
      "-o",
      "ControlMaster=yes",
      "-o",
      `ControlPath=${controlPath}`,
      "-o",
      "ControlPersist=120",
      "-o",
      "StrictHostKeyChecking=accept-new",
      "-o",
      "ConnectTimeout=10",
      "-p",
      String(target.port)
    ];
    if (target.identity) args.push("-i", target.identity);
    args.push(`${target.user}@${target.host}`, "-N");
    const child = spawn("ssh", args, {
      stdio: "inherit",
      // Full terminal access for password prompts
      timeout
    });
    child.on("close", (code) => {
      if (code === 0) resolve6();
      else reject(new Error(`SSH connection to ${target.user}@${target.host} failed (exit ${code})`));
    });
    child.on("error", reject);
  });
}
function runOverControl(cmd, args, options = {}) {
  return new Promise((resolve6, reject) => {
    const child = spawn(cmd, args, {
      stdio: ["pipe", "pipe", "pipe"],
      timeout: options.timeout
    });
    const chunks = [];
    const errChunks = [];
    child.stdout.on("data", (d) => chunks.push(d));
    child.stderr.on("data", (d) => errChunks.push(d));
    child.on("close", (code) => {
      const stdout = Buffer.concat(chunks).toString("utf-8");
      const stderr = Buffer.concat(errChunks).toString("utf-8");
      if (code === 0) {
        resolve6({ stdout, stderr });
      } else {
        reject(new Error(`Command failed: ${cmd} ${args.slice(-1).join(" ")}
${stderr || stdout}`.trim()));
      }
    });
    child.on("error", reject);
  });
}
function controlSSHArgs(target, controlPath, remoteCmd) {
  const args = [
    "-o",
    `ControlPath=${controlPath}`,
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-p",
    String(target.port)
  ];
  if (target.identity) args.push("-i", target.identity);
  args.push(`${target.user}@${target.host}`, ...remoteCmd);
  return args;
}
function controlSCPArgs(target, controlPath, localPath, remotePath) {
  const args = [
    "-o",
    `ControlPath=${controlPath}`,
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-P",
    String(target.port)
  ];
  if (target.identity) args.push("-i", target.identity);
  args.push(localPath, `${target.user}@${target.host}:${remotePath}`);
  return args;
}
function closeControlMaster(target, controlPath) {
  try {
    execFileSync2("ssh", [
      "-o",
      `ControlPath=${controlPath}`,
      "-O",
      "exit",
      `${target.user}@${target.host}`
    ], { timeout: 5e3, stdio: "pipe" });
  } catch {
  }
}
async function detectRemotePlatform(target, controlPath, timeout) {
  const { stdout } = await runOverControl(
    "ssh",
    controlSSHArgs(target, controlPath, ["uname -s && uname -m"]),
    { timeout }
  );
  const lines = stdout.trim().split("\n");
  if (lines.length < 2) throw new Error(`Unexpected uname output from ${target.host}: ${stdout}`);
  const os = lines[0].trim().toLowerCase();
  const rawArch = lines[1].trim().toLowerCase();
  let arch;
  switch (rawArch) {
    case "x86_64":
      arch = "amd64";
      break;
    case "aarch64":
    case "arm64":
      arch = "arm64";
      break;
    default:
      throw new Error(`Unsupported architecture on ${target.host}: ${rawArch}`);
  }
  if (os !== "linux" && os !== "darwin") {
    throw new Error(
      `Unsupported platform on ${target.host}: ${os}/${arch}
  vaso-probe binaries are available for Linux and macOS (amd64/arm64).`
    );
  }
  return { os, arch };
}
async function withRetry(opts) {
  const sleep = opts.sleep ?? defaultSleep;
  let lastErr;
  for (let attempt = 0; attempt <= opts.retries; attempt++) {
    if (attempt > 0) {
      await sleep(attempt);
      opts.onRetry?.(attempt, lastErr);
    }
    try {
      return await opts.fn();
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}
async function executeRemoteProbeWithRetry(target, options, retry) {
  return withRetry({
    retries: retry.retries,
    fn: () => executeRemoteProbe(target, options),
    onRetry: retry.onRetry ? (attempt, err) => retry.onRetry(target, attempt, err) : void 0
  });
}
async function executeRemoteProbe(target, options) {
  const timeout = options.timeout ?? 6e4;
  const uuid = randomUUID().slice(0, 8);
  const controlPath = `/tmp/vaso-ssh-${uuid}`;
  const remoteProbePath = `/tmp/vaso-probe-${uuid}`;
  const remoteManifestPath = `/tmp/vaso-manifest-${uuid}.json`;
  const localManifestPath = `/tmp/vaso-manifest-local-${uuid}.json`;
  try {
    await establishControlMaster(target, controlPath, timeout);
    const platform = await detectRemotePlatform(target, controlPath, timeout);
    const localBinary = await resolveProbeBinary(platform.os, platform.arch, {
      probeBinDir: options.probeBinDir
    });
    await writeFile9(localManifestPath, JSON.stringify(options.manifest), "utf-8");
    await runOverControl("scp", controlSCPArgs(target, controlPath, localBinary, remoteProbePath), { timeout });
    await runOverControl("scp", controlSCPArgs(target, controlPath, localManifestPath, remoteManifestPath), { timeout });
    await runOverControl("ssh", controlSSHArgs(target, controlPath, [`chmod +x ${remoteProbePath}`]), { timeout: 1e4 });
    const probeCmd2 = `${remoteProbePath} --manifest ${remoteManifestPath}${target.sudo ? " --escalate" : ""}`;
    const { stdout } = await runOverControl("ssh", controlSSHArgs(target, controlPath, [probeCmd2]), { timeout });
    return JSON.parse(stdout);
  } finally {
    await unlink3(localManifestPath).catch(() => {
    });
    try {
      await runOverControl("ssh", controlSSHArgs(target, controlPath, [`rm -f ${remoteProbePath} ${remoteManifestPath}`]), { timeout: 1e4 });
    } catch {
    }
    closeControlMaster(target, controlPath);
  }
}
var defaultSleep;
var init_ssh = __esm({
  "src/transport/ssh.ts"() {
    "use strict";
    init_probe_fetch();
    defaultSleep = (attempt) => new Promise((r) => setTimeout(r, Math.min(1e3 * 2 ** (attempt - 1), 8e3)));
  }
});

// src/transport/inventory.ts
var inventory_exports = {};
__export(inventory_exports, {
  parseInventory: () => parseInventory
});
import { readFile as readFile10 } from "fs/promises";
import { parse as parseYAML } from "yaml";
async function parseInventory(path) {
  const raw = await readFile10(path, "utf-8");
  const doc = parseYAML(raw);
  if (!doc || !Array.isArray(doc.hosts)) {
    throw new Error(`Invalid inventory file "${path}": expected a "hosts" array`);
  }
  return doc.hosts.map((entry, idx) => {
    if (!entry.host) {
      throw new Error(`Inventory entry #${idx + 1} missing required "host" field`);
    }
    const user = entry.user ?? "root";
    const port = entry.port ?? 22;
    const defaultLabel = port === 22 ? `${user}@${entry.host}` : `${user}@${entry.host}:${port}`;
    return {
      user,
      host: entry.host,
      port,
      label: entry.label ?? defaultLabel,
      identity: entry.identity,
      sudo: entry.sudo
    };
  });
}
var init_inventory = __esm({
  "src/transport/inventory.ts"() {
    "use strict";
  }
});

// src/transport/multi-host.ts
var multi_host_exports = {};
__export(multi_host_exports, {
  runConcurrent: () => runConcurrent,
  scanMultipleHosts: () => scanMultipleHosts
});
async function runConcurrent(items, concurrency, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workerCount = Math.min(Math.max(concurrency, 1), items.length);
  async function worker() {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: workerCount }, worker));
  return results;
}
async function scanMultipleHosts(options) {
  const { targets, transportOptions, scanOptions } = options;
  const concurrency = options.concurrency ?? 5;
  const retries = options.retries ?? 0;
  const { ScanEngine: ScanEngine2 } = await Promise.resolve().then(() => (init_engine(), engine_exports));
  const { adapterRegistry: adapterRegistry2 } = await Promise.resolve().then(() => (init_registry(), registry_exports));
  const { checkRegistry: checkRegistry2 } = await Promise.resolve().then(() => (init_check_registry(), check_registry_exports));
  const { SnapshotFSProvider: SnapshotFSProvider2 } = await Promise.resolve().then(() => (init_snapshot_fs_provider(), snapshot_fs_provider_exports));
  const { executeRemoteProbeWithRetry: executeRemoteProbeWithRetry2 } = await Promise.resolve().then(() => (init_ssh(), ssh_exports));
  async function processTarget(target) {
    const start = Date.now();
    let entry;
    try {
      const snapshot = await executeRemoteProbeWithRetry2(
        target,
        {
          probeBinDir: transportOptions.probeBinDir,
          manifest: transportOptions.manifest,
          timeout: transportOptions.timeout
        },
        { retries, onRetry: options.onRetry }
      );
      if (options.onSnapshot) {
        await options.onSnapshot(target, snapshot);
      }
      const snapshotFs = new SnapshotFSProvider2(snapshot);
      const engine = new ScanEngine2(adapterRegistry2, checkRegistry2, snapshotFs);
      const result = await engine.scan({
        agentFilter: scanOptions.agentFilter
      });
      result.host = snapshot.hostname;
      result.label = target.label;
      entry = {
        target,
        result,
        durationMs: Date.now() - start
      };
    } catch (err) {
      entry = {
        target,
        error: err.message,
        durationMs: Date.now() - start
      };
    }
    if (options.onComplete) {
      await options.onComplete(entry);
    }
    return entry;
  }
  return runConcurrent(targets, concurrency, processTarget);
}
var init_multi_host = __esm({
  "src/transport/multi-host.ts"() {
    "use strict";
  }
});

// src/core/manifest-builder.ts
var manifest_builder_exports = {};
__export(manifest_builder_exports, {
  buildProbeManifest: () => buildProbeManifest
});
function buildProbeManifest(adapters) {
  const merged = {
    filePaths: [],
    globPatterns: [],
    commands: [],
    directoryListings: [],
    envPrefixes: [],
    systemPaths: [],
    systemDirListings: []
  };
  for (const adapter of adapters) {
    if (adapter.getProbeManifest) {
      const m = adapter.getProbeManifest();
      merged.filePaths.push(...m.filePaths);
      merged.globPatterns.push(...m.globPatterns);
      merged.commands.push(...m.commands);
      merged.directoryListings.push(...m.directoryListings);
      merged.envPrefixes.push(...m.envPrefixes);
      if (m.systemPaths) merged.systemPaths.push(...m.systemPaths);
      if (m.systemDirListings) merged.systemDirListings.push(...m.systemDirListings);
    }
  }
  merged.commands.push(
    { id: "netstat-tcp", cmd: "netstat", args: ["-an", "-p", "tcp"], timeout: 5e3 },
    { id: "ss-tcp", cmd: "ss", args: ["-tn"], timeout: 5e3 },
    { id: "ps-ancestry", cmd: "ps", args: ["-eo", "pid,ppid,comm"], timeout: 5e3 },
    { id: "crontab-list", cmd: "crontab", args: ["-l"], timeout: 5e3 },
    { id: "launchctl-list", cmd: "launchctl", args: ["list"], timeout: 5e3 }
  );
  merged.directoryListings.push("~/Library/LaunchAgents");
  merged.systemDirListings.push("/Library/LaunchAgents", "/Library/LaunchDaemons");
  merged.filePaths.push(
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/.config/Claude/claude_desktop_config.json",
    "~/.cursor/mcp.json",
    "~/.codeium/windsurf/mcp_config.json"
  );
  merged.filePaths = [...new Set(merged.filePaths)];
  merged.globPatterns = [...new Set(merged.globPatterns)];
  merged.directoryListings = [...new Set(merged.directoryListings)];
  merged.envPrefixes = [...new Set(merged.envPrefixes)];
  merged.systemPaths = [...new Set(merged.systemPaths)];
  merged.systemDirListings = [...new Set(merged.systemDirListings)];
  const seen = /* @__PURE__ */ new Set();
  merged.commands = merged.commands.filter((c) => {
    if (seen.has(c.id)) return false;
    seen.add(c.id);
    return true;
  });
  return merged;
}
var init_manifest_builder = __esm({
  "src/core/manifest-builder.ts"() {
    "use strict";
  }
});

// src/commands/scan.ts
var scan_exports = {};
__export(scan_exports, {
  runScan: () => runScan
});
import chalk2 from "chalk";
import { readFile as readFile11, writeFile as writeFile10 } from "fs/promises";
function safeHostname(host) {
  return host.replace(/[^A-Za-z0-9._-]/g, "_");
}
function parsePositiveInt(raw, fallback, label) {
  if (raw === void 0) return fallback;
  const n = parseInt(raw, 10);
  if (isNaN(n) || n < 0) {
    throw new Error(`Invalid ${label} value "${raw}": expected a non-negative integer`);
  }
  return n;
}
async function runScan(options) {
  const failOn = options.failOn && isValidFailOn(options.failOn) ? options.failOn : "critical";
  if (options.failOn && !isValidFailOn(options.failOn)) {
    console.error(chalk2.red(`Invalid --fail-on value "${options.failOn}". Use: critical, warning, info, or none.`));
    process.exitCode = 2;
    return;
  }
  if (options.output && options.outputDir) {
    console.error(chalk2.red("--output and --output-dir are mutually exclusive"));
    process.exitCode = 2;
    return;
  }
  if (options.silent && !options.output && !options.outputDir) {
    console.error(chalk2.red("--silent requires -o/--output or --output-dir"));
    process.exitCode = 2;
    return;
  }
  let snapshotFs;
  if (options.snapshot) {
    let raw;
    try {
      raw = await readFile11(options.snapshot, "utf-8");
    } catch (err) {
      const code = err.code;
      console.error(chalk2.red(code === "ENOENT" ? `Snapshot file not found: ${options.snapshot}` : `Failed to read snapshot file: ${err.message}`));
      process.exitCode = 1;
      return;
    }
    let snapshot;
    try {
      snapshot = JSON.parse(raw);
    } catch (err) {
      console.error(chalk2.red(`Snapshot file is not valid JSON: ${err.message}`));
      process.exitCode = 1;
      return;
    }
    const errors = [];
    if (snapshot.version !== 1) errors.push(`Unsupported snapshot version: ${snapshot.version}`);
    if (!snapshot.platform) errors.push("Missing platform field");
    if (!snapshot.hostname) errors.push("Missing hostname field");
    if (!snapshot.files || typeof snapshot.files !== "object") errors.push("Missing or invalid files field");
    if (!snapshot.directories || typeof snapshot.directories !== "object") errors.push("Missing or invalid directories field");
    if (!snapshot.commandOutputs || typeof snapshot.commandOutputs !== "object") errors.push("Missing or invalid commandOutputs field");
    if (errors.length > 0) {
      console.error(chalk2.red("Invalid snapshot file:"));
      for (const e of errors) console.error(chalk2.red(`  - ${e}`));
      process.exitCode = 1;
      return;
    }
    snapshotFs = new SnapshotFSProvider(snapshot);
    if (!options.silent) {
      if (snapshot.privilege && !snapshot.privilege.isRoot) {
        console.log(chalk2.yellow(`  Warning: snapshot collected as non-root user "${snapshot.privilege.username}" \u2014 scan coverage may be limited.
`));
      }
      console.log(chalk2.dim(`  Scanning snapshot from host "${snapshot.hostname}" (${snapshot.platform})
`));
    }
  }
  if (options.host || options.inventory) {
    const { parseSSHTarget: parseSSHTarget2 } = await Promise.resolve().then(() => (init_ssh(), ssh_exports));
    const { parseInventory: parseInventory2 } = await Promise.resolve().then(() => (init_inventory(), inventory_exports));
    const { scanMultipleHosts: scanMultipleHosts2 } = await Promise.resolve().then(() => (init_multi_host(), multi_host_exports));
    const { buildProbeManifest: buildProbeManifest2 } = await Promise.resolve().then(() => (init_manifest_builder(), manifest_builder_exports));
    const silent = !!options.silent;
    const log = (msg) => {
      if (!silent) console.log(msg);
    };
    let concurrency;
    let retries;
    try {
      concurrency = parsePositiveInt(options.parallel, 5, "--parallel");
      retries = parsePositiveInt(options.sshRetries, 0, "--ssh-retries");
      if (concurrency === 0) throw new Error("--parallel must be at least 1");
    } catch (err) {
      console.error(chalk2.red(err.message));
      process.exitCode = 2;
      return;
    }
    if (options.output && NON_AGGREGATABLE_FORMATS.has(options.format)) {
      console.error(chalk2.red(
        `--output cannot aggregate ${options.format} across multiple hosts. Use --output-dir <dir> instead \u2014 each host will be written as <hostname>.${FORMAT_EXT[options.format]}.`
      ));
      process.exitCode = 2;
      return;
    }
    let targets = [];
    if (options.host) {
      targets = options.host.map((h) => {
        const t = parseSSHTarget2(h);
        if (options.sshKey) t.identity = options.sshKey;
        if (options.sudo) t.sudo = true;
        return t;
      });
    }
    if (options.inventory) {
      const inventoryTargets = await parseInventory2(options.inventory);
      for (const t of inventoryTargets) {
        if (options.sshKey && !t.identity) t.identity = options.sshKey;
        if (options.sudo) t.sudo = true;
      }
      targets.push(...inventoryTargets);
    }
    if (targets.length === 0) {
      console.error(chalk2.red("No scan targets specified"));
      process.exitCode = 1;
      return;
    }
    const { dirname: dirname11, join: join98 } = await import("path");
    const { fileURLToPath: fileURLToPath2 } = await import("url");
    const vasoRoot = join98(dirname11(fileURLToPath2(import.meta.url)), "..");
    const probeBinDir = join98(vasoRoot, "probe", "dist");
    const manifest = buildProbeManifest2(adapterRegistry.getAdapters());
    const timeout = parseInt(options.sshTimeout ?? "60", 10) * 1e3;
    log(chalk2.bold(`
  Scanning ${targets.length} remote host(s)...
`));
    let saveSnapshotDir;
    if (options.saveSnapshot) {
      const { mkdir: mkdir13 } = await import("fs/promises");
      saveSnapshotDir = options.saveSnapshot;
      await mkdir13(saveSnapshotDir, { recursive: true });
    }
    if (options.outputDir) {
      const { mkdir: mkdir13 } = await import("fs/promises");
      await mkdir13(options.outputDir, { recursive: true });
    }
    const reporter = getReporter(options.format ?? "terminal");
    const ext = FORMAT_EXT[options.format] ?? "txt";
    const hostResults = await scanMultipleHosts2({
      targets,
      transportOptions: { probeBinDir, manifest, timeout },
      scanOptions: {
        agentFilter: options.agent,
        format: options.format
      },
      concurrency,
      retries,
      onSnapshot: saveSnapshotDir ? async (target, snapshot) => {
        try {
          const { join: joinPath } = await import("path");
          const safeHost = safeHostname(snapshot.hostname ?? target.host);
          const outPath = joinPath(saveSnapshotDir, `${safeHost}.json`);
          await writeFile10(outPath, JSON.stringify(snapshot, null, 2), "utf-8");
          log(chalk2.dim(`  Saved snapshot for ${target.host} \u2192 ${outPath}`));
        } catch (err) {
          log(chalk2.yellow(`  Warning: failed to save snapshot for ${target.host}: ${err.message}`));
        }
      } : void 0,
      onRetry: (target, attempt, err) => {
        log(chalk2.yellow(`  Retry ${attempt}/${retries} for ${target.host}: ${err.message.split("\n")[0]}`));
      },
      onComplete: async (entry) => {
        const label = entry.target.label ?? `${entry.target.user}@${entry.target.host}`;
        const dur = `${entry.durationMs}ms`;
        if (entry.error) {
          log(chalk2.red(`  \u2717 ${label} (${dur}): ${entry.error.split("\n")[0]}`));
        } else if (entry.result) {
          const findings = entry.result.summary;
          const summary = `${findings.critical}C / ${findings.warning}W / ${findings.info}I`;
          log(chalk2.green(`  \u2713 ${label} (${dur}) \u2014 score ${entry.result.totalScore}/100, ${summary}`));
          if (options.outputDir) {
            try {
              const { join: joinPath } = await import("path");
              const safeHost = safeHostname(entry.result.host ?? entry.target.host);
              const outPath = joinPath(options.outputDir, `${safeHost}.${ext}`);
              await writeFile10(outPath, reporter.render(entry.result), "utf-8");
            } catch (err) {
              log(chalk2.yellow(`  Warning: failed to write output for ${entry.target.host}: ${err.message}`));
            }
          }
        }
      }
    });
    const successResults = hostResults.filter((hr) => hr.result);
    const failedResults = hostResults.filter((hr) => hr.error);
    if (options.outputDir) {
      log(chalk2.green(`
  Wrote ${successResults.length} report(s) to ${options.outputDir}/`));
    } else if (options.output) {
      let combined;
      if (options.format === "json") {
        const aggregate = hostResults.map((hr) => ({
          target: {
            user: hr.target.user,
            host: hr.target.host,
            port: hr.target.port,
            label: hr.target.label
          },
          durationMs: hr.durationMs,
          error: hr.error,
          result: hr.result
        }));
        combined = JSON.stringify(aggregate, null, 2);
      } else {
        const sections = [];
        for (const hr of successResults) {
          if (!hr.result) continue;
          const label = hr.target.label ?? `${hr.target.user}@${hr.target.host}`;
          sections.push(`\u2500\u2500 ${label} (${hr.result.host ?? hr.target.host}) \u2500\u2500

${reporter.render(hr.result)}`);
        }
        if (failedResults.length > 0) {
          const failLines = failedResults.map((hr) => {
            const label = hr.target.label ?? `${hr.target.user}@${hr.target.host}`;
            return `  \u2717 ${label}: ${hr.error}`;
          });
          sections.push(`Failed hosts (${failedResults.length}):
${failLines.join("\n")}`);
        }
        sections.push(`Summary: ${successResults.length} scanned, ${failedResults.length} failed`);
        combined = sections.join("\n\n");
      }
      await writeFileEnsureDir(options.output, combined);
      log(chalk2.green(`Report written to ${options.output}`));
    } else {
      for (const hr of successResults) {
        if (hr.result) {
          const label = hr.target.label ?? `${hr.target.user}@${hr.target.host}`;
          log(chalk2.bold(`
\u2500\u2500 ${label} (${hr.result.host ?? hr.target.host}) \u2500\u2500
`));
          log(reporter.render(hr.result));
        }
      }
      if (failedResults.length > 0) {
        log(chalk2.bold(chalk2.red(`
  Failed hosts (${failedResults.length}):`)));
        for (const hr of failedResults) {
          const label = hr.target.label ?? `${hr.target.user}@${hr.target.host}`;
          log(chalk2.red(`    \u2717 ${label}: ${hr.error}`));
        }
      }
      log(chalk2.bold(`
  Summary: ${successResults.length} scanned, ${failedResults.length} failed
`));
    }
    const allResults = successResults.flatMap(
      (hr) => hr.result?.agents.flatMap((a) => a.results) ?? []
    );
    if (shouldFailScan(allResults, failOn) || failedResults.length > 0) {
      process.exitCode = 1;
    }
    return;
  }
  const localSilent = !!options.silent;
  const localLog = (msg) => {
    if (!localSilent) console.log(msg);
  };
  const engine = new ScanEngine(adapterRegistry, checkRegistry, snapshotFs);
  const scanOptions = {
    agentFilter: options.agent,
    format: options.format,
    saveBaseline: options.saveBaseline,
    diff: options.diff,
    allUsers: options.allUsers
  };
  try {
    const result = await engine.scan(scanOptions);
    if (snapshotFs) {
      result.host = snapshotFs.hostname();
    }
    if (options.saveBaseline) {
      const path = await saveBaseline(result);
      localLog(chalk2.green(`Baseline saved to ${path}`));
    }
    if (options.diff) {
      const baseline = await loadBaseline();
      if (baseline) {
        const diff = diffResults(result, baseline);
        localLog(chalk2.bold("\nDifferential Scan Results:"));
        localLog(`  New findings: ${chalk2.red(String(diff.newFindings.length))}`);
        localLog(`  Resolved: ${chalk2.green(String(diff.resolvedFindings.length))}`);
        localLog(`  Unchanged: ${chalk2.dim(String(diff.unchangedFindings.length))}`);
        if (diff.newFindings.length > 0) {
          localLog(chalk2.bold("\n  New findings:"));
          for (const f of diff.newFindings) {
            localLog(`    ${chalk2.red("[NEW]")} ${f.id}: ${f.name} \u2014 ${f.message}`);
          }
        }
        if (diff.resolvedFindings.length > 0) {
          localLog(chalk2.bold("\n  Resolved:"));
          for (const f of diff.resolvedFindings) {
            localLog(`    ${chalk2.green("[RESOLVED]")} ${f.id}: ${f.name}`);
          }
        }
        localLog("");
      } else {
        localLog(chalk2.yellow("No baseline found. Run with --save-baseline first."));
      }
    }
    const reporter = getReporter(scanOptions.format ?? "terminal");
    const output = reporter.render(result);
    if (options.output) {
      await writeFileEnsureDir(options.output, output);
      localLog(chalk2.green(`Report written to ${options.output}`));
    } else {
      console.log(output);
    }
    const allResults = result.agents.flatMap((a) => a.results);
    if (shouldFailScan(allResults, failOn)) {
      process.exitCode = 1;
    }
  } catch (err) {
    logError(chalk2.red("Scan failed:"), err);
    process.exitCode = 1;
  }
}
var FORMAT_EXT, NON_AGGREGATABLE_FORMATS;
var init_scan = __esm({
  "src/commands/scan.ts"() {
    "use strict";
    init_engine();
    init_registry();
    init_check_registry();
    init_reporting();
    init_baseline();
    init_snapshot_fs_provider();
    init_exit_criteria();
    init_debug();
    init_utils();
    FORMAT_EXT = {
      terminal: "txt",
      json: "json",
      sarif: "sarif",
      markdown: "md",
      html: "html",
      csv: "csv",
      junit: "xml"
    };
    NON_AGGREGATABLE_FORMATS = /* @__PURE__ */ new Set(["sarif", "junit"]);
  }
});

// src/commands/detect.ts
var detect_exports = {};
__export(detect_exports, {
  runDetect: () => runDetect
});
import chalk3 from "chalk";
function safeHostname2(host) {
  return host.replace(/[^A-Za-z0-9._-]/g, "_");
}
function parsePositiveInt2(raw, fallback, label) {
  if (raw === void 0) return fallback;
  const n = parseInt(raw, 10);
  if (isNaN(n) || n < 0) {
    throw new Error(`Invalid ${label} value "${raw}": expected a non-negative integer`);
  }
  return n;
}
async function emit(text, output, silent) {
  if (output) {
    await writeFileEnsureDir(output, text);
    if (!silent) console.log(chalk3.green(`Report written to ${output}`));
  } else {
    console.log(text);
  }
}
async function runDetect(options) {
  if (options.silent && !options.output && !options.outputDir) {
    console.error(chalk3.red("--silent requires -o/--output or --output-dir"));
    process.exitCode = 2;
    return;
  }
  if (options.output && options.outputDir) {
    console.error(chalk3.red("--output and --output-dir are mutually exclusive"));
    process.exitCode = 2;
    return;
  }
  try {
    if (options.snapshot) {
      const results = await detectFromSnapshot(options);
      await renderResults(results, options);
      return;
    }
    if (options.host || options.inventory) {
      await detectRemoteHosts(options);
      return;
    }
    let installations = await adapterRegistry.detectAll({
      allUsers: options.allUsers
    });
    if (options.agent) {
      const agentType = options.agent;
      installations = installations.filter((i) => i.agent === agentType);
    }
    await renderResults(installations, options);
  } catch (err) {
    logError(chalk3.red("Detection failed:"), err);
    process.exitCode = 1;
  }
}
async function detectFromSnapshot(options) {
  const { readFile: readFile18 } = await import("fs/promises");
  const { SnapshotFSProvider: SnapshotFSProvider2 } = await Promise.resolve().then(() => (init_snapshot_fs_provider(), snapshot_fs_provider_exports));
  const raw = await readFile18(options.snapshot, "utf-8");
  const snapshot = JSON.parse(raw);
  const errors = [];
  if (snapshot.version !== 1) errors.push(`Unsupported snapshot version: ${snapshot.version}`);
  if (!snapshot.platform) errors.push("Missing platform field");
  if (!snapshot.hostname) errors.push("Missing hostname field");
  if (!snapshot.files || typeof snapshot.files !== "object") errors.push("Missing or invalid files field");
  if (errors.length > 0) {
    console.error(chalk3.red("Invalid snapshot file:"));
    for (const e of errors) console.error(chalk3.red(`  - ${e}`));
    process.exitCode = 1;
    return [];
  }
  const snapshotFs = new SnapshotFSProvider2(snapshot);
  console.log(chalk3.dim(`  Detecting agents from snapshot "${snapshot.hostname}" (${snapshot.platform})
`));
  let installations = await adapterRegistry.detectAll({
    allUsers: options.allUsers,
    fs: snapshotFs
  });
  if (options.agent) {
    installations = installations.filter((i) => i.agent === options.agent);
  }
  return installations;
}
async function detectRemoteHosts(options) {
  const { parseSSHTarget: parseSSHTarget2, executeRemoteProbeWithRetry: executeRemoteProbeWithRetry2 } = await Promise.resolve().then(() => (init_ssh(), ssh_exports));
  const { parseInventory: parseInventory2 } = await Promise.resolve().then(() => (init_inventory(), inventory_exports));
  const { buildProbeManifest: buildProbeManifest2 } = await Promise.resolve().then(() => (init_manifest_builder(), manifest_builder_exports));
  const { SnapshotFSProvider: SnapshotFSProvider2 } = await Promise.resolve().then(() => (init_snapshot_fs_provider(), snapshot_fs_provider_exports));
  const { runConcurrent: runConcurrent2 } = await Promise.resolve().then(() => (init_multi_host(), multi_host_exports));
  const { dirname: dirname11, join: join98 } = await import("path");
  const { fileURLToPath: fileURLToPath2 } = await import("url");
  const silent = !!options.silent;
  const log = (msg) => {
    if (!silent) console.log(msg);
  };
  let concurrency;
  let retries;
  try {
    concurrency = parsePositiveInt2(options.parallel, 5, "--parallel");
    retries = parsePositiveInt2(options.sshRetries, 0, "--ssh-retries");
    if (concurrency === 0) throw new Error("--parallel must be at least 1");
  } catch (err) {
    console.error(chalk3.red(err.message));
    process.exitCode = 2;
    return;
  }
  let targets = [];
  if (options.host) {
    targets = options.host.map((h) => {
      const t = parseSSHTarget2(h);
      if (options.sshKey) t.identity = options.sshKey;
      return t;
    });
  }
  if (options.inventory) {
    const inventoryTargets = await parseInventory2(options.inventory);
    for (const t of inventoryTargets) {
      if (options.sshKey && !t.identity) t.identity = options.sshKey;
    }
    targets.push(...inventoryTargets);
  }
  if (targets.length === 0) {
    console.error(chalk3.red("No detection targets specified"));
    process.exitCode = 1;
    return;
  }
  const vasoRoot = join98(dirname11(fileURLToPath2(import.meta.url)), "..");
  const probeBinDir = join98(vasoRoot, "probe", "dist");
  const manifest = buildProbeManifest2(adapterRegistry.getAdapters());
  const timeout = parseInt(options.sshTimeout ?? "60", 10) * 1e3;
  if (options.saveSnapshot) {
    const { mkdir: mkdir13 } = await import("fs/promises");
    await mkdir13(options.saveSnapshot, { recursive: true });
  }
  if (options.outputDir) {
    const { mkdir: mkdir13 } = await import("fs/promises");
    await mkdir13(options.outputDir, { recursive: true });
  }
  log(chalk3.bold(`
  Detecting agents on ${targets.length} remote host(s)...
`));
  async function processTarget(target) {
    const start = Date.now();
    let outcome;
    try {
      const snapshot = await executeRemoteProbeWithRetry2(
        target,
        { probeBinDir, manifest, timeout },
        {
          retries,
          onRetry: (t, attempt, err) => {
            log(chalk3.yellow(`  Retry ${attempt}/${retries} for ${t.host}: ${err.message.split("\n")[0]}`));
          }
        }
      );
      if (options.saveSnapshot) {
        try {
          const { writeFile: writeFile17 } = await import("fs/promises");
          const { join: joinPath } = await import("path");
          const safeHost = safeHostname2(snapshot.hostname ?? target.host);
          const outPath = joinPath(options.saveSnapshot, `${safeHost}.json`);
          await writeFile17(outPath, JSON.stringify(snapshot, null, 2), "utf-8");
          log(chalk3.dim(`  Saved snapshot for ${target.host} \u2192 ${outPath}`));
        } catch (err) {
          log(chalk3.yellow(`  Warning: failed to save snapshot for ${target.host}: ${err.message}`));
        }
      }
      const snapshotFs = new SnapshotFSProvider2(snapshot);
      let installations = await adapterRegistry.detectAll({
        allUsers: options.allUsers,
        fs: snapshotFs
      });
      if (options.agent) {
        installations = installations.filter((i) => i.agent === options.agent);
      }
      outcome = { host: snapshot.hostname ?? target.host, label: target.label, installations };
    } catch (err) {
      outcome = { host: target.host, label: target.label, installations: [], error: err.message };
    }
    if (options.outputDir && !outcome.error) {
      try {
        const { writeFile: writeFile17 } = await import("fs/promises");
        const { join: joinPath } = await import("path");
        const safeHost = safeHostname2(outcome.host);
        const ext = options.format === "json" ? "json" : "txt";
        const outPath = joinPath(options.outputDir, `${safeHost}.${ext}`);
        const text = options.format === "json" ? JSON.stringify(outcome.installations, null, 2) : renderTerminal(outcome.installations, options.verbose);
        await writeFile17(outPath, text, "utf-8");
      } catch (err) {
        log(chalk3.yellow(`  Warning: failed to write output for ${target.host}: ${err.message}`));
      }
    }
    const dur = `${Date.now() - start}ms`;
    const labelStr = target.label ?? `${target.user}@${target.host}`;
    if (outcome.error) {
      log(chalk3.red(`  \u2717 ${labelStr} (${dur}): ${outcome.error.split("\n")[0]}`));
    } else {
      log(chalk3.green(`  \u2713 ${labelStr} (${dur}) \u2014 ${outcome.installations.length} agent(s) detected`));
    }
    return outcome;
  }
  const results = await runConcurrent2(targets, concurrency, processTarget);
  if (options.outputDir) {
    const wrote = results.filter((r) => !r.error).length;
    log(chalk3.green(`
  Wrote ${wrote} report(s) to ${options.outputDir}/`));
    return;
  }
  if (options.format === "json") {
    await emit(JSON.stringify(results, null, 2), options.output, silent);
  } else {
    const sections = [];
    for (const hr of results) {
      const hostLabel = hr.label ?? hr.host;
      sections.push(chalk3.bold(`
\u2500\u2500 ${hostLabel} \u2500\u2500
`));
      if (hr.error) {
        sections.push(chalk3.red(`  Error: ${hr.error}
`));
        continue;
      }
      if (hr.installations.length === 0) {
        sections.push(chalk3.yellow("  No agents detected.\n"));
        continue;
      }
      sections.push(renderTerminal(hr.installations, options.verbose));
    }
    const successCount = results.filter((r) => !r.error).length;
    const failedCount = results.filter((r) => r.error).length;
    const totalAgents = results.reduce((sum, r) => sum + r.installations.length, 0);
    sections.push(chalk3.bold(`
  ${successCount} host(s) scanned, ${totalAgents} agent(s) detected.`));
    if (failedCount > 0) {
      sections.push(chalk3.red(`  ${failedCount} host(s) failed.`));
    }
    sections.push("");
    await emit(sections.join("\n"), options.output, silent);
  }
}
async function renderResults(installations, options) {
  const text = options.format === "json" ? renderJson(installations) : renderTerminal(installations, options.verbose);
  await emit(text, options.output, options.silent);
}
function renderJson(installations) {
  return JSON.stringify(installations, null, 2);
}
function renderTerminal(installations, verbose) {
  const lines = [];
  if (verbose) {
    const adapters = adapterRegistry.getAdapters();
    lines.push(chalk3.dim("Adapters checked:"));
    for (const adapter of adapters) {
      const found = installations.some((i) => i.agent === adapter.agent);
      const paths = adapter.getConfigPaths();
      const status = found ? chalk3.green("found") : chalk3.dim("not found");
      lines.push(chalk3.dim(`  ${adapter.displayName}: ${status}`));
      for (const p of paths) {
        lines.push(chalk3.dim(`    ${p}`));
      }
    }
    lines.push("");
  }
  if (installations.length === 0) {
    lines.push(chalk3.yellow("No agents detected."));
    return lines.join("\n");
  }
  for (const inst of installations) {
    const headerParts = [inst.agent];
    if (inst.user) headerParts.push(`user: ${inst.user}`);
    if (inst.agentName) headerParts.push(`agent: ${inst.agentName}`);
    if (inst.profile) headerParts.push(`profile: ${inst.profile}`);
    const header = headerParts.length > 1 ? `${headerParts[0]} (${headerParts.slice(1).join(", ")})` : headerParts[0];
    lines.push(chalk3.bold.cyan(header));
    if (inst.agentName) {
      lines.push(`  ${"Agent name:".padEnd(14)} ${inst.agentName}`);
    }
    lines.push(`  ${"Version:".padEnd(14)} ${inst.version ?? chalk3.dim("unknown")}`);
    lines.push(`  ${"Install dir:".padEnd(14)} ${inst.installDir}`);
    lines.push(`  ${"Config files:".padEnd(14)} ${inst.configFiles.length}`);
    lines.push(`  ${"Skills dir:".padEnd(14)} ${inst.skillsDir ?? chalk3.dim("none")}`);
    if (inst.cliBinary) {
      lines.push(`  ${"CLI binary:".padEnd(14)} ${inst.cliBinary}`);
    }
    if (inst.appBundle) {
      lines.push(`  ${"App bundle:".padEnd(14)} ${inst.appBundle}`);
    }
    if (inst.gateway) {
      const gw = inst.gateway;
      const parts = [];
      if (gw.host) parts.push(gw.host);
      if (gw.port) parts.push(`:${gw.port}`);
      if (gw.tls) parts.push("(TLS)");
      if (gw.authMode) parts.push(`[${gw.authMode}]`);
      lines.push(`  ${"Gateway:".padEnd(14)} ${parts.join(" ") || chalk3.dim("none")}`);
    } else {
      lines.push(`  ${"Gateway:".padEnd(14)} ${chalk3.dim("none")}`);
    }
    if (inst.models && inst.models.length > 0) {
      const label = inst.models.length === 1 ? "Model:" : `Models (${inst.models.length}):`;
      lines.push(`  ${label.padEnd(14)}`);
      for (const m of inst.models) {
        const id = m.provider ? `${m.provider}/${m.id}` : m.id;
        const suffix = m.via ? chalk3.dim(` (${m.via})`) : "";
        lines.push(`    ${id}${suffix}`);
      }
    }
    lines.push("");
  }
  const subAgents = installations.filter((i) => i.agentName);
  if (subAgents.length > 0) {
    lines.push(chalk3.bold(`Found ${installations.length} agent(s) (${subAgents.length} sub-agent definitions).`));
  } else {
    lines.push(chalk3.bold(`Found ${installations.length} agent(s).`));
  }
  return lines.join("\n");
}
var init_detect = __esm({
  "src/commands/detect.ts"() {
    "use strict";
    init_registry();
    init_debug();
    init_utils();
  }
});

// src/remediation/prompt.ts
import { createInterface } from "readline";
import chalk4 from "chalk";
async function promptForFix(finding) {
  const colorFn = SEVERITY_COLORS2[finding.severity] ?? chalk4.white;
  console.log(`
  ${chalk4.bold(finding.id)} ${colorFn(`[${finding.severity}]`)}`);
  console.log(`  ${finding.message}`);
  if (finding.evidence?.length) {
    for (const e of finding.evidence) {
      const loc = e.line ? `${e.file}:${e.line}` : e.file;
      console.log(chalk4.dim(`    ${loc}`));
      if (e.snippet) {
        console.log(chalk4.dim(`    ${e.snippet}`));
      }
    }
  }
  if (finding.fixDescription) {
    console.log(`  ${chalk4.cyan("Fix:")} ${finding.fixDescription}`);
  }
  const rl = createInterface({
    input: process.stdin,
    output: process.stderr
  });
  return new Promise((resolve6) => {
    rl.question("  Apply fix? [y]es / [n]o / [a]ll / [q]uit: ", (answer) => {
      rl.close();
      const normalized = answer.trim().toLowerCase();
      switch (normalized) {
        case "y":
        case "yes":
          resolve6("yes");
          break;
        case "a":
        case "all":
          resolve6("all");
          break;
        case "q":
        case "quit":
          resolve6("quit");
          break;
        default:
          resolve6("no");
          break;
      }
    });
  });
}
var SEVERITY_COLORS2;
var init_prompt = __esm({
  "src/remediation/prompt.ts"() {
    "use strict";
    SEVERITY_COLORS2 = {
      critical: chalk4.red,
      warning: chalk4.yellow,
      info: chalk4.blue
    };
  }
});

// src/remediation/engine.ts
import { mkdir as mkdir8, copyFile } from "fs/promises";
import { join as join90, dirname as dirname9 } from "path";
import { homedir as homedir8 } from "os";
import chalk5 from "chalk";
var RemediationEngine;
var init_engine2 = __esm({
  "src/remediation/engine.ts"() {
    "use strict";
    init_local_fs_provider();
    init_utils();
    init_prompt();
    RemediationEngine = class {
      constructor(checks, adapters) {
        this.checks = checks;
        this.adapters = adapters;
        this.backupDir = join90(homedir8(), ".vaso", "backups", (/* @__PURE__ */ new Date()).toISOString().replace(/[:.]/g, "-"));
      }
      backupDir;
      async fix(scanResult, options) {
        const results = [];
        let applyAll = options.yes ?? false;
        if (!applyAll && !options.dryRun && !process.stdin.isTTY) {
          console.log(chalk5.yellow("Non-interactive terminal detected. Use --yes to apply fixes in CI/scripts."));
          return results;
        }
        for (const agent of scanResult.agents) {
          const fixable = agent.results.filter((r) => !r.passed && r.fixable);
          if (fixable.length === 0) continue;
          console.log(chalk5.cyan(`
Agent: ${agent.agent}`));
          console.log(`  ${fixable.length} fixable issue(s) found
`);
          for (const finding of fixable) {
            const check = this.checks.getAll().find((c) => c.id === finding.id);
            if (!check?.fix) continue;
            if (options.dryRun) {
              console.log(`  ${chalk5.yellow("[dry-run]")} ${finding.id}: ${finding.fixDescription ?? "would fix"}`);
              results.push({ checkId: finding.id, applied: false, message: `Dry run: ${finding.fixDescription}` });
              continue;
            }
            if (!applyAll) {
              const response = await promptForFix(finding);
              if (response === "no") {
                results.push({ checkId: finding.id, applied: false, message: "Skipped by user" });
                continue;
              }
              if (response === "quit") {
                results.push({ checkId: finding.id, applied: false, message: "Skipped by user" });
                return results;
              }
              if (response === "all") {
                applyAll = true;
              }
            }
            try {
              if (finding.evidence) {
                for (const e of finding.evidence) {
                  await this.backupFile(e.file);
                }
              }
              const fs = new LocalFSProvider();
              const adapter = this.adapters?.getAdapter(agent.installation.agent);
              const credentialPaths = adapter?.getCredentialPaths?.(agent.installation.installDir);
              const skillsDirs = getAllSkillsDirs(agent.installation);
              const skillFiles = skillsDirs.length > 0 ? (await Promise.all(skillsDirs.map((d) => getSkillFiles(d, fs)))).flat() : void 0;
              const fixResult = await check.fix({
                installation: agent.installation,
                configs: agent.installation.configFiles,
                platform: process.platform,
                fs,
                credentialPaths,
                skillFiles
              });
              results.push(fixResult);
              const icon = fixResult.applied ? chalk5.green("+") : chalk5.red("x");
              console.log(`  ${icon} ${finding.id}: ${fixResult.message}`);
            } catch (err) {
              results.push({
                checkId: finding.id,
                applied: false,
                message: `Fix failed: ${err.message}`
              });
              console.log(`  ${chalk5.red("x")} ${finding.id}: Fix failed \u2014 ${err.message}`);
            }
          }
        }
        return results;
      }
      async backupFile(filePath) {
        const destDir = join90(this.backupDir, dirname9(filePath));
        await mkdir8(destDir, { recursive: true });
        await copyFile(filePath, join90(this.backupDir, filePath));
      }
    };
  }
});

// src/remediation/rollback.ts
import { readdir as readdir3, copyFile as copyFile2 } from "fs/promises";
import { join as join91 } from "path";
import { homedir as homedir9 } from "os";
import chalk6 from "chalk";
async function rollback(timestamp) {
  const backupsDir = join91(homedir9(), ".vaso", "backups");
  if (!await pathExists(backupsDir)) {
    console.log(chalk6.yellow("No backups found at ~/.vaso/backups/"));
    return;
  }
  const entries = await readdir3(backupsDir, { withFileTypes: true });
  const dirs = entries.filter((e) => e.isDirectory()).map((e) => e.name).sort();
  if (dirs.length === 0) {
    console.log(chalk6.yellow("No backup directories found."));
    return;
  }
  const target = timestamp ? dirs.find((d) => d.includes(timestamp)) : dirs[dirs.length - 1];
  if (!target) {
    console.log(chalk6.red(`No backup matching "${timestamp}" found.`));
    console.log(`Available backups: ${dirs.join(", ")}`);
    return;
  }
  const backupDir = join91(backupsDir, target);
  console.log(chalk6.cyan(`Restoring from backup: ${target}`));
  const files = await collectFiles(backupDir);
  let restored = 0;
  for (const backupFilePath of files) {
    const originalPath = backupFilePath.slice(backupDir.length);
    try {
      await copyFile2(backupFilePath, originalPath);
      console.log(`  ${chalk6.green("+")} Restored ${originalPath}`);
      restored++;
    } catch (err) {
      console.log(`  ${chalk6.red("x")} Failed to restore ${originalPath}: ${err.message}`);
    }
  }
  console.log(`
${chalk6.bold("Rollback complete:")} ${restored} file(s) restored`);
}
async function collectFiles(dir) {
  const results = [];
  const entries = await readdir3(dir, { withFileTypes: true, recursive: true });
  for (const entry of entries) {
    if (entry.isFile()) {
      const fullPath = entry.parentPath ? join91(entry.parentPath, entry.name) : join91(dir, entry.name);
      results.push(fullPath);
    }
  }
  return results;
}
var init_rollback = __esm({
  "src/remediation/rollback.ts"() {
    "use strict";
    init_utils();
  }
});

// src/commands/fix.ts
var fix_exports = {};
__export(fix_exports, {
  runFix: () => runFix
});
import chalk7 from "chalk";
async function runFix(options) {
  if (options.rollback) {
    await rollback();
    return;
  }
  try {
    const engine = new ScanEngine(adapterRegistry, checkRegistry);
    const result = await engine.scan({ agentFilter: options.agent });
    if (result.agents.length === 0) {
      console.log(chalk7.yellow("No agents detected. Nothing to fix."));
      return;
    }
    const fixable = result.agents.flatMap((a) => a.results.filter((r) => !r.passed && r.fixable));
    if (fixable.length === 0) {
      console.log(chalk7.green("No fixable issues found."));
      return;
    }
    console.log(chalk7.bold(`Found ${fixable.length} fixable issue(s)`));
    if (options.dryRun) {
      console.log(chalk7.dim("(dry run \u2014 no changes will be made)\n"));
    }
    const remediation = new RemediationEngine(checkRegistry, adapterRegistry);
    const results = await remediation.fix(result, {
      dryRun: options.dryRun,
      yes: options.yes
    });
    const applied = results.filter((r) => r.applied).length;
    console.log(`
${chalk7.bold("Summary:")} ${applied}/${results.length} fixes applied`);
  } catch (err) {
    logError(chalk7.red("Fix failed:"), err);
    process.exitCode = 1;
  }
}
var init_fix = __esm({
  "src/commands/fix.ts"() {
    "use strict";
    init_engine();
    init_registry();
    init_check_registry();
    init_engine2();
    init_rollback();
    init_debug();
  }
});

// src/visualizations/models/cvss-mapper.ts
function mapToCvss(result) {
  const real = extractRealCvss(result);
  if (real !== void 0) return { score: real, source: "real" };
  return { score: SEVERITY_TO_CVSS[result.severity], source: "severity-mapped" };
}
function extractRealCvss(result) {
  if (!result.evidence) return void 0;
  for (const e of result.evidence) {
    const detail = e.detail ?? "";
    const m = detail.match(CVSS_NUMERIC_RE);
    if (!m) continue;
    const score = Number.parseFloat(m[1]);
    if (Number.isFinite(score) && score >= 0 && score <= 10) return score;
  }
  return void 0;
}
var SEVERITY_TO_CVSS, CVSS_NUMERIC_RE;
var init_cvss_mapper = __esm({
  "src/visualizations/models/cvss-mapper.ts"() {
    "use strict";
    SEVERITY_TO_CVSS = {
      critical: 9,
      warning: 5,
      info: 2
    };
    CVSS_NUMERIC_RE = /\bcvss[=:\s]+([\d]+(?:\.\d+)?)(?![\d./])/i;
  }
});

// src/visualizations/models/attack-tree-model.ts
function scanResultToAttackTree(agentResult) {
  const failed = agentResult.results.filter((r) => !r.passed);
  const agentLabel3 = formatAgentLabel(agentResult);
  const rootId = "root";
  const nodes = [
    {
      id: rootId,
      label: `Compromise ${agentLabel3}`,
      kind: "root"
    }
  ];
  const edges = [];
  const byCategory = groupByCategory(failed);
  for (const [category, results] of byCategory) {
    const categoryId = `cat:${category}`;
    nodes.push({
      id: categoryId,
      label: `${CATEGORY_LABELS[category] ?? category} (${results.length})`,
      kind: "category",
      category
    });
    edges.push({ from: rootId, to: categoryId });
    for (const r of results) {
      const mapping = mapToCvss(r);
      nodes.push({
        id: r.id,
        label: r.name,
        kind: "finding",
        category: r.category,
        severity: r.severity,
        cvss: mapping.score,
        cvssSource: mapping.source
      });
      edges.push({ from: categoryId, to: r.id });
    }
  }
  return {
    agent: agentResult.agent,
    agentLabel: agentLabel3,
    rootId,
    nodes,
    edges,
    failedCount: failed.length
  };
}
function groupByCategory(results) {
  const out = /* @__PURE__ */ new Map();
  for (const r of results) {
    const arr = out.get(r.category) ?? [];
    arr.push(r);
    out.set(r.category, arr);
  }
  return out;
}
function formatAgentLabel(agentResult) {
  const { agent, installation } = agentResult;
  if (installation.agentName) return `${agent} (${installation.agentName})`;
  if (installation.user) return `${agent} (user: ${installation.user})`;
  return agent;
}
var CATEGORY_LABELS;
var init_attack_tree_model = __esm({
  "src/visualizations/models/attack-tree-model.ts"() {
    "use strict";
    init_cvss_mapper();
    CATEGORY_LABELS = {
      config: "Configuration",
      skills: "Skills",
      ioc: "Indicators of Compromise",
      network: "Network",
      runtime: "Runtime",
      policy: "Policy",
      mcp: "MCP",
      openclaw: "OpenClaw",
      nanoclaw: "NanoClaw",
      ironclaw: "IronClaw",
      nanobot: "Nanobot",
      zeroclaw: "ZeroClaw",
      lyrie: "Lyrie",
      hermes: "Hermes",
      advisory: "Advisories",
      "coding-agent": "Coding Agent"
    };
  }
});

// src/visualizations/models/topology-model.ts
function scanResultToTopology(result) {
  const hostId = "host";
  const hostLabel = result.host ?? "local host";
  const nodes = [
    { id: hostId, label: hostLabel, kind: "host" }
  ];
  const edges = [];
  for (const agentResult of result.agents) {
    const agentId = agentNodeId(agentResult);
    nodes.push({
      id: agentId,
      label: agentLabel2(agentResult),
      kind: "agent",
      metadata: {
        agent: agentResult.agent,
        score: String(agentResult.score),
        grade: agentResult.grade,
        installDir: agentResult.installation.installDir
      }
    });
    edges.push({ from: hostId, to: agentId });
    const gw = agentResult.installation.gateway;
    if (gw && (gw.host || gw.port)) {
      const gatewayId = `${agentId}:gateway`;
      const gwLabel = formatGatewayLabel(gw.host, gw.port);
      nodes.push({
        id: gatewayId,
        label: gwLabel,
        kind: "gateway",
        metadata: {
          tls: gw.tls ? "true" : "false",
          authMode: gw.authMode ?? "unknown"
        }
      });
      edges.push({
        from: agentId,
        to: gatewayId,
        label: gw.tls ? "TLS" : "plain"
      });
    }
  }
  return { hostId, hostLabel, scanTimestamp: result.timestamp, nodes, edges };
}
function agentNodeId(agentResult) {
  const slug = (agentResult.installation.installDir ?? agentResult.agent).replace(/[^a-zA-Z0-9]+/g, "_");
  return `agent:${agentResult.agent}:${slug}`;
}
function agentLabel2(agentResult) {
  const { agent, installation } = agentResult;
  if (installation.agentName) return `${agent} \u2014 ${installation.agentName}`;
  if (installation.user) return `${agent} \u2014 ${installation.user}`;
  return agentTypeLabel(agent);
}
function agentTypeLabel(agent) {
  return agent;
}
function formatGatewayLabel(host, port) {
  if (host && port) return `${host}:${port}`;
  if (host) return host;
  if (port) return `:${port}`;
  return "gateway";
}
var init_topology_model = __esm({
  "src/visualizations/models/topology-model.ts"() {
    "use strict";
  }
});

// src/visualizations/serializers/usecvis-shape.ts
function attackTreeToUsecvisShape(model) {
  const labelById = /* @__PURE__ */ new Map();
  for (const n of model.nodes) labelById.set(n.id, n.label);
  const nodes = {};
  for (const n of model.nodes) {
    nodes[n.label] = nodeAttrs(n);
  }
  const edges = {};
  for (const e of model.edges) {
    const fromLabel = labelById.get(e.from);
    const toLabel = labelById.get(e.to);
    if (!fromLabel || !toLabel) continue;
    if (!edges[fromLabel]) edges[fromLabel] = [];
    edges[fromLabel].push({ to: toLabel });
  }
  const rootLabel = labelById.get(model.rootId) ?? `Compromise ${model.agentLabel}`;
  return {
    tree: {
      name: `${model.agentLabel} \u2014 Attack Tree`,
      type: "Attack Tree",
      description: `Failed checks for ${model.agentLabel} (${model.failedCount} finding${model.failedCount === 1 ? "" : "s"})`,
      root: rootLabel,
      version: "1.0"
    },
    nodes,
    edges
  };
}
function nodeAttrs(n) {
  if (n.kind === "root") return { ...ROOT_ATTRS };
  if (n.kind === "category") return { ...CATEGORY_ATTRS };
  const attrs = { ...FINDING_ATTRS };
  if (n.cvss !== void 0) attrs.cvss = n.cvss;
  return attrs;
}
function zoneGraphToUsecvisShape(graph, options) {
  const failed = options.failedCheckIds;
  const components = graph.components.map((c) => {
    const isFailed = (c.guardCheckIds ?? []).some((id) => failed.has(id));
    const out = {
      id: c.id,
      label: c.label,
      zone: c.zone
    };
    if (isFailed) out.failed = true;
    return out;
  });
  const influences = [];
  let i = 0;
  for (const e of graph.edges) {
    const isInversion = e.triggerCheckIds && e.triggerCheckIds.length > 0;
    if (isInversion) {
      const triggered = e.triggerCheckIds.some((id) => failed.has(id));
      if (!triggered) continue;
    }
    influences.push({
      id: `inf_${++i}`,
      from: e.from,
      to: e.to,
      type: e.kind ?? "data",
      ...e.label ? { label: e.label } : {},
      ...isInversion ? { triggered: true } : {}
    });
  }
  return {
    gradient: {
      name: options.name,
      type: "Privilege Gradient Graph",
      description: options.description,
      version: "1.0"
    },
    zones: graph.zones.map((z) => ({ id: z.id, label: z.label, trust_level: z.trustLevel })),
    components,
    influence_types: INFLUENCE_TYPES,
    influences
  };
}
function topologyToUsecvisShape(model) {
  const layers = [
    { name: "Host", order: 1, components: [] },
    { name: "Agents", order: 2, components: [] },
    { name: "Network", order: 3, components: [] }
  ];
  for (const n of model.nodes) {
    if (n.kind === "host") {
      layers[0].components.push({ id: n.id, name: n.label, type: "storage" });
    } else if (n.kind === "agent") {
      layers[1].components.push({
        id: n.id,
        name: n.label,
        type: "cli",
        ...n.metadata?.installDir ? { tech: n.metadata.installDir } : {}
      });
    } else if (n.kind === "gateway") {
      layers[2].components.push({
        id: n.id,
        name: n.label,
        type: "service",
        ...n.metadata?.tls ? { tech: n.metadata.tls === "true" ? "TLS" : "plain" } : {}
      });
    }
  }
  const connections = model.edges.map((e) => ({
    from: e.from,
    to: e.to,
    ...e.label ? { label: e.label } : {},
    style: "sync"
  }));
  return {
    title: `VASO Scan Topology \u2014 ${model.hostLabel}`,
    layers,
    connections
  };
}
var ROOT_ATTRS, CATEGORY_ATTRS, FINDING_ATTRS, INFLUENCE_TYPES;
var init_usecvis_shape = __esm({
  "src/visualizations/serializers/usecvis-shape.ts"() {
    "use strict";
    ROOT_ATTRS = { style: "filled", shape: "oval", fillcolor: "#e74c3c", fontcolor: "white" };
    CATEGORY_ATTRS = { style: "filled", shape: "box", fillcolor: "#3498db", fontcolor: "white" };
    FINDING_ATTRS = { style: "filled", shape: "rectangle" };
    INFLUENCE_TYPES = [
      { id: "data", label: "Data Flow", color: "#3498db", style: "solid", arrowhead: "vee", penwidth: "1.5" },
      { id: "control", label: "Control", color: "#8e44ad", style: "bold", arrowhead: "dot", penwidth: "2" },
      { id: "resource", label: "Resource", color: "#27ae60", style: "dotted", arrowhead: "diamond", penwidth: "2" },
      { id: "feedback", label: "Feedback", color: "#e67e22", style: "dashed", arrowhead: "vee", penwidth: "1.5" }
    ];
  }
});

// src/visualizations/serializers/format.ts
import { stringify as tomlStringify } from "smol-toml";
import { stringify as yamlStringify } from "yaml";
function isValidVisFormat(value) {
  return value === "toml" || value === "json" || value === "yaml";
}
function serialize(shape, format) {
  if (format === "json") return JSON.stringify(shape, null, 2) + "\n";
  if (format === "yaml") return yamlStringify(shape);
  return tomlStringify(shape);
}
var VIS_FORMAT_EXTENSIONS;
var init_format = __esm({
  "src/visualizations/serializers/format.ts"() {
    "use strict";
    VIS_FORMAT_EXTENSIONS = {
      toml: "toml",
      json: "json",
      yaml: "yaml"
    };
  }
});

// src/visualizations/readme.ts
import { basename as basename19 } from "path";
function generateBundleReadme(result, files, options) {
  const lines = [];
  lines.push("# VASO Visualization Bundle");
  lines.push("");
  lines.push(`Scan timestamp: ${result.timestamp}`);
  lines.push(`Host: ${result.host ?? "local"}`);
  lines.push(`Score: ${result.totalScore}/100 (${result.totalGrade})`);
  lines.push(`Format: ${options.format}`);
  lines.push("");
  lines.push("## Files");
  lines.push("");
  for (const f of files.filter((f2) => f2.diagram !== "readme")) {
    lines.push(`- \`${basename19(f.path)}\` \u2014 ${DIAGRAM_LABELS[f.diagram]} (${f.bytes} bytes)`);
  }
  lines.push("");
  lines.push("## Render with USecVisLib");
  lines.push("");
  lines.push("Install: https://github.com/vulnex/usecvislib");
  lines.push("");
  lines.push("```bash");
  for (const f of files.filter((f2) => f2.diagram !== "readme")) {
    const mode = USECVIS_MODE[f.diagram];
    const name = basename19(f.path);
    const out = name.replace(/\.[a-z]+$/, "");
    lines.push(`usecvis -m ${mode} -i ${name} -o ${out} -f png`);
  }
  lines.push("```");
  lines.push("");
  lines.push("## Note on CVSS scores");
  lines.push("");
  lines.push("Attack-tree leaves carry a `cvss` value. The source is one of:");
  lines.push("");
  lines.push("- **Real CVSS** \u2014 extracted from advisory check evidence when a CVE reference includes a numeric score.");
  lines.push("- **Severity-mapped** \u2014 coarse approximation when no real CVSS is available:");
  lines.push("  - `critical` \u2192 9.0");
  lines.push("  - `warning` \u2192 5.0");
  lines.push("  - `info` \u2192 2.0");
  lines.push("");
  lines.push("Severity-mapped values exist to drive USecVisLib's color presets. Treat them as severity bands, not real CVSS measurements.");
  lines.push("");
  lines.push("---");
  lines.push("Generated by `vaso visualize` (VULNEX Agent Security Observer).");
  return lines.join("\n") + "\n";
}
var USECVIS_MODE, DIAGRAM_LABELS;
var init_readme = __esm({
  "src/visualizations/readme.ts"() {
    "use strict";
    USECVIS_MODE = {
      "attack-tree": "0",
      "privilege-gradient": "6",
      component: "7"
    };
    DIAGRAM_LABELS = {
      "attack-tree": "Attack Tree",
      "privilege-gradient": "Privilege Gradient",
      component: "Component Diagram"
    };
  }
});

// src/visualizations/bundle.ts
import { mkdir as mkdir9, writeFile as writeFile12 } from "fs/promises";
import { join as join92 } from "path";
async function emitBundle(result, options) {
  await mkdir9(options.outputDir, { recursive: true });
  const files = [];
  const ext = VIS_FORMAT_EXTENSIONS[options.format];
  const slugCounts = /* @__PURE__ */ new Map();
  if (options.diagrams.includes("component")) {
    const topology = scanResultToTopology(result);
    const shape = topologyToUsecvisShape(topology);
    const file = await writeBundleFile(options.outputDir, `topology.${ext}`, shape, options.format);
    files.push({ ...file, diagram: "component" });
  }
  for (const agent of result.agents) {
    const slug = agentSlug(agent, slugCounts);
    if (options.diagrams.includes("attack-tree")) {
      const tree = scanResultToAttackTree(agent);
      const shape = attackTreeToUsecvisShape(tree);
      const file = await writeBundleFile(
        options.outputDir,
        `${slug}-attack-tree.${ext}`,
        shape,
        options.format
      );
      files.push({ ...file, diagram: "attack-tree" });
    }
    if (options.diagrams.includes("privilege-gradient")) {
      const graph = resolveZoneGraph(agent, options.adapters);
      const failedCheckIds = new Set(agent.results.filter((r) => !r.passed).map((r) => r.id));
      const shape = zoneGraphToUsecvisShape(graph, {
        name: `${slug} \u2014 Privilege Gradient`,
        description: `Privilege gradient for ${agent.agent} (${failedCheckIds.size} failure${failedCheckIds.size === 1 ? "" : "s"})`,
        failedCheckIds
      });
      const file = await writeBundleFile(
        options.outputDir,
        `${slug}-privilege-gradient.${ext}`,
        shape,
        options.format
      );
      files.push({ ...file, diagram: "privilege-gradient" });
    }
  }
  const readme = generateBundleReadme(result, files, options);
  const readmePath = join92(options.outputDir, "README.md");
  await writeFile12(readmePath, readme, "utf-8");
  files.push({ path: readmePath, bytes: Buffer.byteLength(readme, "utf-8"), diagram: "readme" });
  return { outputDir: options.outputDir, format: options.format, files };
}
async function writeBundleFile(dir, filename, shape, format) {
  const content = serialize(shape, format);
  const path = join92(dir, filename);
  await writeFile12(path, content, "utf-8");
  return { path, bytes: Buffer.byteLength(content, "utf-8") };
}
function resolveZoneGraph(agent, adapters) {
  const adapter = adapters.get(agent.agent);
  return adapter?.getZoneGraph?.() ?? defaultZoneGraph();
}
function agentSlug(agent, counts) {
  const base = agent.installation.agentName ? `${agent.agent}-${slugify(agent.installation.agentName)}` : agent.installation.user ? `${agent.agent}-${slugify(agent.installation.user)}` : agent.agent;
  const seen = counts.get(base) ?? 0;
  counts.set(base, seen + 1);
  return seen === 0 ? base : `${base}-${seen + 1}`;
}
function slugify(s) {
  return s.replace(/[^a-zA-Z0-9-]+/g, "-").replace(/^-+|-+$/g, "").toLowerCase() || "unnamed";
}
var ALL_DIAGRAMS;
var init_bundle = __esm({
  "src/visualizations/bundle.ts"() {
    "use strict";
    init_default_zone_graph();
    init_attack_tree_model();
    init_topology_model();
    init_usecvis_shape();
    init_format();
    init_readme();
    ALL_DIAGRAMS = ["attack-tree", "privilege-gradient", "component"];
  }
});

// src/commands/visualize.ts
var visualize_exports = {};
__export(visualize_exports, {
  runVisualize: () => runVisualize
});
import chalk8 from "chalk";
import { readFile as readFile13 } from "fs/promises";
import { resolve as resolve3 } from "path";
async function runVisualize(options) {
  const format = parseFormat(options.visFormat);
  if (!format) {
    console.error(chalk8.red(`Invalid --vis-format "${options.visFormat}". Use: toml, json, or yaml.`));
    process.exitCode = 2;
    return;
  }
  const diagrams = parseDiagrams(options.diagrams);
  if (!diagrams) {
    console.error(chalk8.red(`Invalid --diagrams. Available: ${ALL_DIAGRAMS.join(", ")}.`));
    process.exitCode = 2;
    return;
  }
  let result;
  try {
    result = options.input ? await loadScanResult(options.input) : await runFreshScan(options);
  } catch (err) {
    logError("visualize: scan-result", err);
    console.error(chalk8.red(`Failed to obtain scan result: ${err.message}`));
    process.exitCode = 1;
    return;
  }
  const adapters = /* @__PURE__ */ new Map();
  for (const a of adapterRegistry.getAdapters()) adapters.set(a.agent, a);
  const outputDir = resolve3(options.output ?? DEFAULT_OUTPUT_DIR);
  try {
    const bundle = await emitBundle(result, { outputDir, format, diagrams, adapters });
    console.log(chalk8.green(`Wrote ${bundle.files.length} file(s) to ${bundle.outputDir}`));
    for (const f of bundle.files) {
      const tag = f.diagram === "readme" ? "readme" : f.diagram;
      console.log(chalk8.dim(`  ${tag.padEnd(20)} ${f.path}`));
    }
  } catch (err) {
    logError("visualize: emit-bundle", err);
    console.error(chalk8.red(`Failed to write bundle: ${err.message}`));
    process.exitCode = 1;
  }
}
function parseFormat(value) {
  const v = value ?? "toml";
  return isValidVisFormat(v) ? v : void 0;
}
function parseDiagrams(value) {
  if (!value) return [...ALL_DIAGRAMS];
  const parts = value.split(",").map((s) => s.trim()).filter(Boolean);
  const out = [];
  for (const p of parts) {
    if (ALL_DIAGRAMS.includes(p)) out.push(p);
    else return void 0;
  }
  return out;
}
async function loadScanResult(path) {
  const raw = await readFile13(path, "utf-8");
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.agents)) {
    throw new Error(`File "${path}" does not look like a VASO scan result (missing 'agents' array)`);
  }
  return parsed;
}
async function runFreshScan(options) {
  const engine = new ScanEngine(adapterRegistry, checkRegistry);
  const scanOptions = {
    agentFilter: options.agent,
    allUsers: options.allUsers
  };
  return engine.scan(scanOptions);
}
var DEFAULT_OUTPUT_DIR;
var init_visualize = __esm({
  "src/commands/visualize.ts"() {
    "use strict";
    init_engine();
    init_registry();
    init_check_registry();
    init_bundle();
    init_format();
    init_debug();
    DEFAULT_OUTPUT_DIR = "./vaso-visualizations";
  }
});

// src/commands/update.ts
var update_exports = {};
__export(update_exports, {
  runUpdate: () => runUpdate
});
import chalk9 from "chalk";
async function runUpdate(options = {}) {
  console.log(chalk9.cyan("Updating IOC database from remote feed..."));
  const result = await fetchAndUpdateFeed({
    feedUrl: options.url,
    force: options.force ?? true
    // CLI update always forces by default
  });
  if (!result.success) {
    console.log(chalk9.red(`Update failed: ${result.message}`));
    console.log(chalk9.yellow("Falling back to bundled IOC data."));
    return;
  }
  console.log(chalk9.green(result.message));
  if (result.newIndicators) {
    console.log(chalk9.dim("  New indicators in feed:"));
    console.log(`    C2 IPs: ${result.newIndicators.c2Ips}`);
    console.log(`    Malicious domains: ${result.newIndicators.maliciousDomains}`);
    console.log(`    File hashes: ${result.newIndicators.fileHashes}`);
    console.log(`    Malicious publishers: ${result.newIndicators.maliciousPublishers}`);
    console.log(`    Malicious skill patterns: ${result.newIndicators.maliciousSkillPatterns}`);
    console.log(`    Trusted skill names: ${result.newIndicators.trustedSkillNames}`);
    console.log(`    Trusted MCP packages: ${result.newIndicators.trustedMCPPackages}`);
    console.log(`    Binary patterns: ${result.newIndicators.binaryPatterns}`);
  }
  reloadIOCDatabase();
  await initIOCDatabase();
  const db = getIOCDatabase();
  console.log(chalk9.green("\nMerged IOC database totals:"));
  console.log(`  C2 IPs: ${db.c2Ips.length}`);
  console.log(`  Malicious domains: ${db.maliciousDomains.length}`);
  console.log(`  File hashes: ${db.fileHashes.length}`);
  console.log(`  Malicious publishers: ${db.maliciousPublishers.length}`);
  console.log(`  Malicious skill patterns: ${db.maliciousSkillPatterns.length}`);
  console.log(`  Trusted skill names: ${db.trustedSkillNames.length}`);
  console.log(`  Trusted MCP packages: ${db.trustedMCPPackages.length}`);
  console.log(`  Binary patterns: ${db.binaryPatterns.length}`);
  console.log(chalk9.cyan("\nUpdating advisory database from remote feed..."));
  const advResult = await fetchAndUpdateAdvisoryFeed({
    force: options.force ?? true
  });
  if (!advResult.success) {
    console.log(chalk9.red(`Advisory update failed: ${advResult.message}`));
    console.log(chalk9.yellow("Falling back to bundled advisory data."));
  } else {
    console.log(chalk9.green(advResult.message));
    if (advResult.newAdvisories !== void 0) {
      console.log(chalk9.dim(`  Advisories in feed: ${advResult.newAdvisories}`));
    }
  }
  reloadAdvisoryDatabase();
  await initAdvisoryDatabase();
  const advDb = getAdvisoryDatabase();
  console.log(chalk9.green(`
Merged advisory database: ${advDb.advisories.length} advisories`));
}
var init_update = __esm({
  "src/commands/update.ts"() {
    "use strict";
    init_database();
    init_updater();
    init_database2();
    init_updater2();
  }
});

// src/mcp/discovery.ts
import { join as join93 } from "path";
function getGlobalConfigLocations(platform, home) {
  const locations = [];
  if (platform === "darwin") {
    locations.push({
      source: "Claude Desktop",
      path: join93(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
    });
  } else if (platform === "linux") {
    locations.push({
      source: "Claude Desktop",
      path: join93(home, ".config", "Claude", "claude_desktop_config.json")
    });
  } else if (platform === "win32") {
    const appData = process.env.APPDATA ?? join93(home, "AppData", "Roaming");
    locations.push({
      source: "Claude Desktop",
      path: join93(appData, "Claude", "claude_desktop_config.json")
    });
  }
  locations.push({
    source: "Claude Code",
    path: join93(home, ".claude", "mcp.json")
  });
  locations.push({
    source: "Cursor",
    path: join93(home, ".cursor", "mcp.json")
  });
  locations.push({
    source: "Windsurf",
    path: join93(home, ".codeium", "windsurf", "mcp_config.json")
  });
  return locations;
}
function getProjectConfigLocations(projectDir) {
  return [
    { source: "Claude Code (project)", path: join93(projectDir, ".mcp.json") },
    { source: "Cursor (project)", path: join93(projectDir, ".cursor", "mcp.json") },
    { source: "Windsurf (project)", path: join93(projectDir, ".windsurf", "mcp.json") },
    { source: "VS Code", path: join93(projectDir, ".vscode", "mcp.json") },
    { source: "Generic MCP", path: join93(projectDir, "mcp.json") }
  ];
}
function parseServerEntries(data) {
  const servers = [];
  const mcpServers = data.mcpServers;
  if (!mcpServers || typeof mcpServers !== "object") return servers;
  for (const [name, config] of Object.entries(mcpServers)) {
    if (!config || typeof config !== "object") continue;
    let transport = "stdio";
    if (config.url) {
      const url = String(config.url);
      if (url.includes("/sse")) {
        transport = "sse";
      } else {
        transport = "streamable-http";
      }
    }
    servers.push({
      name,
      command: config.command ? String(config.command) : void 0,
      args: Array.isArray(config.args) ? config.args.map(String) : void 0,
      env: config.env && typeof config.env === "object" ? Object.fromEntries(Object.entries(config.env).map(([k, v]) => [k, String(v)])) : void 0,
      headers: config.headers && typeof config.headers === "object" ? Object.fromEntries(Object.entries(config.headers).map(([k, v]) => [k, String(v)])) : void 0,
      url: config.url ? String(config.url) : void 0,
      transport
    });
  }
  return servers;
}
var MCPDiscovery;
var init_discovery = __esm({
  "src/mcp/discovery.ts"() {
    "use strict";
    init_local_fs_provider();
    MCPDiscovery = class {
      fs;
      constructor(fs) {
        this.fs = fs ?? new LocalFSProvider();
      }
      async discover(platform = process.platform, projectDir) {
        const configs = [];
        const home = this.fs.homedir();
        const locations = [
          ...getGlobalConfigLocations(platform, home),
          ...projectDir ? getProjectConfigLocations(projectDir) : []
        ];
        for (const location of locations) {
          if (!await this.fs.access(location.path)) continue;
          try {
            const raw = await this.fs.readFile(location.path);
            const data = JSON.parse(raw);
            const servers = parseServerEntries(data);
            if (servers.length > 0) {
              configs.push({
                source: location.source,
                filePath: location.path,
                servers
              });
            }
          } catch {
          }
        }
        const totalServers = configs.reduce((sum, c) => sum + c.servers.length, 0);
        return { configs, totalServers };
      }
      async discoverFromPaths(paths) {
        const configs = [];
        for (const filePath of paths) {
          if (!await this.fs.access(filePath)) continue;
          try {
            const raw = await this.fs.readFile(filePath);
            const data = JSON.parse(raw);
            const servers = parseServerEntries(data);
            if (servers.length > 0) {
              configs.push({
                source: "Custom",
                filePath,
                servers
              });
            }
          } catch {
          }
        }
        const totalServers = configs.reduce((sum, c) => sum + c.servers.length, 0);
        return { configs, totalServers };
      }
    };
  }
});

// src/mcp/package-fetcher.ts
import { mkdir as mkdir10, readFile as readFile14, readdir as readdir4, access as access2 } from "fs/promises";
import { join as join94, basename as basename20, relative as relative3, extname as extname9 } from "path";
import { homedir as homedir10 } from "os";
import { execFile as execFile2 } from "child_process";
import { promisify as promisify2 } from "util";
function defaultPackageCacheDir() {
  return join94(homedir10(), ".vaso", "mcp-pkg-cache");
}
function isRegistrySpec(spec) {
  return REGISTRY_SPEC_RE.test(spec);
}
function sanitizeSpec(spec) {
  return spec.replace(/[^a-zA-Z0-9._-]+/g, "_").slice(0, 120) || "pkg";
}
async function resolveNpmPackageSource(spec, options = {}) {
  if (!isRegistrySpec(spec)) return void 0;
  const cacheDir = options.cacheDir ?? defaultPackageCacheDir();
  const runner = options.runner ?? defaultRunner;
  const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS2;
  const pkgDir = join94(cacheDir, sanitizeSpec(spec));
  const extractedDir = join94(pkgDir, "package");
  const cached = await collectPackageSource(extractedDir);
  if (cached) return cached;
  try {
    await mkdir10(pkgDir, { recursive: true });
    const { stdout } = await runner(
      "npm",
      ["pack", spec, "--json", "--ignore-scripts", "--pack-destination", pkgDir],
      { timeout }
    );
    const tarball = parsePackFilename(stdout);
    if (!tarball) return void 0;
    await runner("tar", ["-xzf", join94(pkgDir, tarball), "-C", pkgDir], { timeout });
    return collectPackageSource(extractedDir);
  } catch {
    return void 0;
  }
}
function parsePackFilename(stdout) {
  try {
    const arr = JSON.parse(stdout);
    if (Array.isArray(arr) && arr[0]?.filename) return basename20(String(arr[0].filename));
  } catch {
    const last = stdout.split("\n").map((l) => l.trim()).filter(Boolean).pop();
    if (last && last.endsWith(".tgz")) return basename20(last);
  }
  return void 0;
}
async function findPackageEntry(dir) {
  try {
    const pkg = JSON.parse(await readFile14(join94(dir, "package.json"), "utf-8"));
    if (typeof pkg.main === "string") {
      const p = join94(dir, pkg.main);
      if (await exists(p)) return p;
    }
    if (pkg.bin) {
      const binEntry = typeof pkg.bin === "string" ? pkg.bin : Object.values(pkg.bin)[0];
      if (binEntry) {
        const p = join94(dir, String(binEntry));
        if (await exists(p)) return p;
      }
    }
  } catch {
  }
  for (const candidate of ENTRY_CANDIDATES) {
    const p = join94(dir, candidate);
    if (await exists(p)) return p;
  }
  return void 0;
}
async function exists(path) {
  try {
    await access2(path);
    return true;
  } catch {
    return false;
  }
}
async function collectPackageSource(extractedDir) {
  const files = await listSourceFiles(extractedDir);
  if (files.length === 0) return void 0;
  const entry = await findPackageEntry(extractedDir);
  files.sort((a, b) => a === entry ? -1 : b === entry ? 1 : a.localeCompare(b));
  const parts = [];
  let total = 0;
  for (const file of files) {
    if (total >= MAX_SOURCE_BYTES) break;
    try {
      const buf = await readFile14(file);
      const slice = buf.byteLength > PER_FILE_CAP ? buf.subarray(0, PER_FILE_CAP) : buf;
      parts.push(`// === ${relative3(extractedDir, file)} ===
${slice.toString("utf-8")}`);
      total += slice.byteLength;
    } catch {
    }
  }
  return parts.length > 0 ? parts.join("\n\n") : void 0;
}
async function listSourceFiles(dir) {
  const out = [];
  async function walk4(current) {
    let entries;
    try {
      entries = await readdir4(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join94(current, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) await walk4(full);
      } else if (entry.isFile()) {
        const lower = entry.name.toLowerCase();
        if (lower.endsWith(".d.ts") || lower.endsWith(".map")) continue;
        if (SOURCE_EXT.has(extname9(lower))) out.push(full);
      }
    }
  }
  await walk4(dir);
  return out;
}
var execFileAsync2, DEFAULT_TIMEOUT_MS2, MAX_BUFFER, MAX_SOURCE_BYTES, REGISTRY_SPEC_RE, defaultRunner, ENTRY_CANDIDATES, SOURCE_EXT, SKIP_DIRS, PER_FILE_CAP;
var init_package_fetcher = __esm({
  "src/mcp/package-fetcher.ts"() {
    "use strict";
    execFileAsync2 = promisify2(execFile2);
    DEFAULT_TIMEOUT_MS2 = 6e4;
    MAX_BUFFER = 16 * 1024 * 1024;
    MAX_SOURCE_BYTES = 2e6;
    REGISTRY_SPEC_RE = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*(?:@[a-zA-Z0-9.~^*><=|\- ]+)?$/i;
    defaultRunner = async (cmd, args, opts) => {
      const { stdout, stderr } = await execFileAsync2(cmd, args, {
        cwd: opts.cwd,
        timeout: opts.timeout ?? DEFAULT_TIMEOUT_MS2,
        maxBuffer: MAX_BUFFER,
        encoding: "utf-8"
      });
      return { stdout: String(stdout), stderr: String(stderr) };
    };
    ENTRY_CANDIDATES = [
      "index.js",
      "dist/index.js",
      "build/index.js",
      "lib/index.js",
      "src/index.js",
      "index.mjs",
      "index.cjs",
      "main.js",
      "server.js"
    ];
    SOURCE_EXT = /* @__PURE__ */ new Set([".js", ".mjs", ".cjs"]);
    SKIP_DIRS = /* @__PURE__ */ new Set(["node_modules", "test", "tests", "__tests__", "example", "examples", ".git"]);
    PER_FILE_CAP = 512 * 1024;
  }
});

// src/mcp/source-resolver.ts
import { join as join95, resolve as resolve4 } from "path";
function inferPackageName(server) {
  if (!server.command || !server.args?.length) return void 0;
  const cmd = server.command;
  const args = server.args;
  if (cmd === "npx" || cmd === "npx.cmd") {
    for (const arg of args) {
      if (arg.startsWith("-")) continue;
      return arg;
    }
  }
  if (cmd === "uvx" || cmd === "uv") {
    for (const arg of args) {
      if (arg === "run" || arg === "tool" || arg.startsWith("-")) continue;
      return arg;
    }
  }
  if (cmd === "node" || cmd === "node.exe") {
    for (const arg of args) {
      if (arg.startsWith("-")) continue;
      return void 0;
    }
  }
  return void 0;
}
function resolveLocalPath(server) {
  if (!server.command || !server.args?.length) return void 0;
  const cmd = server.command;
  const args = server.args;
  if (cmd === "node" || cmd === "node.exe") {
    for (const arg of args) {
      if (arg.startsWith("-")) continue;
      return resolve4(arg);
    }
  }
  if (cmd.startsWith("/") || cmd.startsWith("./") || cmd.startsWith("../")) {
    return resolve4(cmd);
  }
  return void 0;
}
async function readSourceFile(filePath, fs) {
  try {
    const content = await fs.readFile(filePath);
    return content;
  } catch {
    return void 0;
  }
}
async function findMainEntry(dir, fs) {
  const pkgPath = join95(dir, "package.json");
  if (await fs.access(pkgPath)) {
    try {
      const pkg = JSON.parse(await fs.readFile(pkgPath));
      if (pkg.main) return join95(dir, pkg.main);
      if (pkg.bin) {
        const binEntry = typeof pkg.bin === "string" ? pkg.bin : Object.values(pkg.bin)[0];
        if (binEntry) return join95(dir, binEntry);
      }
    } catch {
    }
  }
  const candidates = ["index.js", "index.ts", "src/index.js", "src/index.ts", "main.js", "server.js"];
  for (const candidate of candidates) {
    const fullPath = join95(dir, candidate);
    if (await fs.access(fullPath)) return fullPath;
  }
  return void 0;
}
function isNpmCommand(cmd) {
  return cmd === "npx" || cmd === "npx.cmd";
}
async function resolveServerSources(servers, options = {}) {
  const provider = options.fs ?? new LocalFSProvider();
  const sources = [];
  for (const server of servers) {
    const packageName = inferPackageName(server);
    const localPath = resolveLocalPath(server);
    let sourceCode;
    if (localPath) {
      sourceCode = await readSourceFile(localPath, provider);
      if (!sourceCode) {
        const entry = await findMainEntry(localPath, provider);
        if (entry) {
          sourceCode = await readSourceFile(entry, provider);
        }
      }
    }
    if (!sourceCode && packageName && options.resolvePackages && isNpmCommand(server.command)) {
      const fetcher = options.npmFetcher ?? ((spec) => resolveNpmPackageSource(spec, { cacheDir: options.cacheDir }));
      sourceCode = await fetcher(packageName);
    }
    sources.push({
      serverName: server.name,
      packageName,
      localPath,
      sourceCode
    });
  }
  return sources;
}
var init_source_resolver = __esm({
  "src/mcp/source-resolver.ts"() {
    "use strict";
    init_local_fs_provider();
    init_package_fetcher();
  }
});

// src/commands/mcp.ts
var mcp_exports = {};
__export(mcp_exports, {
  runMCPList: () => runMCPList,
  runMCPScan: () => runMCPScan
});
import chalk10 from "chalk";
import { writeFile as writeFile13 } from "fs/promises";
async function runMCPScan(options) {
  const discovery = new MCPDiscovery();
  try {
    const discoveryResult = options.path ? await discovery.discoverFromPaths(options.path) : await discovery.discover(process.platform, process.cwd());
    if (discoveryResult.totalServers === 0) {
      console.log(chalk10.yellow("No MCP servers found. Nothing to scan."));
      return;
    }
    console.log(chalk10.dim(`Found ${discoveryResult.totalServers} MCP server(s) across ${discoveryResult.configs.length} config(s)`));
    const allServers = discoveryResult.configs.flatMap((c) => c.servers);
    if (options.resolvePackages) {
      console.log(chalk10.dim("Resolving npm-packaged servers from the registry (download-only, no execution)\u2026"));
    }
    const serverSources = await resolveServerSources(allServers, {
      resolvePackages: options.resolvePackages
    });
    if (options.resolvePackages) {
      const resolved = serverSources.filter((s) => s.packageName && s.sourceCode).length;
      const packaged = serverSources.filter((s) => s.packageName && !s.localPath).length;
      console.log(chalk10.dim(`Resolved source for ${resolved}/${packaged} packaged server(s) (npm only; uvx/PyPI not analyzed).`));
    }
    const engine = new ScanEngine(adapterRegistry, checkRegistry);
    const scanOptions = {
      format: options.format
    };
    const result = await engine.scanMCP(discoveryResult.configs, serverSources, scanOptions);
    const reporter = getReporter(scanOptions.format ?? "terminal");
    const output = reporter.render(result);
    if (options.output) {
      await writeFile13(options.output, output, "utf-8");
      console.log(chalk10.green(`Report written to ${options.output}`));
    } else {
      console.log(output);
    }
    const hasCritical = result.agents.some(
      (a) => a.results.some((r) => r.severity === "critical" && !r.passed)
    );
    if (hasCritical) {
      process.exitCode = 1;
    }
  } catch (err) {
    logError(chalk10.red("MCP scan failed:"), err);
    process.exitCode = 1;
  }
}
async function runMCPList(options) {
  const discovery = new MCPDiscovery();
  try {
    const result = options.path ? await discovery.discoverFromPaths(options.path) : await discovery.discover(process.platform, process.cwd());
    if (result.totalServers === 0) {
      console.log(chalk10.yellow("No MCP servers found."));
      return;
    }
    if (options.format === "json") {
      console.log(JSON.stringify(result, null, 2));
      return;
    }
    console.log(chalk10.bold(`
MCP Servers (${result.totalServers} total)
`));
    for (const config of result.configs) {
      console.log(chalk10.cyan(`  ${config.source}`));
      console.log(chalk10.dim(`  ${config.filePath}`));
      for (const server of config.servers) {
        console.log(`    ${chalk10.bold(server.name)}`);
        console.log(`      Transport: ${server.transport}`);
        if (server.command) {
          const cmd = [server.command, ...server.args ?? []].join(" ");
          console.log(`      Command: ${cmd}`);
        }
        if (server.url) {
          console.log(`      URL: ${server.url}`);
        }
        if (server.env) {
          const envKeys = Object.keys(server.env);
          console.log(`      Env: ${envKeys.join(", ")}`);
        }
      }
      console.log("");
    }
  } catch (err) {
    logError(chalk10.red("MCP list failed:"), err);
    process.exitCode = 1;
  }
}
var init_mcp = __esm({
  "src/commands/mcp.ts"() {
    "use strict";
    init_engine();
    init_registry();
    init_check_registry();
    init_reporting();
    init_discovery();
    init_source_resolver();
    init_debug();
  }
});

// src/commands/skill-audit.ts
var skill_audit_exports = {};
__export(skill_audit_exports, {
  runSkillAudit: () => runSkillAudit
});
import chalk11 from "chalk";
import { stat as stat3 } from "fs/promises";
import { resolve as resolve5 } from "path";
import { writeFile as writeFile14 } from "fs/promises";
async function runSkillAudit(skillPath, options) {
  const resolved = resolve5(skillPath);
  let pathStat;
  try {
    pathStat = await stat3(resolved);
  } catch {
    console.error(chalk11.red(`Path does not exist: ${resolved}`));
    process.exitCode = 1;
    return;
  }
  if (!pathStat.isDirectory()) {
    console.error(chalk11.red(`Path is not a directory: ${resolved}`));
    process.exitCode = 1;
    return;
  }
  const skillFiles = await getSkillFiles(resolved);
  const hasSymlink = skillFiles.length === 0 && await directoryHasSymlink(resolved);
  if (skillFiles.length === 0 && !hasSymlink) {
    console.log(chalk11.yellow(`No code files or symlinks found in ${resolved}. Nothing to audit.`));
    return;
  }
  console.log(
    chalk11.dim(
      skillFiles.length > 0 ? `Auditing ${skillFiles.length} file(s) in ${resolved}
` : `Auditing ${resolved} for symlink escapes
`
    )
  );
  try {
    const engine = new ScanEngine(adapterRegistry, checkRegistry);
    const result = await engine.scanSkill(resolved, skillFiles, {
      format: options.format
    });
    const reporter = getReporter(options.format ?? "terminal");
    const output = reporter.render(result);
    if (options.output) {
      await writeFile14(options.output, output, "utf-8");
      console.log(chalk11.green(`Report written to ${options.output}`));
    } else {
      console.log(output);
    }
    const hasCritical = result.agents.some(
      (a) => a.results.some((r) => r.severity === "critical" && !r.passed)
    );
    if (hasCritical) {
      process.exitCode = 1;
    }
  } catch (err) {
    logError(chalk11.red("Skill audit failed:"), err);
    process.exitCode = 1;
  }
}
async function directoryHasSymlink(dir) {
  try {
    const entries = await new LocalFSProvider().readdirEntries(dir, { recursive: true });
    return entries.some((e) => e.isSymbolicLink);
  } catch {
    return false;
  }
}
var init_skill_audit = __esm({
  "src/commands/skill-audit.ts"() {
    "use strict";
    init_engine();
    init_registry();
    init_check_registry();
    init_reporting();
    init_utils();
    init_local_fs_provider();
    init_debug();
  }
});

// src/plugins/types.ts
var PLUGIN_AGENTS;
var init_types2 = __esm({
  "src/plugins/types.ts"() {
    "use strict";
    PLUGIN_AGENTS = ["openclaw", "nanoclaw", "picoclaw"];
  }
});

// src/plugins/installer.ts
import { readFile as readFile15, writeFile as writeFile15, mkdir as mkdir11, unlink as unlink4, chmod as chmod3, access as access3 } from "fs/promises";
import { join as join96, dirname as dirname10 } from "path";
import { homedir as homedir11 } from "os";
import { execFileSync as execFileSync3 } from "child_process";
function getPluginInstallPath(agent) {
  return PLUGIN_PATHS[agent];
}
function getManifestPath(agent) {
  const pluginPath = getPluginInstallPath(agent);
  return join96(dirname10(pluginPath), "vaso-plugin-manifest.json");
}
function resolveVasoBinaryPath() {
  if (process.argv[1]) {
    return process.argv[1];
  }
  try {
    const result = execFileSync3("which", ["vaso"], { encoding: "utf-8" }).trim();
    if (result) return result;
  } catch {
  }
  return "vaso";
}
function generatePluginContent(agent, vasoBinaryPath) {
  const configPath = CONFIG_PATH;
  const sharedPreamble = `// VASO Security Plugin \u2014 auto-generated by vaso plugin install
// Do not edit manually. Re-run: vaso plugin install --agent ${agent} --force
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const VASO_BINARY = ${JSON.stringify(vasoBinaryPath)};
const VASO_VERSION = ${JSON.stringify(VERSION3)};
const CONFIG_PATH = ${JSON.stringify(configPath)};

function loadConfig() {
  try {
    const raw = readFileSync(CONFIG_PATH, 'utf-8');
    return { blockOnCritical: true, blockOnWarning: false, timeout: 30000, excludeChecks: [], ...JSON.parse(raw) };
  } catch {
    return { blockOnCritical: true, blockOnWarning: false, timeout: 30000, excludeChecks: [] };
  }
}

function runScan(agent) {
  const config = loadConfig();
  try {
    const stdout = execFileSync(VASO_BINARY, ['scan', '--agent', agent, '--format', 'json'], {
      timeout: config.timeout,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return JSON.parse(stdout);
  } catch (err) {
    // Exit code 1 means critical findings \u2014 stdout still has valid JSON
    if (err.stdout) {
      try { return JSON.parse(err.stdout); } catch { /* fall through */ }
    }
    console.warn('[vaso] Security scan failed, allowing startup:', err.message);
    return null;
  }
}

function evaluate(result, config) {
  if (!result) return { blocked: false };
  const critical = result.agents?.flatMap(a => a.results ?? [])
    .filter(r => r.severity === 'critical' && !r.passed && !config.excludeChecks.includes(r.id)) ?? [];
  const warnings = result.agents?.flatMap(a => a.results ?? [])
    .filter(r => r.severity === 'warning' && !r.passed && !config.excludeChecks.includes(r.id)) ?? [];

  if (config.blockOnCritical && critical.length > 0) {
    return { blocked: true, reason: critical.length + ' critical finding(s)', critical, warnings };
  }
  if (config.blockOnWarning && warnings.length > 0) {
    return { blocked: true, reason: warnings.length + ' warning finding(s)', critical, warnings };
  }
  return { blocked: false, critical, warnings };
}
`;
  if (agent === "openclaw") {
    return `${sharedPreamble}
export default {
  name: 'vaso-security',
  version: VASO_VERSION,
  hooks: {
    before_agent_start: async () => {
      const result = runScan('openclaw');
      const config = loadConfig();
      const evaluation = evaluate(result, config);
      if (evaluation.warnings?.length) {
        console.warn('[vaso] ' + evaluation.warnings.length + ' security warning(s) detected');
      }
      if (evaluation.blocked) {
        throw new Error('[vaso] Agent startup blocked: ' + evaluation.reason);
      }
    },
  },
};
`;
  }
  if (agent === "nanoclaw") {
    return `${sharedPreamble}
export const name = 'vaso-security';
export const version = VASO_VERSION;
export const lifecycle = {
  onBeforeStart: async () => {
    const result = runScan('nanoclaw');
    const config = loadConfig();
    const evaluation = evaluate(result, config);
    if (evaluation.warnings?.length) {
      console.warn('[vaso] ' + evaluation.warnings.length + ' security warning(s) detected');
    }
    if (evaluation.blocked) {
      throw new Error('[vaso] Agent startup blocked: ' + evaluation.reason);
    }
  },
};
`;
  }
  return `${sharedPreamble}
export default {
  name: 'vaso-security',
  version: VASO_VERSION,
  handlers: {
    preStart: async () => {
      const result = runScan('picoclaw');
      const config = loadConfig();
      const evaluation = evaluate(result, config);
      if (evaluation.warnings?.length) {
        console.warn('[vaso] ' + evaluation.warnings.length + ' security warning(s) detected');
      }
      if (evaluation.blocked) {
        throw new Error('[vaso] Agent startup blocked: ' + evaluation.reason);
      }
    },
  },
};
`;
}
async function installPlugin(agent, options) {
  const pluginPath = getPluginInstallPath(agent);
  const manifestPath = getManifestPath(agent);
  if (!options?.force) {
    try {
      await access3(pluginPath);
      throw new Error(`Plugin already installed at ${pluginPath}. Use --force to overwrite.`);
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
    }
  }
  const vasoBinaryPath = options?.vasoBinaryPath ?? resolveVasoBinaryPath();
  const content = generatePluginContent(agent, vasoBinaryPath);
  await mkdir11(dirname10(pluginPath), { recursive: true });
  await writeFile15(pluginPath, content, "utf-8");
  await chmod3(pluginPath, 420);
  const manifest = {
    agent,
    vasoVersion: VERSION3,
    vasoBinaryPath,
    installedAt: (/* @__PURE__ */ new Date()).toISOString(),
    pluginPath
  };
  await writeFile15(manifestPath, JSON.stringify(manifest, null, 2), "utf-8");
  return { pluginPath, manifestPath };
}
async function uninstallPlugin(agent) {
  const pluginPath = getPluginInstallPath(agent);
  const manifestPath = getManifestPath(agent);
  for (const filePath of [pluginPath, manifestPath]) {
    try {
      await unlink4(filePath);
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
    }
  }
}
async function getPluginStatus(agent) {
  const agents = agent ? [agent] : PLUGIN_AGENTS;
  const results = [];
  for (const a of agents) {
    const pluginPath = getPluginInstallPath(a);
    const manifestPath = getManifestPath(a);
    let installed = false;
    let vasoBinaryPath;
    let installedAt;
    try {
      await access3(pluginPath);
      installed = true;
      try {
        const raw = await readFile15(manifestPath, "utf-8");
        const manifest = JSON.parse(raw);
        vasoBinaryPath = manifest.vasoBinaryPath;
        installedAt = manifest.installedAt;
      } catch {
      }
    } catch {
    }
    results.push({
      agent: a,
      installed,
      pluginPath: installed ? pluginPath : void 0,
      vasoBinaryPath,
      installedAt
    });
  }
  return results;
}
var VERSION3, PLUGIN_PATHS, CONFIG_PATH;
var init_installer = __esm({
  "src/plugins/installer.ts"() {
    "use strict";
    init_types2();
    VERSION3 = "0.2.1";
    PLUGIN_PATHS = {
      openclaw: join96(homedir11(), ".openclaw", "plugins", "vaso-security.mjs"),
      nanoclaw: join96(homedir11(), ".config", "nanoclaw", "plugins", "vaso-security.mjs"),
      picoclaw: join96(homedir11(), ".picoclaw", "plugins", "vaso-security.mjs")
    };
    CONFIG_PATH = join96(homedir11(), ".vaso", "plugin-config.json");
  }
});

// src/commands/plugin.ts
var plugin_exports = {};
__export(plugin_exports, {
  runPluginInstall: () => runPluginInstall,
  runPluginStatus: () => runPluginStatus,
  runPluginUninstall: () => runPluginUninstall
});
import chalk12 from "chalk";
function validateAgent(agent) {
  if (!PLUGIN_AGENTS.includes(agent)) {
    throw new Error(`Invalid agent: ${agent}. Must be one of: ${PLUGIN_AGENTS.join(", ")}`);
  }
  return agent;
}
async function runPluginInstall(options) {
  try {
    const agent = validateAgent(options.agent);
    const result = await installPlugin(agent, { force: options.force });
    console.log(chalk12.green(`Plugin installed for ${agent}`));
    console.log(chalk12.dim(`  Plugin: ${result.pluginPath}`));
    console.log(chalk12.dim(`  Manifest: ${result.manifestPath}`));
  } catch (err) {
    const message = err.message;
    if (message.includes("already installed")) {
      console.error(chalk12.red(message));
      console.error(chalk12.dim("Use --force to overwrite the existing plugin."));
    } else {
      console.error(chalk12.red(`Plugin install failed: ${message}`));
    }
    process.exitCode = 1;
  }
}
async function runPluginUninstall(options) {
  try {
    const agent = validateAgent(options.agent);
    await uninstallPlugin(agent);
    console.log(chalk12.green(`Plugin uninstalled for ${agent}`));
  } catch (err) {
    console.error(chalk12.red(`Plugin uninstall failed: ${err.message}`));
    process.exitCode = 1;
  }
}
async function runPluginStatus(options) {
  try {
    const agent = options.agent ? validateAgent(options.agent) : void 0;
    const statuses = await getPluginStatus(agent);
    if (options.format === "json") {
      console.log(JSON.stringify(statuses, null, 2));
      return;
    }
    console.log(chalk12.bold("\nVASO Plugin Status\n"));
    for (const status of statuses) {
      const icon = status.installed ? chalk12.green("\u25CF") : chalk12.dim("\u25CB");
      const state = status.installed ? chalk12.green("installed") : chalk12.dim("not installed");
      console.log(`  ${icon} ${chalk12.bold(status.agent)} \u2014 ${state}`);
      if (status.installed) {
        console.log(chalk12.dim(`    Path: ${status.pluginPath}`));
        if (status.installedAt) {
          console.log(chalk12.dim(`    Installed: ${status.installedAt}`));
        }
      }
    }
    console.log("");
  } catch (err) {
    console.error(chalk12.red(`Plugin status failed: ${err.message}`));
    process.exitCode = 1;
  }
}
var init_plugin = __esm({
  "src/commands/plugin.ts"() {
    "use strict";
    init_types2();
    init_installer();
  }
});

// src/commands/user-plugin.ts
var user_plugin_exports = {};
__export(user_plugin_exports, {
  runExtInfo: () => runExtInfo,
  runExtList: () => runExtList
});
import chalk13 from "chalk";
async function runExtList(options) {
  const plugins = getLoadedPlugins();
  if (options.format === "json") {
    console.log(JSON.stringify(plugins, null, 2));
    return;
  }
  if (plugins.length === 0) {
    console.log(chalk13.dim("  No user plugins loaded.\n"));
    console.log(chalk13.dim("  Drop .js or .mjs files into ~/.vaso/plugins/ to extend VASO.\n"));
    return;
  }
  console.log(chalk13.bold("\nUser Plugins\n"));
  for (const plugin of plugins) {
    const icon = plugin.status === "loaded" ? chalk13.green("\u25CF") : chalk13.red("\u25CF");
    const state = plugin.status === "loaded" ? chalk13.green("loaded") : chalk13.red("error");
    const nameStr = chalk13.bold(plugin.name) + (plugin.version ? chalk13.dim(` v${plugin.version}`) : "");
    console.log(`  ${icon} ${nameStr} \u2014 ${state}`);
    if (plugin.description) {
      console.log(chalk13.dim(`    ${plugin.description}`));
    }
    const counts = formatRegisteredCounts(plugin);
    if (counts) {
      console.log(chalk13.dim(`    Registered: ${counts}`));
    }
    console.log(chalk13.dim(`    Path: ${plugin.path}`));
    if (plugin.error) {
      console.log(chalk13.red(`    Error: ${plugin.error}`));
    }
  }
  console.log("");
}
async function runExtInfo(name, options) {
  const plugins = getLoadedPlugins();
  const plugin = plugins.find((p) => p.name === name);
  if (!plugin) {
    if (options.format === "json") {
      console.log(JSON.stringify({ error: `Plugin "${name}" not found` }));
    } else {
      console.error(chalk13.red(`  Plugin "${name}" not found.
`));
      const available = plugins.map((p) => p.name);
      if (available.length > 0) {
        console.log(chalk13.dim(`  Available plugins: ${available.join(", ")}
`));
      }
    }
    process.exitCode = 1;
    return;
  }
  if (options.format === "json") {
    console.log(JSON.stringify(plugin, null, 2));
    return;
  }
  console.log(chalk13.bold(`
Plugin: ${plugin.name}
`));
  const status = plugin.status === "loaded" ? chalk13.green("loaded") : chalk13.red("error");
  console.log(`  Status:      ${status}`);
  console.log(`  Path:        ${chalk13.dim(plugin.path)}`);
  if (plugin.version) console.log(`  Version:     ${plugin.version}`);
  if (plugin.description) console.log(`  Description: ${plugin.description}`);
  if (plugin.registered.checks.length > 0) {
    console.log(`
  ${chalk13.bold("Checks:")}    ${plugin.registered.checks.join(", ")}`);
  }
  if (plugin.registered.adapters.length > 0) {
    console.log(`  ${chalk13.bold("Adapters:")}  ${plugin.registered.adapters.join(", ")}`);
  }
  if (plugin.registered.reporters.length > 0) {
    console.log(`  ${chalk13.bold("Reporters:")} ${plugin.registered.reporters.join(", ")}`);
  }
  if (plugin.error) {
    console.log(`
  ${chalk13.red("Error:")} ${plugin.error}`);
  }
  console.log("");
}
function formatRegisteredCounts(plugin) {
  const parts = [];
  if (plugin.registered.checks.length > 0) {
    parts.push(`${plugin.registered.checks.length} check${plugin.registered.checks.length !== 1 ? "s" : ""}`);
  }
  if (plugin.registered.adapters.length > 0) {
    parts.push(`${plugin.registered.adapters.length} adapter${plugin.registered.adapters.length !== 1 ? "s" : ""}`);
  }
  if (plugin.registered.reporters.length > 0) {
    parts.push(`${plugin.registered.reporters.length} reporter${plugin.registered.reporters.length !== 1 ? "s" : ""}`);
  }
  return parts.join(", ");
}
var init_user_plugin = __esm({
  "src/commands/user-plugin.ts"() {
    "use strict";
    init_loader();
  }
});

// src/commands/rules.ts
var rules_exports = {};
__export(rules_exports, {
  runRulesInit: () => runRulesInit,
  runRulesList: () => runRulesList,
  runRulesValidate: () => runRulesValidate
});
import { writeFile as writeFile16, mkdir as mkdir12 } from "fs/promises";
import { join as join97 } from "path";
import { homedir as homedir12 } from "os";
import chalk14 from "chalk";
import { readFile as readFile16 } from "fs/promises";
import YAML4 from "yaml";
async function runRulesList(options) {
  const result = await loadRules();
  if (result.allErrors.length > 0) {
    for (const err of result.allErrors) {
      const loc = err.rule ? ` (rule ${err.rule})` : "";
      console.log(chalk14.yellow(`  Warning: ${err.file}${loc}: ${err.message}`));
    }
    console.log();
  }
  if (result.allRules.length === 0) {
    console.log(chalk14.dim("  No declarative rules found."));
    console.log(chalk14.dim(`  Create rules in ~/.vaso/rules/ or .vaso/rules/`));
    console.log(chalk14.dim(`  Run "vaso rules init" to generate a starter template.
`));
    return;
  }
  if (options.format === "json") {
    const output = result.allRules.map((r) => ({
      id: r.id,
      name: r.name,
      category: r.category,
      severity: r.severity,
      description: r.description,
      type: r.config ? "config" : r.pattern ? "pattern" : "file_exists"
    }));
    console.log(JSON.stringify(output, null, 2));
    return;
  }
  console.log(chalk14.bold(`  Loaded ${result.allRules.length} declarative rule(s):
`));
  const severityColor2 = (s) => s === "critical" ? chalk14.red(s) : s === "warning" ? chalk14.yellow(s) : chalk14.blue(s);
  for (const rule of result.allRules) {
    const type = rule.config ? "config" : rule.pattern ? "pattern" : "file_exists";
    console.log(`  ${chalk14.bold(rule.id)}  ${rule.name}`);
    console.log(`    ${severityColor2(rule.severity)}  ${chalk14.dim(type)}  ${chalk14.dim(rule.description)}`);
  }
  console.log();
  for (const file of result.files) {
    if (file.rules.length > 0) {
      console.log(chalk14.dim(`  ${file.filePath} (${file.rules.length} rule(s))`));
    }
  }
  console.log();
}
async function runRulesValidate(filePath, options) {
  let content;
  try {
    content = await readFile16(filePath, "utf-8");
  } catch (err) {
    console.error(chalk14.red(`  Error: Cannot read file: ${filePath}`));
    console.error(chalk14.red(`  ${err instanceof Error ? err.message : String(err)}
`));
    process.exitCode = 1;
    return;
  }
  let data;
  try {
    data = YAML4.parse(content);
  } catch (err) {
    console.error(chalk14.red(`  Error: Invalid YAML syntax`));
    console.error(chalk14.red(`  ${err instanceof Error ? err.message : String(err)}
`));
    process.exitCode = 1;
    return;
  }
  const { rules, errors } = validateRuleFile(data);
  if (options.format === "json") {
    console.log(JSON.stringify({ valid: errors.length === 0, rules: rules.length, errors }, null, 2));
    return;
  }
  if (errors.length > 0) {
    console.log(chalk14.red(`  ${errors.length} validation error(s) in ${filePath}:
`));
    for (const err of errors) {
      const loc = [err.rule, err.field].filter(Boolean).join(".");
      console.log(chalk14.red(`  ${loc ? `[${loc}] ` : ""}${err.message}`));
    }
    console.log();
    process.exitCode = 1;
  }
  if (rules.length > 0) {
    console.log(chalk14.green(`  ${rules.length} valid rule(s) in ${filePath}
`));
    for (const rule of rules) {
      const type = rule.config ? "config" : rule.pattern ? "pattern" : "file_exists";
      console.log(`    ${chalk14.bold(rule.id)}  ${rule.name}  ${chalk14.dim(`(${type}, ${rule.severity})`)}`);
    }
    console.log();
  }
  if (errors.length === 0) {
    console.log(chalk14.green("  All rules valid.\n"));
  }
}
async function runRulesInit(options) {
  const targetDir = options.dir ?? join97(homedir12(), ".vaso", "rules");
  const targetFile = join97(targetDir, "example.yaml");
  try {
    await mkdir12(targetDir, { recursive: true });
    await writeFile16(targetFile, STARTER_TEMPLATE, "utf-8");
    console.log(chalk14.green(`  Created starter rule file: ${targetFile}
`));
    console.log(chalk14.dim('  Edit the file and run "vaso rules validate" to check it.'));
    console.log(chalk14.dim('  Rules are loaded automatically on "vaso scan".\n'));
  } catch (err) {
    console.error(chalk14.red(`  Error creating rule file: ${err instanceof Error ? err.message : String(err)}
`));
    process.exitCode = 1;
  }
}
var STARTER_TEMPLATE;
var init_rules2 = __esm({
  "src/commands/rules.ts"() {
    "use strict";
    init_rules();
    STARTER_TEMPLATE = `# VASO Declarative Rules
# Place this file in ~/.vaso/rules/ (global) or .vaso/rules/ (project-level).
# All rules are loaded automatically on scan.
#
# Each rule must have exactly one type: config, pattern, or file_exists.
# See: https://github.com/vulnex/vaso#declarative-rules

rules:
  # Config value check \u2014 fail if a config field has a dangerous value
  - id: CUSTOM-001
    name: Disable debug mode
    category: config
    severity: warning
    description: Debug mode should be disabled in production
    # agents: [openclaw]         # optional: limit to specific agents
    # platforms: [linux, darwin]  # optional: limit to specific OS
    config:
      path: "server.debug"
      operator: "eq"
      value: true
    fix:
      set: "server.debug"
      value: false

  # Pattern match \u2014 scan config/skill files for regex matches
  - id: CUSTOM-002
    name: Hardcoded AWS access key
    category: config
    severity: critical
    description: AWS access keys must not be hardcoded in config files
    pattern:
      regex: "AKIA[0-9A-Z]{16}"
      target: "configs"        # configs | skills | all
      message: "AWS key found in {{file}}:{{line}}"

  # File existence \u2014 fail if a file exists (or does not exist)
  - id: CUSTOM-003
    name: No .env file in agent directory
    category: config
    severity: warning
    description: ".env files may contain secrets and should not be in the agent directory"
    file_exists:
      path: ".env"
      pass_when: "not-exists"
    fix:
      guidance: "Move secrets to a vault or environment variables and delete the .env file"
`;
  }
});

// src/commands/probe.ts
var probe_exports = {};
__export(probe_exports, {
  probeManifest: () => probeManifest,
  probeValidate: () => probeValidate
});
import { readFile as readFile17 } from "fs/promises";
async function probeManifest(adapters) {
  const allAdapters = adapters.getAdapters();
  const manifest = buildProbeManifest(allAdapters);
  console.log(JSON.stringify(manifest, null, 2));
}
async function probeValidate(snapshotPath) {
  let raw;
  try {
    raw = await readFile17(snapshotPath, "utf-8");
  } catch (err) {
    const code = err.code;
    console.error(code === "ENOENT" ? `Snapshot file not found: ${snapshotPath}` : `Failed to read snapshot file: ${err.message}`);
    process.exitCode = 1;
    return;
  }
  let snapshot;
  try {
    snapshot = JSON.parse(raw);
  } catch (err) {
    console.error(`Snapshot file is not valid JSON: ${err.message}`);
    process.exitCode = 1;
    return;
  }
  const errors = [];
  if (snapshot.version !== 1) errors.push(`Unsupported snapshot version: ${snapshot.version}`);
  if (!snapshot.platform) errors.push("Missing platform field");
  if (!snapshot.hostname) errors.push("Missing hostname field");
  if (!snapshot.files || typeof snapshot.files !== "object") errors.push("Missing or invalid files field");
  if (!snapshot.directories || typeof snapshot.directories !== "object") errors.push("Missing or invalid directories field");
  if (!snapshot.commandOutputs || typeof snapshot.commandOutputs !== "object") errors.push("Missing or invalid commandOutputs field");
  if (errors.length > 0) {
    console.error("Snapshot validation failed:");
    for (const e of errors) console.error(`  - ${e}`);
    process.exitCode = 1;
    return;
  }
  console.log(`Snapshot: ${snapshotPath}`);
  console.log(`  Host:      ${snapshot.hostname}`);
  console.log(`  Platform:  ${snapshot.platform}`);
  console.log(`  Timestamp: ${snapshot.timestamp}`);
  console.log(`  Files:     ${Object.keys(snapshot.files).length} collected`);
  console.log(`  Dirs:      ${Object.keys(snapshot.directories).length} collected`);
  console.log(`  Commands:  ${Object.keys(snapshot.commandOutputs).length} collected`);
  if (snapshot.privilege) {
    console.log(`  Privilege:  ${snapshot.privilege.isRoot ? "root" : "user"} (${snapshot.privilege.username})`);
    console.log(`  Users:     ${snapshot.privilege.scannedUsers.join(", ")}`);
  }
  console.log("Snapshot is valid.");
}
var init_probe = __esm({
  "src/commands/probe.ts"() {
    "use strict";
    init_manifest_builder();
  }
});

// src/cli.ts
init_registry();
import { Command } from "commander";
import chalk15 from "chalk";

// src/adapters/openclaw.ts
init_local_fs_provider();
init_config_loader();
init_utils();
import { join as join3, basename as basename2 } from "path";

// src/adapters/version-query.ts
import { basename, dirname as dirname2, join as join2 } from "path";
var SEMVER_RE = /(\d+\.\d+\.\d+(?:[-.][a-zA-Z0-9.]+)?)/;
var DEFAULT_TIMEOUT_MS = 15e3;
function queryCliVersion(binary, fs, options = {}) {
  if (!binary) return void 0;
  const argSets = options.argSets ?? [["--version"]];
  const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  for (const args of argSets) {
    try {
      const output = fs.execSync(binary, [...args], { timeout }).trim();
      const m = SEMVER_RE.exec(output);
      if (m?.[1]) return m[1];
    } catch {
    }
  }
  return void 0;
}
async function readPackageVersion(binary, fs, npmPackageName) {
  if (!binary) return void 0;
  try {
    let resolved;
    try {
      resolved = await fs.realpath(binary);
    } catch {
      resolved = binary;
    }
    let dir = dirname2(resolved);
    for (let i = 0; i < 6; i++) {
      const pkgPath = join2(dir, "package.json");
      try {
        const raw = await fs.readFile(pkgPath);
        const pkg = JSON.parse(raw);
        if (pkg.version && SEMVER_RE.test(pkg.version)) {
          return pkg.version;
        }
      } catch {
      }
      const parent = dirname2(dir);
      if (parent === dir) break;
      dir = parent;
    }
  } catch {
  }
  if (npmPackageName) {
    const direct = await readNpmGlobalDirect(binary, fs, npmPackageName);
    if (direct) return direct;
  }
  return readNpmGlobalPackageVersion(binary, fs);
}
async function readNpmGlobalDirect(binary, fs, packageName) {
  const binDir = dirname2(binary);
  if (basename(binDir) !== "bin") return void 0;
  const prefix = dirname2(binDir);
  const pkgPath = join2(prefix, "lib", "node_modules", packageName, "package.json");
  try {
    const pkg = JSON.parse(await fs.readFile(pkgPath));
    if (pkg.version && SEMVER_RE.test(pkg.version)) return pkg.version;
  } catch {
  }
  return void 0;
}
async function readNpmGlobalPackageVersion(binary, fs) {
  const binDir = dirname2(binary);
  if (basename(binDir) !== "bin") return void 0;
  const name = basename(binary);
  const prefix = dirname2(binDir);
  const nodeModulesDir = join2(prefix, "lib", "node_modules");
  if (!await fs.access(nodeModulesDir)) return void 0;
  let entries;
  try {
    entries = await fs.readdirEntries(nodeModulesDir);
  } catch {
    return void 0;
  }
  const candidates = [];
  for (const e of entries) {
    if (!e.isDirectory) continue;
    if (e.name.startsWith("@")) {
      const scopeDir = join2(nodeModulesDir, e.name);
      let scoped;
      try {
        scoped = await fs.readdirEntries(scopeDir);
      } catch {
        continue;
      }
      for (const s of scoped) {
        if (s.isDirectory) candidates.push(join2(scopeDir, s.name));
      }
    } else {
      candidates.push(join2(nodeModulesDir, e.name));
    }
  }
  for (const pkgDir of candidates) {
    const pkgPath = join2(pkgDir, "package.json");
    let pkg;
    try {
      pkg = JSON.parse(await fs.readFile(pkgPath));
    } catch {
      continue;
    }
    if (!pkg.version || !SEMVER_RE.test(pkg.version)) continue;
    let matches = false;
    if (typeof pkg.bin === "string") {
      const pkgName = typeof pkg.name === "string" ? pkg.name : "";
      const tail = pkgName.includes("/") ? pkgName.split("/").pop() : pkgName;
      matches = tail === name;
    } else if (pkg.bin && typeof pkg.bin === "object") {
      matches = Object.prototype.hasOwnProperty.call(pkg.bin, name);
    }
    if (matches) return pkg.version;
  }
  return void 0;
}

// src/adapters/openclaw.ts
var CONFIG_FILENAMES = [
  "openclaw.json",
  "config.yaml",
  "config.json",
  "gateway.yaml",
  ".env"
];
var SYSTEM_CLI_PATHS = [
  "/usr/local/bin/openclaw",
  "/opt/homebrew/bin/openclaw",
  "/usr/bin/openclaw"
];
var USER_CLI_RELATIVE_PATHS = [
  ".volta/bin/openclaw",
  ".local/bin/openclaw",
  ".nvm/current/bin/openclaw",
  ".npm-global/bin/openclaw",
  "bin/openclaw"
];
var AGENT_CONFIG_FILENAMES = [
  "agent.yaml",
  "agent.json",
  "config.yaml",
  "config.json",
  ".env"
];
var APP_BUNDLE_PATH = "/Applications/OpenClaw.app";
var EXCLUDED_USERS = /* @__PURE__ */ new Set(["Shared", "Guest", ".localized"]);
async function getUserHomeDirs(allUsers, fs) {
  const _fs = fs ?? new LocalFSProvider();
  if (allUsers && process.getuid?.() === 0) {
    const baseDir = _fs.platform === "darwin" ? "/Users" : "/home";
    try {
      const entries = await _fs.readdirEntries(baseDir);
      const dirs = [];
      for (const entry of entries) {
        if (!entry.isDirectory) continue;
        if (EXCLUDED_USERS.has(entry.name)) continue;
        dirs.push({ home: join3(baseDir, entry.name), user: entry.name });
      }
      if (_fs.platform === "linux" && await _fs.access("/root")) {
        dirs.push({ home: "/root", user: "root" });
      }
      return dirs;
    } catch {
    }
  }
  const home = _fs.homedir();
  return [{ home, user: basename2(home) }];
}
function getSearchDirs(home, profile, fs) {
  const dirs = [
    join3(home, ".openclaw"),
    join3(home, ".clawdbot"),
    join3(home, ".moltbot")
  ];
  if (profile) {
    dirs.unshift(join3(home, `.openclaw-${profile}`));
  }
  if (process.env.OPENCLAW_HOME) {
    dirs.unshift(process.env.OPENCLAW_HOME);
  }
  const currentHome = fs ? fs.homedir() : new LocalFSProvider().homedir();
  if (home === currentHome) {
    dirs.push("/etc/openclaw");
  }
  return dirs;
}
async function findCLIBinary(home, fs) {
  for (const p of SYSTEM_CLI_PATHS) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS) {
    const p = join3(home, rel);
    if (await fs.access(p)) return p;
  }
  try {
    const result = fs.execSync("which", ["openclaw"], { timeout: 3e3 }).trim();
    if (result) return result;
  } catch {
  }
  return void 0;
}
async function findAppBundle(fs) {
  if (fs.platform !== "darwin") return void 0;
  if (await fs.access(APP_BUNDLE_PATH)) return APP_BUNDLE_PATH;
  return void 0;
}
var openclawAdapter = {
  agent: "openclaw",
  displayName: "OpenClaw",
  async detect(options) {
    const fs = options?.fs ?? new LocalFSProvider();
    const profile = process.env.OPENCLAW_PROFILE || void 0;
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const appBundle = await findAppBundle(fs);
    const installations = [];
    for (const { home, user } of userDirs) {
      const cliBinary = await findCLIBinary(home, fs);
      const searchDirs = getSearchDirs(home, profile, fs);
      let foundForUser = false;
      for (const dir of searchDirs) {
        if (!await fs.access(dir)) continue;
        const configFiles = [];
        for (const filename of CONFIG_FILENAMES) {
          const filePath = join3(dir, filename);
          try {
            const config = await loadConfig(filePath, fs);
            configFiles.push(config);
          } catch {
          }
        }
        if (configFiles.length === 0) continue;
        const mainConfig = configFiles.find((c) => c.filePath.endsWith("openclaw.json"));
        const meta = mainConfig?.data?.meta;
        const version = mainConfig?.data?.version ?? meta?.lastTouchedVersion ?? meta?.lastRunVersion ?? (cliBinary ? queryCliVersion(cliBinary, fs, { argSets: [["--version"], ["version"]] }) : void 0) ?? (cliBinary ? await readPackageVersion(cliBinary, fs) : void 0);
        const skillsDir = this.getSkillsDir(dir);
        const merged = {};
        for (const c of configFiles) {
          Object.assign(merged, c.data);
        }
        const globalInstallation = {
          agent: "openclaw",
          version,
          installDir: dir,
          configFiles,
          skillsDir,
          gateway: this.getGatewayInfo(merged),
          models: await this.getModels?.(configFiles),
          profile,
          user: options?.allUsers ? user : void 0,
          appBundle,
          cliBinary
        };
        installations.push(globalInstallation);
        const agentsDir = join3(dir, "agents");
        if (await fs.access(agentsDir)) {
          try {
            const agentEntries = await fs.readdirEntries(agentsDir);
            for (const entry of agentEntries) {
              if (!entry.isDirectory) continue;
              const agentSubDir = join3(agentsDir, entry.name);
              const agentConfigFiles = [];
              for (const filename of AGENT_CONFIG_FILENAMES) {
                const filePath = join3(agentSubDir, filename);
                try {
                  const config = await loadConfig(filePath, fs);
                  agentConfigFiles.push(config);
                } catch {
                }
              }
              let agentMerged = { ...merged };
              for (const c of agentConfigFiles) {
                agentMerged = deepMerge(agentMerged, c.data);
              }
              const agentSkillsDirs = [];
              if (skillsDir && await fs.access(skillsDir)) {
                agentSkillsDirs.push(skillsDir);
              }
              const agentSkillsDir = join3(agentSubDir, "skills");
              if (await fs.access(agentSkillsDir)) {
                agentSkillsDirs.push(agentSkillsDir);
              }
              installations.push({
                agent: "openclaw",
                agentName: entry.name,
                version,
                installDir: agentSubDir,
                configFiles: [...configFiles, ...agentConfigFiles],
                skillsDir: agentSkillsDirs.length > 0 ? agentSkillsDirs[agentSkillsDirs.length - 1] : void 0,
                skillsDirs: agentSkillsDirs.length > 0 ? agentSkillsDirs : void 0,
                gateway: this.getGatewayInfo(agentMerged),
                models: await this.getModels?.([...configFiles, ...agentConfigFiles]),
                profile,
                user: options?.allUsers ? user : void 0,
                appBundle,
                cliBinary
              });
            }
          } catch {
          }
        }
        foundForUser = true;
      }
      if (!foundForUser && (cliBinary || appBundle)) {
        installations.push({
          agent: "openclaw",
          installDir: join3(home, ".openclaw"),
          configFiles: [],
          cliBinary,
          appBundle,
          profile,
          user: options?.allUsers ? user : void 0
        });
      }
    }
    return installations;
  },
  getConfigPaths() {
    const _fs = new LocalFSProvider();
    const dirs = getSearchDirs(_fs.homedir(), process.env.OPENCLAW_PROFILE || void 0, _fs);
    return dirs.flatMap(
      (dir) => CONFIG_FILENAMES.map((f) => join3(dir, f))
    );
  },
  getSkillsDir(installDir) {
    const candidates = [
      join3(installDir, "skills"),
      join3(installDir, "custom_skills")
    ];
    return candidates[0];
  },
  getGatewayInfo(config) {
    const gw = config.gateway;
    if (!gw) return void 0;
    return {
      host: gw.host,
      port: gw.port,
      authMode: gw.auth?.mode,
      tls: gw.tls
    };
  },
  getModels(configs) {
    const main = configs.find((c) => c.filePath.endsWith("openclaw.json"));
    const providers = main?.data?.models?.providers;
    if (!providers) return [];
    const out = [];
    for (const [provider, providerCfg] of Object.entries(providers)) {
      const list = providerCfg?.models;
      if (!Array.isArray(list)) continue;
      for (const m of list) {
        const id = m?.id ?? m?.name;
        if (id) out.push({ id, provider });
      }
    }
    return out;
  },
  getMemoryFiles(installDir) {
    return [
      join3(installDir, "memory.json"),
      join3(installDir, "conversations.db")
    ];
  },
  getCredentialPaths(installDir) {
    return [
      join3(installDir, ".env"),
      join3(installDir, "credentials.json"),
      join3(installDir, "auth.json")
    ];
  },
  getCLICommand() {
    return "openclaw";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.openclaw/openclaw.json",
        "~/.openclaw/config.yaml",
        "~/.openclaw/config.json",
        "~/.openclaw/gateway.yaml",
        "~/.openclaw/.env",
        "~/.clawdbot/openclaw.json",
        "~/.clawdbot/config.yaml",
        "~/.clawdbot/config.json",
        "~/.clawdbot/gateway.yaml",
        "~/.clawdbot/.env",
        "~/.moltbot/openclaw.json",
        "~/.moltbot/config.yaml",
        "~/.moltbot/config.json",
        "~/.moltbot/gateway.yaml",
        "~/.moltbot/.env",
        "~/.openclaw/credentials.json",
        "~/.openclaw/auth.json",
        "~/.openclaw/memory.json",
        "~/.openclaw/conversations.db",
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        "~/.volta/bin/openclaw",
        "~/.local/bin/openclaw",
        "~/.nvm/current/bin/openclaw",
        "~/.npm-global/bin/openclaw",
        "~/bin/openclaw"
      ],
      globPatterns: [
        "~/.openclaw/skills/**",
        "~/.openclaw/custom_skills/**",
        "~/.openclaw/agents/*/agent.yaml",
        "~/.openclaw/agents/*/agent.json",
        "~/.openclaw/agents/*/config.yaml",
        "~/.openclaw/agents/*/config.json",
        "~/.openclaw/agents/*/.env",
        "~/.openclaw/agents/*/skills/**"
      ],
      commands: [
        { id: "openclaw-which", cmd: "which", args: ["openclaw"], timeout: 3e3 },
        { id: "openclaw-version", cmd: "openclaw", args: ["--version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.openclaw",
        "~/.openclaw/agents",
        "~/.openclaw/skills",
        "~/.clawdbot",
        "~/.moltbot"
      ],
      envPrefixes: ["OPENCLAW_"],
      systemPaths: [
        "/usr/local/bin/openclaw",
        "/opt/homebrew/bin/openclaw",
        "/usr/bin/openclaw",
        "/etc/openclaw",
        "/Applications/OpenClaw.app"
      ],
      systemDirListings: [
        "/etc/openclaw"
      ]
    };
  }
};

// src/adapters/nanoclaw.ts
init_local_fs_provider();
init_config_loader();
import { join as join4 } from "path";
var nanoclawAdapter = {
  agent: "nanoclaw",
  displayName: "NanoClaw",
  async detect(_options) {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const configDir = join4(home, ".config", "nanoclaw");
    const envPath = join4(home, ".nanoclaw.env");
    const configFiles = [];
    if (await fs.access(envPath)) {
      try {
        const config = await loadConfig(envPath, fs);
        if (config.data.NANOCLAW_HOME || config.data.NANOCLAW_PORT) {
          configFiles.push(config);
        }
      } catch {
      }
    }
    const mountAllowlistPath = join4(configDir, "mount-allowlist.json");
    if (await fs.access(mountAllowlistPath)) {
      try {
        configFiles.push(await loadConfig(mountAllowlistPath, fs));
      } catch {
      }
    }
    const configPath = join4(configDir, "config.json");
    if (await fs.access(configPath)) {
      try {
        configFiles.push(await loadConfig(configPath, fs));
      } catch {
      }
    }
    if (configFiles.length === 0) return [];
    const mainConfig = configFiles.find((c) => c.filePath.endsWith("config.json"));
    const version = mainConfig?.data?.version ?? queryCliVersion("nanoclaw", fs);
    return [{
      agent: "nanoclaw",
      installDir: configDir,
      configFiles,
      skillsDir: this.getSkillsDir(configDir),
      models: await this.getModels?.(configFiles, fs),
      version
    }];
  },
  getConfigPaths() {
    const home = new LocalFSProvider().homedir();
    return [
      join4(home, ".nanoclaw.env"),
      join4(home, ".config", "nanoclaw", "config.json"),
      join4(home, ".config", "nanoclaw", "mount-allowlist.json")
    ];
  },
  getSkillsDir(installDir) {
    return join4(installDir, "skills");
  },
  getGatewayInfo(config) {
    return void 0;
  },
  getModels(_configs, _fs) {
    return [];
  },
  getCLICommand() {
    return "nanoclaw";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.nanoclaw.env",
        "~/.config/nanoclaw/config.json",
        "~/.config/nanoclaw/mount-allowlist.json"
      ],
      globPatterns: [
        "~/.config/nanoclaw/skills/**"
      ],
      commands: [
        { id: "nanoclaw-which", cmd: "which", args: ["nanoclaw"], timeout: 3e3 },
        { id: "nanoclaw-version", cmd: "nanoclaw", args: ["--version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.config/nanoclaw",
        "~/.config/nanoclaw/skills"
      ],
      envPrefixes: ["NANOCLAW_"],
      systemPaths: [],
      systemDirListings: []
    };
  }
};

// src/adapters/picoclaw.ts
init_local_fs_provider();
init_config_loader();
import { join as join5 } from "path";
var picoclawAdapter = {
  agent: "picoclaw",
  displayName: "PicoClaw",
  async detect(_options) {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const picoDir = join5(home, ".picoclaw");
    const configFiles = [];
    const configPath = join5(picoDir, "config.json");
    if (await fs.access(configPath)) {
      try {
        configFiles.push(await loadConfig(configPath, fs));
      } catch {
      }
    }
    const authPath = join5(picoDir, "auth.json");
    if (await fs.access(authPath)) {
      try {
        configFiles.push(await loadConfig(authPath, fs));
      } catch {
      }
    }
    if (configFiles.length === 0) return [];
    const merged = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }
    const mainConfig = configFiles.find((c) => c.filePath.endsWith("config.json"));
    const version = mainConfig?.data?.version ?? queryCliVersion("picoclaw", fs);
    return [{
      agent: "picoclaw",
      installDir: picoDir,
      configFiles,
      skillsDir: this.getSkillsDir(picoDir),
      gateway: this.getGatewayInfo(merged),
      models: await this.getModels?.(configFiles),
      version
    }];
  },
  getConfigPaths() {
    const home = new LocalFSProvider().homedir();
    return [
      join5(home, ".picoclaw", "config.json"),
      join5(home, ".picoclaw", "auth.json")
    ];
  },
  getSkillsDir(installDir) {
    return join5(installDir, "skills");
  },
  getGatewayInfo(config) {
    const gw = config.gateway;
    if (!gw) return void 0;
    return {
      host: gw.host,
      port: gw.port,
      authMode: config.auth?.mode,
      tls: gw.tls
    };
  },
  getModels(configs) {
    const out = [];
    const seen = /* @__PURE__ */ new Set();
    const push = (modelStr, slot, isDefault) => {
      if (typeof modelStr !== "string" || !modelStr.trim()) return;
      const trimmed = modelStr.trim();
      const slash = trimmed.indexOf("/");
      const provider = slash !== -1 ? trimmed.slice(0, slash) : void 0;
      const id = slash !== -1 ? trimmed.slice(slash + 1) : trimmed;
      const via = isDefault ? void 0 : slot;
      const key = `${provider ?? ""}|${id}|${via ?? ""}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, ...provider ? { provider } : {}, ...via ? { via } : {} });
    };
    const main = configs.find((c) => c.filePath.endsWith("config.json"));
    if (!main) return out;
    const defaultName = main.data?.agents?.defaults?.model_name;
    const list = main.data?.model_list;
    if (Array.isArray(list)) {
      for (const entry of list) {
        const e = entry;
        const name = e?.model_name;
        const model = e?.model;
        if (!name) continue;
        push(model, name, name === defaultName);
      }
    }
    return out;
  },
  getCLICommand() {
    return "picoclaw";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.picoclaw/config.json",
        "~/.picoclaw/auth.json"
      ],
      globPatterns: [
        "~/.picoclaw/skills/**"
      ],
      commands: [
        { id: "picoclaw-which", cmd: "which", args: ["picoclaw"], timeout: 3e3 },
        { id: "picoclaw-version", cmd: "picoclaw", args: ["--version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.picoclaw",
        "~/.picoclaw/skills"
      ],
      envPrefixes: ["PICOCLAW_"],
      systemPaths: [],
      systemDirListings: []
    };
  }
};

// src/adapters/ironclaw.ts
init_local_fs_provider();
init_config_loader();
import { join as join6 } from "path";
var CONFIG_FILENAMES2 = [
  ".env",
  "config.toml",
  "settings.json",
  "mcp-servers.json"
];
var ironclawAdapter = {
  agent: "ironclaw",
  displayName: "IronClaw",
  async detect(_options) {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const ironDir = join6(home, ".ironclaw");
    const configFiles = [];
    for (const filename of CONFIG_FILENAMES2) {
      const filePath = join6(ironDir, filename);
      if (await fs.access(filePath)) {
        try {
          configFiles.push(await loadConfig(filePath, fs));
        } catch {
        }
      }
    }
    const cliBinary = await findCLIBinary2(home, fs);
    if (configFiles.length === 0 && !cliBinary) return [];
    const merged = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }
    const tomlConfig = configFiles.find((c) => c.filePath.endsWith(".toml"));
    const version = tomlConfig?.data?.version ?? tomlConfig?.data?.package?.version ?? queryCliVersion(cliBinary ?? "ironclaw", fs);
    return [{
      agent: "ironclaw",
      installDir: ironDir,
      configFiles,
      skillsDir: this.getSkillsDir(ironDir),
      gateway: this.getGatewayInfo(merged),
      models: await this.getModels?.(configFiles, fs),
      cliBinary,
      version
    }];
  },
  getConfigPaths() {
    const home = new LocalFSProvider().homedir();
    const ironDir = join6(home, ".ironclaw");
    return CONFIG_FILENAMES2.map((f) => join6(ironDir, f));
  },
  getSkillsDir(installDir) {
    return join6(installDir, "skills");
  },
  getGatewayInfo(config) {
    const envHost = config.GATEWAY_HOST;
    const envPort = config.GATEWAY_PORT;
    if (envHost || envPort) {
      return {
        host: envHost,
        port: envPort ? parseInt(envPort, 10) : void 0
      };
    }
    const gw = config.gateway;
    if (gw) {
      return {
        host: gw.host,
        port: gw.port,
        tls: gw.tls
      };
    }
    return void 0;
  },
  getModels(configs, fs) {
    const out = [];
    const seen = /* @__PURE__ */ new Set();
    const BACKEND_ENV = {
      nearai: { model: "NEARAI_MODEL" },
      ollama: { model: "OLLAMA_MODEL" },
      openai_compatible: { model: "LLM_MODEL" },
      openai: { model: "OPENAI_MODEL" },
      anthropic: { model: "ANTHROPIC_MODEL" },
      github_copilot: { model: "GITHUB_COPILOT_MODEL" },
      tinfoil: { model: "TINFOIL_MODEL" },
      openai_codex: { model: "OPENAI_CODEX_MODEL" },
      gemini_oauth: { model: "GEMINI_MODEL" },
      minimax: { model: "MINIMAX_MODEL" }
    };
    const lookup = (key) => {
      const env = configs.find((c) => c.filePath.endsWith(".env"));
      const fromFile = env?.data?.[key];
      if (typeof fromFile === "string" && fromFile.trim()) return fromFile.trim();
      const fromProc = fs?.getEnv?.(key);
      if (typeof fromProc === "string" && fromProc.trim()) return fromProc.trim();
      return void 0;
    };
    const push = (id, provider, via) => {
      if (!id) return;
      const key = `${provider}|${id}|${via ?? ""}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, provider, ...via ? { via } : {} });
    };
    const selected = lookup("LLM_BACKEND");
    if (selected && BACKEND_ENV[selected]) {
      push(lookup(BACKEND_ENV[selected].model), selected);
    } else {
      for (const [backend, keys] of Object.entries(BACKEND_ENV)) {
        push(lookup(keys.model), backend, selected ? void 0 : "env-detected");
      }
    }
    return out;
  },
  getMemoryFiles(installDir) {
    return [
      join6(installDir, "memory.json"),
      join6(installDir, "conversations.db")
    ];
  },
  getCredentialPaths(installDir) {
    return [
      join6(installDir, ".env"),
      join6(installDir, "config.toml"),
      join6(installDir, "settings.json")
    ];
  },
  getCLICommand() {
    return "ironclaw";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.ironclaw/.env",
        "~/.ironclaw/config.toml",
        "~/.ironclaw/settings.json",
        "~/.ironclaw/mcp-servers.json",
        "~/.ironclaw/memory.json",
        "~/.ironclaw/conversations.db"
      ],
      globPatterns: [
        "~/.ironclaw/skills/**"
      ],
      commands: [
        { id: "ironclaw-which", cmd: "which", args: ["ironclaw"], timeout: 3e3 },
        { id: "ironclaw-version", cmd: "ironclaw", args: ["--version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.ironclaw",
        "~/.ironclaw/skills",
        "~/.cargo/bin"
      ],
      envPrefixes: ["IRONCLAW_", "GATEWAY_"],
      systemPaths: [],
      systemDirListings: []
    };
  },
  getZoneGraph() {
    return {
      zones: [
        { id: "net", label: "Network", trustLevel: 0 },
        { id: "gw", label: "gRPC Gateway", trustLevel: 1 },
        { id: "sbx", label: "Sandbox", trustLevel: 2 },
        { id: "host", label: "Host FS", trustLevel: 3 }
      ],
      components: [
        { id: "inbound", label: "Network Ingress", zone: "net" },
        {
          id: "gateway",
          label: "IronClaw gRPC Gateway",
          zone: "gw",
          guardCheckIds: ["IC-001", "IC-002", "IC-003", "IC-004", "IC-010"]
        },
        {
          id: "sandbox",
          label: "Sandbox Boundary",
          zone: "sbx",
          guardCheckIds: ["IC-005", "IC-006", "IC-011", "IC-012"]
        },
        {
          id: "fs",
          label: "Host Filesystem",
          zone: "host",
          guardCheckIds: ["IC-007", "IC-008", "IC-009"]
        }
      ],
      edges: [
        { from: "inbound", to: "gateway", kind: "data" },
        { from: "gateway", to: "sandbox", kind: "control" },
        { from: "sandbox", to: "fs", kind: "data" },
        {
          from: "inbound",
          to: "fs",
          label: "sandbox bypass",
          triggerCheckIds: ["IC-005", "IC-008"]
        }
      ]
    };
  }
};
async function findCLIBinary2(home, fs) {
  const cargoPath = join6(home, ".cargo", "bin", "ironclaw");
  if (await fs.access(cargoPath)) return cargoPath;
  try {
    const result = fs.execSync("which", ["ironclaw"], { timeout: 3e3 }).trim();
    if (result) return result;
  } catch {
  }
  return void 0;
}

// src/adapters/nanobot.ts
init_local_fs_provider();
init_config_loader();
import { join as join7 } from "path";
var SYSTEM_CLI_PATHS2 = [
  "/usr/local/bin/nanobot",
  "/opt/homebrew/bin/nanobot",
  "/usr/bin/nanobot"
];
var USER_CLI_RELATIVE_PATHS2 = [
  ".local/bin/nanobot",
  ".npm-global/bin/nanobot",
  ".volta/bin/nanobot",
  ".bun/bin/nanobot"
];
function nodeModulesPackageJsonCandidates(home) {
  return [
    "/usr/lib/node_modules/nanobot/package.json",
    "/usr/local/lib/node_modules/nanobot/package.json",
    "/opt/homebrew/lib/node_modules/nanobot/package.json",
    `${home}/.npm-global/lib/node_modules/nanobot/package.json`,
    `${home}/.bun/install/global/node_modules/nanobot/package.json`,
    `${home}/.volta/tools/image/packages/nanobot/package.json`
  ];
}
async function readNodePackageVersion(fs) {
  const home = fs.homedir();
  for (const p of nodeModulesPackageJsonCandidates(home)) {
    try {
      const raw = await fs.readFile(p);
      const pkg = JSON.parse(raw);
      if (pkg.version && /^\d+\.\d+\.\d+/.test(pkg.version)) return pkg.version;
    } catch {
    }
  }
  return void 0;
}
var nanobotAdapter = {
  agent: "nanobot",
  displayName: "Nanobot",
  async detect(_options) {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const nanobotDir = join7(home, ".nanobot");
    const configFiles = [];
    const configPath = join7(nanobotDir, "config.json");
    if (await fs.access(configPath)) {
      try {
        configFiles.push(await loadConfig(configPath, fs));
      } catch {
      }
    }
    const cliBinary = await findCLIBinary3(home, fs);
    if (configFiles.length === 0 && !cliBinary) return [];
    const merged = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }
    const mainConfig = configFiles.find((c) => c.filePath.endsWith("config.json"));
    const version = mainConfig?.data?.version ?? queryCliVersion(cliBinary, fs) ?? await readPackageVersion(cliBinary, fs) ?? await readNodePackageVersion(fs);
    return [{
      agent: "nanobot",
      installDir: nanobotDir,
      configFiles,
      skillsDir: this.getSkillsDir(nanobotDir),
      gateway: this.getGatewayInfo(merged),
      models: await this.getModels?.(configFiles),
      cliBinary,
      version
    }];
  },
  getConfigPaths() {
    const home = new LocalFSProvider().homedir();
    return [
      join7(home, ".nanobot", "config.json")
    ];
  },
  getSkillsDir(installDir) {
    return join7(installDir, "workspace", "skills");
  },
  getGatewayInfo(config) {
    const host = config.host;
    const port = config.port;
    if (host || port) {
      return {
        host: host ?? "0.0.0.0",
        port: port ?? 18790
      };
    }
    return void 0;
  },
  getModels(configs) {
    const main = configs.find((c) => c.filePath.endsWith("config.json"));
    const agents = main?.data?.agents;
    const out = [];
    const seen = /* @__PURE__ */ new Set();
    const push = (raw, via) => {
      const slash = raw.indexOf("/");
      const provider = slash !== -1 ? raw.slice(0, slash) : void 0;
      const id = slash !== -1 ? raw.slice(slash + 1) : raw;
      const key = `${provider ?? ""}|${id}|${via ?? ""}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, provider, via });
    };
    const defaults = agents?.defaults;
    const defaultModel = defaults?.model;
    if (defaultModel) push(defaultModel);
    for (const [name, cfg] of Object.entries(agents ?? {})) {
      if (name === "defaults") continue;
      const m = cfg?.model;
      if (m) push(m, name);
    }
    return out;
  },
  getMemoryFiles(installDir) {
    return [
      join7(installDir, "workspace", "memory", "MEMORY.md"),
      join7(installDir, "workspace", "HEARTBEAT.md"),
      join7(installDir, "workspace", "SOUL.md")
    ];
  },
  getCredentialPaths(installDir) {
    return [
      join7(installDir, "config.json")
    ];
  },
  getCLICommand() {
    return "nanobot";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.nanobot/config.json",
        "~/.nanobot/workspace/memory/MEMORY.md",
        "~/.nanobot/workspace/HEARTBEAT.md",
        "~/.nanobot/workspace/SOUL.md",
        // User-relative CLI install locations.
        "~/.local/bin/nanobot",
        "~/.npm-global/bin/nanobot",
        "~/.volta/bin/nanobot",
        "~/.bun/bin/nanobot",
        // npm-global package.json (canonical version source for Node CLIs).
        "/usr/lib/node_modules/nanobot/package.json",
        "/usr/local/lib/node_modules/nanobot/package.json",
        "/opt/homebrew/lib/node_modules/nanobot/package.json",
        "~/.npm-global/lib/node_modules/nanobot/package.json",
        "~/.bun/install/global/node_modules/nanobot/package.json",
        "~/.volta/tools/image/packages/nanobot/package.json"
      ],
      globPatterns: [
        "~/.nanobot/workspace/skills/**",
        "~/.nvm/versions/node/*/lib/node_modules/nanobot/package.json"
      ],
      commands: [
        { id: "nanobot-which", cmd: "which", args: ["nanobot"], timeout: 3e3 },
        { id: "nanobot-version", cmd: "nanobot", args: ["--version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.nanobot",
        "~/.nanobot/workspace",
        "~/.nanobot/workspace/skills"
      ],
      envPrefixes: ["NANOBOT_"],
      systemPaths: SYSTEM_CLI_PATHS2,
      systemDirListings: []
    };
  },
  getZoneGraph() {
    return {
      zones: [
        { id: "chat", label: "Chat Platforms", trustLevel: 0 },
        { id: "core", label: "Bot Core", trustLevel: 1 },
        { id: "exec", label: "Shell Exec", trustLevel: 2 },
        { id: "host", label: "Host FS", trustLevel: 3 }
      ],
      components: [
        { id: "edge", label: "Discord/Slack Edge", zone: "chat" },
        {
          id: "bot",
          label: "Nanobot Core",
          zone: "core",
          guardCheckIds: ["NB-001", "NB-008", "NB-010", "NB-011", "NB-012"]
        },
        {
          id: "shell",
          label: "Tool/Shell Execution",
          zone: "exec",
          guardCheckIds: ["NB-004", "NB-005", "NB-006", "NB-007", "NB-009"]
        },
        {
          id: "fs",
          label: "Host Filesystem",
          zone: "host",
          guardCheckIds: ["NB-002", "NB-003"]
        }
      ],
      edges: [
        { from: "edge", to: "bot", kind: "data", label: "message" },
        { from: "bot", to: "shell", kind: "control" },
        { from: "shell", to: "fs", kind: "data" },
        {
          from: "edge",
          to: "fs",
          label: "channel-driven exec",
          triggerCheckIds: ["NB-001", "NB-004"]
        }
      ]
    };
  }
};
async function findCLIBinary3(home, fs) {
  for (const p of SYSTEM_CLI_PATHS2) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS2) {
    const p = join7(home, rel);
    if (await fs.access(p)) return p;
  }
  try {
    const result = fs.execSync("which", ["nanobot"], { timeout: 3e3 }).trim();
    if (result) return result;
  } catch {
  }
  return void 0;
}

// src/adapters/zeroclaw.ts
init_local_fs_provider();
init_config_loader();
init_utils();
import { join as join8 } from "path";
var CONFIG_FILENAMES3 = [
  "config.toml",
  "auth-profiles.json"
];
var zeroclawAdapter = {
  agent: "zeroclaw",
  displayName: "ZeroClaw",
  async detect(_options) {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const zeroDir = join8(home, ".zeroclaw");
    const configFiles = [];
    for (const filename of CONFIG_FILENAMES3) {
      const filePath = join8(zeroDir, filename);
      if (await fs.access(filePath)) {
        try {
          configFiles.push(await loadConfig(filePath, fs));
        } catch {
        }
      }
    }
    const cliBinary = await findCLIBinary4(home, fs);
    if (configFiles.length === 0 && !cliBinary) return [];
    const merged = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }
    const tomlConfig = configFiles.find((c) => c.filePath.endsWith(".toml"));
    const version = tomlConfig?.data?.version ?? tomlConfig?.data?.package?.version ?? queryCliVersion(cliBinary ?? "zeroclaw", fs);
    return [{
      agent: "zeroclaw",
      installDir: zeroDir,
      configFiles,
      skillsDir: this.getSkillsDir(zeroDir),
      gateway: this.getGatewayInfo(merged),
      models: await this.getModels?.(configFiles, fs),
      cliBinary,
      version
    }];
  },
  getConfigPaths() {
    const home = new LocalFSProvider().homedir();
    const zeroDir = join8(home, ".zeroclaw");
    return CONFIG_FILENAMES3.map((f) => join8(zeroDir, f));
  },
  getSkillsDir(installDir) {
    return join8(installDir, "workspace", "skills");
  },
  getGatewayInfo(config) {
    const serverHost = getNestedValue(config, "server.host");
    const serverPort = getNestedValue(config, "server.port");
    if (serverHost || serverPort) {
      return {
        host: serverHost,
        port: serverPort ?? 3e3
      };
    }
    const gwHost = getNestedValue(config, "gateway.host");
    const gwPort = getNestedValue(config, "gateway.port");
    if (gwHost || gwPort) {
      return {
        host: gwHost,
        port: gwPort ?? 3e3
      };
    }
    return void 0;
  },
  getModels(configs, fs) {
    const out = [];
    const seen = /* @__PURE__ */ new Set();
    const stripUrl = (provider) => {
      if (!provider) return void 0;
      const colon = provider.indexOf(":");
      return colon !== -1 ? provider.slice(0, colon) : provider;
    };
    const push = (rawId, rawProvider, via) => {
      if (typeof rawId !== "string" || !rawId.trim()) return;
      const trimmed = rawId.trim();
      let provider = typeof rawProvider === "string" && rawProvider.trim() ? stripUrl(rawProvider.trim()) : void 0;
      let id = trimmed;
      if (!provider && trimmed.includes("/")) {
        const slash = trimmed.indexOf("/");
        provider = trimmed.slice(0, slash);
        id = trimmed.slice(slash + 1);
      }
      const key = `${provider ?? ""}|${id}|${via ?? ""}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, ...provider ? { provider } : {}, ...via ? { via } : {} });
    };
    const toml = configs.find((c) => c.filePath.endsWith("config.toml"));
    if (toml) {
      push(toml.data?.default_model, toml.data?.default_provider);
      const routes = toml.data?.model_routes;
      if (Array.isArray(routes)) {
        for (const r of routes) {
          const route = r;
          const name = route?.name ?? route?.id;
          push(route?.model, route?.provider, name);
        }
      }
      const reliability = toml.data?.reliability;
      const fallbacks = reliability?.model_fallbacks;
      if (fallbacks) {
        for (const [slot, val] of Object.entries(fallbacks)) {
          if (typeof val === "string") {
            push(val, void 0, `fallback:${slot}`);
          } else if (Array.isArray(val)) {
            for (const v of val) {
              if (typeof v === "string") push(v, void 0, `fallback:${slot}`);
            }
          }
        }
      }
    }
    if (out.length === 0 && fs?.getEnv) {
      push(fs.getEnv("ZEROCLAW_MODEL"), fs.getEnv("ZEROCLAW_PROVIDER"), "ZEROCLAW_MODEL");
    }
    return out;
  },
  getCredentialPaths(installDir) {
    return [
      join8(installDir, "config.toml"),
      join8(installDir, "auth-profiles.json"),
      join8(installDir, ".secret_key")
    ];
  },
  getCLICommand() {
    return "zeroclaw";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.zeroclaw/config.toml",
        "~/.zeroclaw/auth-profiles.json",
        "~/.zeroclaw/.secret_key"
      ],
      globPatterns: [
        "~/.zeroclaw/workspace/skills/**"
      ],
      commands: [
        { id: "zeroclaw-which", cmd: "which", args: ["zeroclaw"], timeout: 3e3 },
        { id: "zeroclaw-version", cmd: "zeroclaw", args: ["--version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.zeroclaw",
        "~/.zeroclaw/workspace",
        "~/.zeroclaw/workspace/skills",
        "~/.cargo/bin"
      ],
      envPrefixes: ["ZEROCLAW_"],
      systemPaths: [],
      systemDirListings: []
    };
  }
};
async function findCLIBinary4(home, fs) {
  const cargoPath = join8(home, ".cargo", "bin", "zeroclaw");
  if (await fs.access(cargoPath)) return cargoPath;
  try {
    const result = fs.execSync("which", ["zeroclaw"], { timeout: 3e3 }).trim();
    if (result) return result;
  } catch {
  }
  return void 0;
}

// src/adapters/nemoclaw.ts
init_local_fs_provider();
init_config_loader();
import { join as join9 } from "path";
var SYSTEM_CLI_PATHS3 = [
  "/usr/local/bin/nemoclaw",
  "/usr/bin/nemoclaw",
  "/opt/homebrew/bin/nemoclaw"
];
var USER_CLI_RELATIVE_PATHS3 = [
  ".local/bin/nemoclaw",
  ".npm-global/bin/nemoclaw",
  ".volta/bin/nemoclaw",
  ".bun/bin/nemoclaw"
];
async function findCLIBinary5(home, fs) {
  for (const p of SYSTEM_CLI_PATHS3) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS3) {
    const p = join9(home, rel);
    if (await fs.access(p)) return p;
  }
  try {
    const result = fs.execSync("which", ["nemoclaw"], { timeout: 3e3 }).trim();
    if (result) return result;
  } catch {
  }
  return void 0;
}
function nodeModulesPackageJsonCandidates2(home) {
  return [
    "/usr/lib/node_modules/nemoclaw/package.json",
    "/usr/local/lib/node_modules/nemoclaw/package.json",
    "/opt/homebrew/lib/node_modules/nemoclaw/package.json",
    `${home}/.npm-global/lib/node_modules/nemoclaw/package.json`,
    `${home}/.bun/install/global/node_modules/nemoclaw/package.json`,
    `${home}/.volta/tools/image/packages/nemoclaw/package.json`
  ];
}
async function readNodePackageVersion2(fs) {
  const home = fs.homedir();
  for (const p of nodeModulesPackageJsonCandidates2(home)) {
    try {
      const raw = await fs.readFile(p);
      const pkg = JSON.parse(raw);
      if (pkg.version && /^\d+\.\d+\.\d+/.test(pkg.version)) return pkg.version;
    } catch {
    }
  }
  return void 0;
}
var PIP_VERSION_RE = /^Version:\s*(\d+\.\d+\.\d+(?:[-.][a-zA-Z0-9.]+)?)/m;
var SEMVER_RE2 = /^\s*(\d+\.\d+\.\d+(?:[-.][a-zA-Z0-9.]+)?)\s*$/m;
var IMPORT_META_SCRIPT = "from importlib.metadata import version; print(version('nemoclaw'))";
var PY_VERSIONS = ["3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"];
var PKG_DIRS = ["site-packages", "dist-packages"];
var NEMOCLAW_DIST_RE = /^nemoclaw[-_]/i;
var DIST_INFO_SUFFIX = [".dist-info", ".egg-info"];
function tryExec(fs, argv) {
  try {
    return fs.execSync(argv[0], argv.slice(1), { timeout: 1e4 });
  } catch {
    return void 0;
  }
}
function parsePipShowVersion(fs, argv) {
  const out = tryExec(fs, argv);
  if (!out) return void 0;
  return PIP_VERSION_RE.exec(out)?.[1];
}
function parsePyMetadataVersion(fs, python) {
  const out = tryExec(fs, [python, "-c", IMPORT_META_SCRIPT]);
  if (!out) return void 0;
  return SEMVER_RE2.exec(out)?.[1];
}
async function findInstalledPackageVersion(fs) {
  const home = fs.homedir();
  const roots = [
    "/usr/lib",
    "/usr/local/lib",
    `${home}/.local/lib`,
    `${home}/.local/share/pipx/venvs/nemoclaw/lib`
  ];
  for (const root of roots) {
    for (const ver of PY_VERSIONS) {
      for (const pkgs of PKG_DIRS) {
        const dir = `${root}/python${ver}/${pkgs}`;
        let entries;
        try {
          entries = await fs.readdirEntries(dir);
        } catch {
          continue;
        }
        for (const entry of entries) {
          if (!NEMOCLAW_DIST_RE.test(entry.name)) continue;
          if (!DIST_INFO_SUFFIX.some((s) => entry.name.endsWith(s))) continue;
          for (const fname of ["METADATA", "PKG-INFO"]) {
            try {
              const content = await fs.readFile(`${dir}/${entry.name}/${fname}`);
              const m = PIP_VERSION_RE.exec(content);
              if (m?.[1]) return m[1];
            } catch {
            }
          }
        }
      }
    }
  }
  return void 0;
}
var nemoclawAdapter = {
  agent: "nemoclaw",
  displayName: "NemoClaw",
  async detect(_options) {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const nemoDir = join9(home, ".nemoclaw");
    if (!await fs.access(nemoDir)) return [];
    const configFiles = [];
    const sandboxesPath = join9(nemoDir, "sandboxes.json");
    if (await fs.access(sandboxesPath)) {
      try {
        configFiles.push(await loadConfig(sandboxesPath, fs));
      } catch {
      }
    }
    const credPath = join9(nemoDir, "credentials.json");
    if (await fs.access(credPath)) {
      try {
        configFiles.push(await loadConfig(credPath, fs));
      } catch {
      }
    }
    const configPath = join9(nemoDir, "config.json");
    if (await fs.access(configPath)) {
      try {
        configFiles.push(await loadConfig(configPath, fs));
      } catch {
      }
    }
    const statePath = join9(nemoDir, "state", "nemoclaw.json");
    if (await fs.access(statePath)) {
      try {
        configFiles.push(await loadConfig(statePath, fs));
      } catch {
      }
    }
    if (configFiles.length === 0) return [];
    const cliBinary = await findCLIBinary5(home, fs);
    let version = await readNodePackageVersion2(fs) ?? await readPackageVersion(cliBinary, fs) ?? parsePyMetadataVersion(fs, "python3") ?? parsePyMetadataVersion(fs, "python") ?? parsePipShowVersion(fs, ["pip3", "show", "nemoclaw"]) ?? parsePipShowVersion(fs, ["pip", "show", "nemoclaw"]) ?? await findInstalledPackageVersion(fs) ?? queryCliVersion("nemoclaw", fs, {
      argSets: [["version"], ["--version"], ["help"]]
    });
    if (!version) {
      try {
        const stateRaw = await fs.readFile(statePath);
        const state = JSON.parse(stateRaw);
        version = state.blueprintVersion;
      } catch {
      }
    }
    let agentName;
    try {
      const sandboxesRaw = await fs.readFile(sandboxesPath);
      const sandboxes = JSON.parse(sandboxesRaw);
      const defaultSandbox = sandboxes.defaultSandbox;
      const sandboxMap = sandboxes.sandboxes;
      const count = sandboxMap ? Object.keys(sandboxMap).length : 0;
      if (defaultSandbox) {
        agentName = count > 1 ? `${defaultSandbox} (+${count - 1} more)` : defaultSandbox;
      }
    } catch {
    }
    return [{
      agent: "nemoclaw",
      agentName,
      installDir: nemoDir,
      configFiles,
      cliBinary,
      version,
      models: await this.getModels?.(configFiles)
    }];
  },
  getConfigPaths() {
    const home = new LocalFSProvider().homedir();
    return [
      join9(home, ".nemoclaw", "sandboxes.json"),
      join9(home, ".nemoclaw", "credentials.json"),
      join9(home, ".nemoclaw", "config.json"),
      join9(home, ".nemoclaw", "state", "nemoclaw.json")
    ];
  },
  getSkillsDir(_installDir) {
    return void 0;
  },
  getGatewayInfo(_config) {
    return void 0;
  },
  getModels(configs) {
    const sb = configs.find((c) => c.filePath.endsWith("sandboxes.json"));
    const map = sb?.data?.sandboxes;
    if (!map) return [];
    const out = [];
    for (const [name, cfg] of Object.entries(map)) {
      const c = cfg;
      const id = c?.model;
      if (!id) continue;
      out.push({ id, provider: c?.provider, via: name });
    }
    return out;
  },
  getCredentialPaths(installDir) {
    return [join9(installDir, "credentials.json")];
  },
  getCLICommand() {
    return "nemoclaw";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.nemoclaw/sandboxes.json",
        "~/.nemoclaw/credentials.json",
        "~/.nemoclaw/config.json",
        "~/.nemoclaw/state/nemoclaw.json",
        // NemoClaw is shipped as an npm-global Node.js package — its
        // package.json holds the canonical version. Cover the common
        // global-install prefixes.
        "/usr/lib/node_modules/nemoclaw/package.json",
        "/usr/local/lib/node_modules/nemoclaw/package.json",
        "~/.npm-global/lib/node_modules/nemoclaw/package.json",
        "~/.bun/install/global/node_modules/nemoclaw/package.json",
        "~/.volta/tools/image/packages/nemoclaw/package.json"
      ],
      globPatterns: [
        "~/.nemoclaw/blueprints/**",
        "~/.nemoclaw/policies/**",
        // nvm installs live under a per-version subdir.
        "~/.nvm/versions/node/*/lib/node_modules/nemoclaw/package.json",
        // Defensive: also collect any nearby package.json walking up from the
        // /usr/bin/nemoclaw shim, and Python METADATA in case a fork is
        // packaged that way.
        "/usr/lib/python*/site-packages/nemoclaw*/METADATA",
        "/usr/lib/python*/dist-packages/nemoclaw*/METADATA",
        "/usr/local/lib/python*/site-packages/nemoclaw*/METADATA",
        "/usr/local/lib/python*/dist-packages/nemoclaw*/METADATA",
        "~/.local/lib/python*/site-packages/nemoclaw*/METADATA"
      ],
      commands: [
        { id: "nemoclaw-which", cmd: "which", args: ["nemoclaw"], timeout: 3e3 },
        { id: "nemoclaw-version-flag", cmd: "nemoclaw", args: ["--version"], timeout: 15e3 },
        { id: "nemoclaw-version-sub", cmd: "nemoclaw", args: ["version"], timeout: 15e3 },
        { id: "nemoclaw-help", cmd: "nemoclaw", args: ["help"], timeout: 15e3 },
        // NemoClaw is a pip/pipx/uv-installed Python CLI without a built-in
        // version flag. importlib.metadata works regardless of install method
        // and is the most reliable source.
        {
          id: "nemoclaw-py3-meta",
          cmd: "python3",
          args: ["-c", "from importlib.metadata import version; print(version('nemoclaw'))"],
          timeout: 1e4
        },
        {
          id: "nemoclaw-py-meta",
          cmd: "python",
          args: ["-c", "from importlib.metadata import version; print(version('nemoclaw'))"],
          timeout: 1e4
        },
        { id: "nemoclaw-pip3-show", cmd: "pip3", args: ["show", "nemoclaw"], timeout: 1e4 },
        { id: "nemoclaw-pip-show", cmd: "pip", args: ["show", "nemoclaw"], timeout: 1e4 }
      ],
      directoryListings: [
        "~/.nemoclaw",
        "~/.nemoclaw/state",
        "~/.nemoclaw/blueprints",
        "~/.nemoclaw/policies"
      ],
      envPrefixes: ["NEMOCLAW_"],
      systemPaths: [
        "/usr/bin/nemoclaw",
        "/usr/local/bin/nemoclaw"
      ],
      systemDirListings: []
    };
  },
  getZoneGraph() {
    return {
      zones: [
        { id: "net", label: "Network", trustLevel: 0 },
        { id: "gw", label: "Gateway", trustLevel: 1 },
        { id: "cpu", label: "CPU Sandbox", trustLevel: 2 },
        { id: "gpu", label: "GPU Isolation", trustLevel: 3 },
        { id: "host", label: "Host FS", trustLevel: 4 }
      ],
      components: [
        { id: "inbound", label: "Network Ingress", zone: "net" },
        {
          id: "gateway",
          label: "NemoClaw Gateway",
          zone: "gw",
          guardCheckIds: ["CFG-001", "CFG-004", "NET-001", "CFG-020"]
        },
        {
          id: "sandbox",
          label: "CPU Sandbox",
          zone: "cpu",
          guardCheckIds: ["CFG-016", "CFG-017", "CFG-022", "CFG-024"]
        },
        {
          id: "gpu",
          label: "GPU Boundary",
          zone: "gpu",
          guardCheckIds: ["CFG-018", "CFG-019", "CFG-021", "CFG-023"]
        },
        {
          id: "fs",
          label: "Host Filesystem",
          zone: "host",
          guardCheckIds: ["RUN-001", "POL-001"]
        }
      ],
      edges: [
        { from: "inbound", to: "gateway", kind: "data" },
        { from: "gateway", to: "sandbox", kind: "control" },
        { from: "sandbox", to: "gpu", kind: "resource" },
        { from: "gpu", to: "fs", kind: "data", label: "model artifacts" },
        {
          from: "inbound",
          to: "fs",
          label: "sandbox bypass",
          triggerCheckIds: ["CFG-017", "CFG-022", "CFG-024"]
        }
      ]
    };
  }
};

// src/adapters/hermes.ts
init_local_fs_provider();
init_config_loader();
import { join as join10 } from "path";
var CONFIG_FILENAMES4 = ["cli-config.yaml", "config.yaml", ".env"];
var SYSTEM_CLI_PATHS4 = [
  "/usr/local/bin/hermes",
  "/opt/homebrew/bin/hermes",
  "/usr/bin/hermes"
];
var USER_CLI_RELATIVE_PATHS4 = [
  ".local/bin/hermes",
  ".local/pipx/venvs/hermes-agent/bin/hermes"
];
var hermesAdapter = {
  agent: "hermes",
  displayName: "Hermes",
  async detect(_options) {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const hermesHome = process.env.HERMES_HOME ?? join10(home, ".hermes");
    if (!await fs.access(hermesHome)) return [];
    const configFiles = [];
    for (const filename of CONFIG_FILENAMES4) {
      const filePath = join10(hermesHome, filename);
      try {
        if (await fs.access(filePath)) {
          configFiles.push(await loadConfig(filePath, fs));
        }
      } catch {
      }
    }
    if (configFiles.length === 0) return [];
    const version = queryCliVersion(await findCLIBinary6(home, fs), fs, { argSets: [["version"], ["--version"]] });
    const merged = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }
    const cliBinary = await findCLIBinary6(home, fs);
    return [{
      agent: "hermes",
      installDir: hermesHome,
      configFiles,
      skillsDir: this.getSkillsDir(hermesHome),
      version,
      gateway: this.getGatewayInfo(merged),
      models: await this.getModels?.(configFiles, fs),
      cliBinary
    }];
  },
  getConfigPaths() {
    const home = new LocalFSProvider().homedir();
    const hermesHome = process.env.HERMES_HOME ?? join10(home, ".hermes");
    return CONFIG_FILENAMES4.map((f) => join10(hermesHome, f));
  },
  getSkillsDir(installDir) {
    return join10(installDir, "skills");
  },
  getGatewayInfo(config) {
    const platforms = config.platforms;
    const apiServer = platforms?.api_server;
    if (!apiServer && !platforms) return void 0;
    return {
      host: apiServer?.host ?? "127.0.0.1",
      port: apiServer?.port ?? 8642
    };
  },
  getModels(configs, fs) {
    const out = [];
    const seen = /* @__PURE__ */ new Set();
    const push = (rawId, rawProvider, via) => {
      if (typeof rawId !== "string" || !rawId.trim()) return;
      const trimmed = rawId.trim();
      let provider = typeof rawProvider === "string" && rawProvider.trim() ? rawProvider.trim() : void 0;
      let id = trimmed;
      if (!provider && trimmed.includes("/")) {
        const slash = trimmed.indexOf("/");
        provider = trimmed.slice(0, slash);
        id = trimmed.slice(slash + 1);
      }
      const key = `${provider ?? ""}|${id}|${via ?? ""}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, ...provider ? { provider } : {}, ...via ? { via } : {} });
    };
    const yaml = configs.find(
      (c) => c.filePath.endsWith("cli-config.yaml") || c.filePath.endsWith("config.yaml")
    );
    const block = yaml?.data?.model;
    if (typeof block === "string") {
      push(block);
    } else if (block && typeof block === "object") {
      const m = block;
      push(m.default ?? m.model, m.provider);
      push(m.fallback, m.fallback_provider ?? m.provider, "fallback");
    }
    const env = configs.find((c) => c.filePath.endsWith(".env"));
    if (env) {
      const envProvider = env.data.HERMES_PROVIDER;
      push(env.data.HERMES_MODEL, envProvider, out.length ? "HERMES_MODEL" : void 0);
      push(env.data.HERMES_DEFAULT_MODEL, envProvider);
      push(env.data.OPENROUTER_MODEL, "openrouter", "OPENROUTER_MODEL");
    }
    if (out.length === 0 && fs?.getEnv) {
      push(fs.getEnv("HERMES_MODEL"), fs.getEnv("HERMES_PROVIDER"), "HERMES_MODEL");
    }
    return out;
  },
  getMemoryFiles(installDir) {
    return [
      join10(installDir, "memory"),
      join10(installDir, "conversations.db")
    ];
  },
  getCredentialPaths(installDir) {
    return [
      join10(installDir, ".env"),
      join10(installDir, "credentials.json")
    ];
  },
  getCLICommand() {
    return "hermes";
  },
  // Hermes' privilege gradient: untrusted network → API-server gateway →
  // approvals/Tirith layer → terminal/MCP/inference fan-out → host filesystem
  // and remote inference endpoints. Inversion edges fire when the API server
  // is reachable without auth (HM-004) or approvals are off (HM-008), when
  // a custom inference endpoint is plaintext (HM-006) or untrusted (HM-007),
  // or when MCP stdio is shell-c'd / world-writable (HM-010).
  getZoneGraph() {
    return {
      zones: [
        { id: "net", label: "Network / Browser Tabs", trustLevel: 0 },
        { id: "api", label: "API Server Gateway", trustLevel: 1 },
        { id: "approval", label: "Approvals + Tirith", trustLevel: 2 },
        { id: "tools", label: "Terminal + MCP + Inference", trustLevel: 3 },
        { id: "host", label: "Host FS + Remote Endpoints", trustLevel: 4 }
      ],
      components: [
        { id: "inbound", label: "Network Ingress", zone: "net" },
        {
          id: "api-server",
          label: "Hermes API Server (8642)",
          zone: "api",
          guardCheckIds: ["HM-004", "HM-005"]
        },
        {
          id: "approval-layer",
          label: "Approvals + Tirith Scanner",
          zone: "approval",
          guardCheckIds: ["HM-008", "HM-009"]
        },
        {
          id: "tool-fanout",
          label: "Terminal + MCP + Inference",
          zone: "tools",
          guardCheckIds: ["HM-001", "HM-002", "HM-003", "HM-010"]
        },
        {
          id: "remote",
          label: "Inference Endpoints + Host FS",
          zone: "host",
          guardCheckIds: ["HM-006", "HM-007"]
        }
      ],
      edges: [
        { from: "inbound", to: "api-server", kind: "data" },
        { from: "api-server", to: "approval-layer", kind: "control" },
        { from: "approval-layer", to: "tool-fanout", kind: "data" },
        { from: "tool-fanout", to: "remote", kind: "data" },
        {
          from: "inbound",
          to: "tool-fanout",
          label: "unauth API bypass",
          triggerCheckIds: ["HM-004"]
        },
        {
          from: "api-server",
          to: "tool-fanout",
          label: "approval bypass",
          triggerCheckIds: ["HM-008"]
        },
        {
          from: "tool-fanout",
          to: "remote",
          label: "plaintext / exfil endpoint",
          triggerCheckIds: ["HM-006", "HM-007"]
        }
      ]
    };
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.hermes/cli-config.yaml",
        "~/.hermes/config.yaml",
        "~/.hermes/.env",
        "~/.hermes/credentials.json"
      ],
      globPatterns: [
        "~/.hermes/skills/**",
        "~/.hermes/optional-skills/**"
      ],
      commands: [
        { id: "hermes-which", cmd: "which", args: ["hermes"], timeout: 3e3 },
        { id: "hermes-version", cmd: "hermes", args: ["version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.hermes",
        "~/.hermes/skills",
        "~/.hermes/optional-skills"
      ],
      envPrefixes: ["HERMES_"],
      systemPaths: [
        "/usr/local/bin/hermes",
        "/opt/homebrew/bin/hermes",
        "/usr/bin/hermes"
      ],
      systemDirListings: []
    };
  }
};
async function findCLIBinary6(home, fs) {
  for (const p of SYSTEM_CLI_PATHS4) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS4) {
    const p = join10(home, rel);
    if (await fs.access(p)) return p;
  }
  try {
    const result = fs.execSync("which", ["hermes"], { timeout: 3e3 }).trim();
    if (result) return result;
  } catch {
  }
  return void 0;
}

// src/adapters/lyrie.ts
init_local_fs_provider();
init_config_loader();
import { join as join11 } from "path";
var RUNTIME_FILES = [".env"];
var SYSTEM_CLI_PATHS5 = [
  "/usr/local/bin/lyrie",
  "/opt/homebrew/bin/lyrie",
  "/usr/bin/lyrie"
];
var USER_CLI_RELATIVE_PATHS5 = [
  ".bun/bin/lyrie",
  ".local/bin/lyrie"
];
var lyrieAdapter = {
  agent: "lyrie",
  displayName: "Lyrie",
  async detect(_options) {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const lyrieDir = join11(home, ".lyrie");
    const runtimeMarkers = [
      join11(lyrieDir, "memory"),
      join11(lyrieDir, "pairing.json"),
      join11(lyrieDir, "edits.json"),
      join11(lyrieDir, "migrations")
    ];
    let hasRuntime = false;
    for (const marker of runtimeMarkers) {
      if (await fs.access(marker)) {
        hasRuntime = true;
        break;
      }
    }
    const cliBinary = await findCLIBinary7(home, fs);
    if (!hasRuntime && !cliBinary) return [];
    const configFiles = [];
    for (const filename of RUNTIME_FILES) {
      const filePath = join11(lyrieDir, filename);
      if (await fs.access(filePath)) {
        try {
          configFiles.push(await loadConfig(filePath, fs));
        } catch {
        }
      }
    }
    const merged = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }
    const version = queryCliVersion(cliBinary, fs, { argSets: [["--version"], ["version"]] }) ?? await readPackageVersion(cliBinary, fs) ?? "0.1.0";
    return [{
      agent: "lyrie",
      installDir: lyrieDir,
      configFiles,
      skillsDir: this.getSkillsDir(lyrieDir),
      gateway: this.getGatewayInfo(merged),
      models: await this.getModels?.(configFiles, fs),
      cliBinary,
      version
    }];
  },
  getConfigPaths() {
    const home = new LocalFSProvider().homedir();
    const lyrieDir = join11(home, ".lyrie");
    return RUNTIME_FILES.map((f) => join11(lyrieDir, f));
  },
  getSkillsDir(installDir) {
    return join11(installDir, "skills");
  },
  getGatewayInfo(config) {
    const webchatPort = config.LYRIE_WEBCHAT_PORT;
    const webchatHost = config.LYRIE_WEBCHAT_HOST;
    if (!webchatPort) return void 0;
    const port = parseInt(webchatPort, 10);
    if (Number.isNaN(port)) return void 0;
    return {
      host: webchatHost ?? "127.0.0.1",
      port
    };
  },
  getModels(configs, fs) {
    const out = [];
    const seen = /* @__PURE__ */ new Set();
    const push = (raw, via) => {
      if (typeof raw !== "string" || !raw.trim()) return;
      const trimmed = raw.trim();
      const slash = trimmed.indexOf("/");
      const provider = slash !== -1 ? trimmed.slice(0, slash) : void 0;
      const id = slash !== -1 ? trimmed.slice(slash + 1) : trimmed;
      const key = `${provider ?? ""}|${id}|${via ?? ""}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, ...provider ? { provider } : {}, ...via ? { via } : {} });
    };
    const env = configs.find((c) => c.filePath.endsWith(".env"));
    if (env) {
      push(env.data.LYRIE_MODEL);
      push(env.data.LYRIE_DEFAULT_MODEL);
      push(env.data.LYRIE_FALLBACK_MODEL, "fallback");
      for (const [k, v] of Object.entries(env.data)) {
        const m = /^LYRIE_([A-Z]+)_MODEL$/.exec(k);
        if (!m) continue;
        const slot = m[1].toLowerCase();
        if (slot === "default" || slot === "fallback") continue;
        if (typeof v === "string") push(v, slot);
      }
    }
    if (out.length === 0 && fs?.getEnv) {
      push(fs.getEnv("LYRIE_MODEL"), "LYRIE_MODEL");
    }
    return out;
  },
  getMemoryFiles(installDir) {
    return [
      join11(installDir, "memory", "lyrie-memory.db"),
      join11(installDir, "edits.json"),
      join11(installDir, "pairing.json")
    ];
  },
  getCredentialPaths(installDir) {
    return [
      join11(installDir, ".env")
    ];
  },
  getCLICommand() {
    return "lyrie";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.lyrie/.env",
        "~/.lyrie/memory/lyrie-memory.db",
        "~/.lyrie/edits.json",
        "~/.lyrie/pairing.json",
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        "~/.bun/bin/lyrie",
        "~/.local/bin/lyrie"
      ],
      globPatterns: [
        "~/.lyrie/memory/archive/*.db",
        "~/.lyrie/migrations/*.json",
        "~/.lyrie/skills/**"
      ],
      commands: [
        { id: "lyrie-which", cmd: "which", args: ["lyrie"], timeout: 3e3 },
        { id: "lyrie-version", cmd: "lyrie", args: ["--version"], timeout: 15e3 },
        { id: "lyrie-shield-version", cmd: "lyrie-shield", args: ["--version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.lyrie",
        "~/.lyrie/memory",
        "~/.lyrie/memory/archive",
        "~/.lyrie/skills",
        "~/.lyrie/migrations"
      ],
      envPrefixes: [
        "LYRIE_",
        "ANTHROPIC_",
        "OPENAI_",
        "GOOGLE_",
        "XAI_",
        "MINIMAX_",
        "OLLAMA_",
        "TELEGRAM_",
        "DISCORD_",
        "SLACK_",
        "WHATSAPP_",
        "MATRIX_",
        "FEISHU_",
        "DAYTONA_",
        "MODAL_"
      ],
      systemPaths: SYSTEM_CLI_PATHS5,
      systemDirListings: []
    };
  },
  // Layered architecture: Shield is Layer 1, sitting between channels and the
  // engine. Inversion edges fire when Shield is degraded (passive mode or
  // missing binary) or DM pairing is left open — in either case untrusted
  // channel input flows past the intended security gate.
  getZoneGraph() {
    return {
      zones: [
        { id: "net", label: "Network", trustLevel: 0 },
        { id: "ch", label: "Channel Gateway", trustLevel: 1 },
        { id: "shld", label: "Lyrie Shield (Layer 1)", trustLevel: 2 },
        { id: "eng", label: "Engine + EditEngine + MCP", trustLevel: 3 },
        { id: "mem", label: "Memory + Pairing + Edits", trustLevel: 4 }
      ],
      components: [
        { id: "inbound", label: "Network Ingress", zone: "net" },
        {
          id: "channels",
          label: "Channel Adapters",
          zone: "ch",
          guardCheckIds: ["LY-003", "LY-010", "LY-011"]
        },
        {
          id: "shield",
          label: "Lyrie Shield",
          zone: "shld",
          guardCheckIds: ["LY-001", "LY-002"]
        },
        {
          id: "engine",
          label: "Engine + EditEngine",
          zone: "eng",
          guardCheckIds: ["LY-012", "LY-013", "LY-014"]
        },
        {
          id: "memory",
          label: "Memory + Pairing + Edits",
          zone: "mem",
          guardCheckIds: ["LY-006", "LY-015", "LY-018"]
        }
      ],
      edges: [
        { from: "inbound", to: "channels", kind: "data" },
        { from: "channels", to: "shield", kind: "control" },
        { from: "shield", to: "engine", kind: "data" },
        { from: "engine", to: "memory", kind: "data" },
        {
          from: "inbound",
          to: "engine",
          label: "shield bypass",
          triggerCheckIds: ["LY-001", "LY-002"]
        },
        {
          from: "inbound",
          to: "memory",
          label: "DM pairing bypass",
          triggerCheckIds: ["LY-003"]
        }
      ]
    };
  }
};
async function findCLIBinary7(home, fs) {
  for (const p of SYSTEM_CLI_PATHS5) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS5) {
    const p = join11(home, rel);
    if (await fs.access(p)) return p;
  }
  try {
    const result = fs.execSync("which", ["lyrie"], { timeout: 3e3 }).trim();
    if (result) return result;
  } catch {
  }
  return void 0;
}

// src/adapters/claude-code.ts
init_local_fs_provider();
init_config_loader();
import { join as join13, basename as basename3 } from "path";

// src/adapters/nvm-binary.ts
import { join as join12 } from "path";
async function findNvmBinary(home, fs, binaryName) {
  const nvmRoot = join12(home, ".nvm", "versions", "node");
  let entries;
  try {
    entries = await fs.readdirEntries(nvmRoot);
  } catch {
    return void 0;
  }
  const versions = entries.filter((e) => e.isDirectory).map((e) => e.name).sort().reverse();
  for (const v of versions) {
    const p = join12(nvmRoot, v, "bin", binaryName);
    if (await fs.access(p)) return p;
  }
  return void 0;
}
function nvmBinaryGlob(binaryName) {
  return `~/.nvm/versions/node/*/bin/${binaryName}`;
}
function npmPackageJsonGlobs(packageName) {
  return [
    `~/.nvm/versions/node/*/lib/node_modules/${packageName}/package.json`,
    `~/.npm-global/lib/node_modules/${packageName}/package.json`,
    `~/.volta/tools/image/packages/${packageName}/package.json`,
    `/usr/local/lib/node_modules/${packageName}/package.json`,
    `/usr/lib/node_modules/${packageName}/package.json`,
    `/opt/homebrew/lib/node_modules/${packageName}/package.json`
  ];
}

// src/adapters/claude-code.ts
var CLAUDE_DIR_NAME = ".claude";
var SETTINGS_FILES = ["settings.json", "settings.local.json"];
var ROOT_STATE_FILE = ".claude.json";
var NPM_PACKAGE_NAME = "@anthropic-ai/claude-code";
var SYSTEM_CLI_PATHS6 = [
  "/usr/local/bin/claude",
  "/opt/homebrew/bin/claude",
  "/usr/bin/claude"
];
var USER_CLI_RELATIVE_PATHS6 = [
  ".local/bin/claude",
  ".npm-global/bin/claude",
  ".volta/bin/claude",
  ".claude/local/claude",
  ".bun/bin/claude"
];
async function findCLIBinary8(home, fs) {
  for (const p of SYSTEM_CLI_PATHS6) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS6) {
    const p = join13(home, rel);
    if (await fs.access(p)) return p;
  }
  const nvm = await findNvmBinary(home, fs, "claude");
  if (nvm) return nvm;
  try {
    const result = fs.execSync("which", ["claude"], { timeout: 3e3 }).trim();
    if (result) return result;
  } catch {
  }
  return void 0;
}
async function loadSettingsFiles(dir, fs) {
  const configFiles = [];
  for (const filename of SETTINGS_FILES) {
    const filePath = join13(dir, filename);
    if (!await fs.access(filePath)) continue;
    try {
      configFiles.push(await loadConfig(filePath, fs));
    } catch {
    }
  }
  return configFiles;
}
function inferPlanDefaultModel(rootState) {
  if (!rootState) return void 0;
  const flag = (k) => rootState[k] === true;
  const opusVersion = flag("opus47MigrationComplete") ? "4.7" : flag("opus45MigrationComplete") || flag("opusProMigrationComplete") ? "4.5" : void 0;
  const sonnetVersion = flag("sonnet1m45MigrationComplete") || flag("sonnet45MigrationComplete") ? "4.5" : void 0;
  const onOpusPlan = flag("hasOpusPlanDefault") || flag("opusProMigrationComplete");
  if (onOpusPlan && opusVersion) {
    return { id: `claude-opus-${opusVersion}`, provider: "anthropic", via: "plan default" };
  }
  if (sonnetVersion) {
    return { id: `claude-sonnet-${sonnetVersion}`, provider: "anthropic", via: "plan default" };
  }
  if (opusVersion) {
    return { id: `claude-opus-${opusVersion}`, provider: "anthropic", via: "plan default" };
  }
  return void 0;
}
var claudeCodeAdapter = {
  agent: "claude-code",
  displayName: "Claude Code",
  async detect(options) {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations = [];
    for (const { home, user } of userDirs) {
      const claudeDir = join13(home, CLAUDE_DIR_NAME);
      const rootStateFile = join13(home, ROOT_STATE_FILE);
      const cliBinary = await findCLIBinary8(home, fs);
      const hasClaudeDir = await fs.access(claudeDir);
      const hasRootState = await fs.access(rootStateFile);
      if (!hasClaudeDir && !hasRootState && !cliBinary) continue;
      const configFiles = hasClaudeDir ? await loadSettingsFiles(claudeDir, fs) : [];
      if (hasRootState) {
        try {
          configFiles.push(await loadConfig(rootStateFile, fs));
        } catch {
        }
      }
      if (configFiles.length === 0 && !cliBinary) continue;
      const version = queryCliVersion(cliBinary, fs) ?? await readPackageVersion(cliBinary, fs, NPM_PACKAGE_NAME);
      const skillsDir = this.getSkillsDir(claudeDir);
      installations.push({
        agent: "claude-code",
        version,
        installDir: claudeDir,
        configFiles,
        skillsDir,
        models: await this.getModels?.(configFiles, fs),
        user: options?.allUsers ? user : void 0,
        cliBinary
      });
    }
    const cwd = process.cwd();
    const projectClaudeDir = join13(cwd, CLAUDE_DIR_NAME);
    if (await fs.access(projectClaudeDir)) {
      const projectConfigs = await loadSettingsFiles(projectClaudeDir, fs);
      if (projectConfigs.length > 0) {
        installations.push({
          agent: "claude-code",
          agentName: `project:${basename3(cwd)}`,
          installDir: projectClaudeDir,
          configFiles: projectConfigs,
          skillsDir: this.getSkillsDir(projectClaudeDir),
          models: await this.getModels?.(projectConfigs, fs),
          profile: "project"
        });
      }
    }
    return installations;
  },
  getConfigPaths() {
    const home = new LocalFSProvider().homedir();
    const claudeDir = join13(home, CLAUDE_DIR_NAME);
    return [
      ...SETTINGS_FILES.map((f) => join13(claudeDir, f)),
      join13(home, ROOT_STATE_FILE)
    ];
  },
  getSkillsDir(installDir) {
    return join13(installDir, "skills");
  },
  getGatewayInfo(_config) {
    return void 0;
  },
  getModels(configs, fs) {
    const out = [];
    for (const file of configs) {
      if (!file.filePath.endsWith("settings.json") && !file.filePath.endsWith("settings.local.json")) continue;
      const id = file.data?.model;
      if (id) out.push({ id, provider: "anthropic" });
      const fallback = file.data?.fallbackModel;
      if (fallback && fallback !== id) out.push({ id: fallback, provider: "anthropic", via: "fallback" });
    }
    if (out.length > 0) return out;
    const rootState = configs.find((c) => c.filePath.endsWith(ROOT_STATE_FILE));
    const rootModel = rootState?.data?.model;
    if (rootModel) return [{ id: rootModel, provider: "anthropic" }];
    const envModel = fs?.getEnv?.("ANTHROPIC_MODEL");
    if (envModel) return [{ id: envModel, provider: "anthropic", via: "ANTHROPIC_MODEL" }];
    const inferred = inferPlanDefaultModel(rootState?.data);
    return inferred ? [inferred] : [];
  },
  getMemoryFiles(installDir) {
    return [
      join13(installDir, "CLAUDE.md"),
      join13(installDir, "projects")
    ];
  },
  getCredentialPaths(installDir) {
    return [
      join13(installDir, ".credentials.json"),
      join13(installDir, "settings.json"),
      join13(installDir, "settings.local.json")
    ];
  },
  getCLICommand() {
    return "claude";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.claude/settings.json",
        "~/.claude/settings.local.json",
        "~/.claude/CLAUDE.md",
        "~/.claude/.credentials.json",
        "~/.claude/mcp.json",
        "~/.claude.json",
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        // so findCLIBinary can resolve the binary in remote snapshots where the
        // non-interactive SSH PATH may not include the install dir.
        "~/.local/bin/claude",
        "~/.npm-global/bin/claude",
        "~/.volta/bin/claude",
        "~/.claude/local/claude",
        "~/.bun/bin/claude"
      ],
      globPatterns: [
        "~/.claude/skills/**",
        "~/.claude/plugins/**",
        "~/.claude/agents/**",
        nvmBinaryGlob("claude"),
        ...npmPackageJsonGlobs(NPM_PACKAGE_NAME)
      ],
      commands: [
        { id: "claude-which", cmd: "which", args: ["claude"], timeout: 3e3 },
        { id: "claude-version", cmd: "claude", args: ["--version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.claude",
        "~/.claude/skills",
        "~/.claude/plugins",
        "~/.claude/agents"
      ],
      envPrefixes: ["CLAUDE_", "ANTHROPIC_"],
      systemPaths: SYSTEM_CLI_PATHS6,
      systemDirListings: []
    };
  },
  getZoneGraph() {
    return {
      zones: [
        { id: "net", label: "Network", trustLevel: 0 },
        { id: "mcp", label: "MCP Transport", trustLevel: 1 },
        { id: "tool", label: "Tool Execution", trustLevel: 2 },
        { id: "host", label: "Host FS", trustLevel: 3 }
      ],
      components: [
        { id: "inbound", label: "Network / Remote MCP", zone: "net" },
        {
          id: "mcp-transport",
          label: "MCP Transport",
          zone: "mcp",
          guardCheckIds: ["CC-005", "CC-006"]
        },
        {
          id: "tools",
          label: "Tool Permissions",
          zone: "tool",
          guardCheckIds: ["CC-001", "CC-002", "CC-008"]
        },
        {
          id: "hooks",
          label: "Hooks (side-channel)",
          zone: "tool",
          guardCheckIds: ["CC-003", "CC-010", "CC-011"]
        },
        {
          id: "fs",
          label: "Host Filesystem",
          zone: "host",
          guardCheckIds: ["CC-004", "CC-007", "CC-009", "CC-012"]
        }
      ],
      edges: [
        { from: "inbound", to: "mcp-transport", kind: "data" },
        { from: "mcp-transport", to: "tools", kind: "control" },
        { from: "tools", to: "fs", kind: "data" },
        { from: "tools", to: "hooks", kind: "control" },
        { from: "hooks", to: "fs", kind: "control", label: "arbitrary cmd" },
        {
          from: "inbound",
          to: "fs",
          label: "permission bypass",
          triggerCheckIds: ["CC-001", "CC-002"]
        }
      ]
    };
  }
};

// src/adapters/claude-desktop.ts
init_local_fs_provider();
init_config_loader();
import { join as join14 } from "path";
var CONFIG_FILE = "claude_desktop_config.json";
var EXTENSIONS_DIR_NAME = "Claude Extensions";
var APP_BUNDLE_PATH2 = "/Applications/Claude.app";
var LOCAL_STORAGE_LEVELDB = ["Local Storage", "leveldb"];
var SELECTOR_KEY = "model-selector-local";
var MODEL_ID_RE = /claude-(?:opus|sonnet|haiku)-\d+(?:-\d+)?(?:\[\d+m\])?/;
function getDesktopConfigDir(home, fs) {
  if (fs.platform === "darwin") {
    return join14(home, "Library", "Application Support", "Claude");
  }
  if (fs.platform === "win32") {
    const appData = fs.getEnv?.("APPDATA");
    if (appData) return join14(appData, "Claude");
    return join14(home, "AppData", "Roaming", "Claude");
  }
  return void 0;
}
async function findAppBundle2(fs) {
  if (fs.platform === "darwin" && await fs.access(APP_BUNDLE_PATH2)) {
    return APP_BUNDLE_PATH2;
  }
  return void 0;
}
async function readAppVersion(fs) {
  if (fs.platform !== "darwin") return void 0;
  if (!await fs.access(APP_BUNDLE_PATH2)) return void 0;
  try {
    const result = await fs.exec(
      "defaults",
      ["read", `${APP_BUNDLE_PATH2}/Contents/Info.plist`, "CFBundleShortVersionString"],
      { timeout: 3e3 }
    );
    if (result.exitCode === 0) {
      const v = result.stdout.trim();
      if (v.length > 0) return v;
    }
  } catch {
  }
  return void 0;
}
async function readLocalStorageModel(installDir, fs) {
  const ldbDir = join14(installDir, ...LOCAL_STORAGE_LEVELDB);
  if (!await fs.access(ldbDir)) return void 0;
  let entries;
  try {
    entries = await fs.readdirEntries(ldbDir);
  } catch {
    return void 0;
  }
  const files = entries.filter((e) => e.isFile && (e.name.endsWith(".ldb") || e.name.endsWith(".log"))).map((e) => join14(ldbDir, e.name));
  for (const f of files) {
    try {
      const text = await fs.readFile(f);
      const keyIdx = text.indexOf(SELECTOR_KEY);
      if (keyIdx < 0) continue;
      const window = text.slice(keyIdx, keyIdx + 256);
      const match = MODEL_ID_RE.exec(window);
      if (match) return match[0];
    } catch {
    }
  }
  return void 0;
}
async function loadDesktopConfig(dir, fs) {
  const configFiles = [];
  const filePath = join14(dir, CONFIG_FILE);
  if (!await fs.access(filePath)) return configFiles;
  try {
    configFiles.push(await loadConfig(filePath, fs));
  } catch {
  }
  return configFiles;
}
var claudeDesktopAdapter = {
  agent: "claude-desktop",
  displayName: "Claude Desktop",
  async detect(options) {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations = [];
    const appBundle = await findAppBundle2(fs);
    const version = appBundle ? await readAppVersion(fs) : void 0;
    for (const { home, user } of userDirs) {
      const configDir = getDesktopConfigDir(home, fs);
      if (!configDir) continue;
      const hasConfigDir = await fs.access(configDir);
      if (!hasConfigDir && !appBundle) continue;
      const configFiles = hasConfigDir ? await loadDesktopConfig(configDir, fs) : [];
      let models = this.getModels?.(configFiles, fs);
      if (!models || models.length === 0) {
        const inferredId = hasConfigDir ? await readLocalStorageModel(configDir, fs) : void 0;
        if (inferredId) models = [{ id: inferredId, provider: "anthropic", via: "cowork local-storage" }];
      }
      installations.push({
        agent: "claude-desktop",
        version,
        installDir: configDir,
        configFiles,
        models,
        user: options?.allUsers ? user : void 0,
        appBundle
      });
    }
    return installations;
  },
  getConfigPaths() {
    const fs = new LocalFSProvider();
    const dir = getDesktopConfigDir(fs.homedir(), fs);
    return dir ? [join14(dir, CONFIG_FILE)] : [];
  },
  getSkillsDir(installDir) {
    return join14(installDir, EXTENSIONS_DIR_NAME);
  },
  getGatewayInfo(_config) {
    return void 0;
  },
  getModels(configs) {
    for (const file of configs) {
      const id = file.data?.model;
      if (id) return [{ id, provider: "anthropic" }];
    }
    return [];
  },
  getMemoryFiles() {
    return [];
  },
  getCredentialPaths(installDir) {
    return [join14(installDir, CONFIG_FILE)];
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/Library/Application Support/Claude/claude_desktop_config.json"
      ],
      globPatterns: [
        "~/Library/Application Support/Claude/Claude Extensions/**",
        // Chromium Local Storage SSTables — read for the active-model
        // sticky-selector value. Binary content gets U+FFFD-substituted in
        // the JSON snapshot, but the ASCII anchor key and the model id
        // survive intact, which is all readLocalStorageModel needs.
        "~/Library/Application Support/Claude/Local Storage/leveldb/*.ldb",
        "~/Library/Application Support/Claude/Local Storage/leveldb/*.log"
      ],
      commands: [
        { id: "claude-desktop-version", cmd: "defaults", args: ["read", `${APP_BUNDLE_PATH2}/Contents/Info.plist`, "CFBundleShortVersionString"], timeout: 3e3 }
      ],
      directoryListings: [
        "~/Library/Application Support/Claude",
        "~/Library/Application Support/Claude/Claude Extensions",
        "~/Library/Application Support/Claude/Local Storage/leveldb"
      ],
      envPrefixes: ["CLAUDE_", "ANTHROPIC_"],
      systemPaths: [APP_BUNDLE_PATH2],
      systemDirListings: []
    };
  },
  // Privilege gradient: untrusted network → MCP transport / extensions →
  // tool approval (alwaysApprove + per-tool prompts) → connected folders on
  // host. Inversion fires when always-approve is broad or unsigned MCPB
  // extensions are installed, letting prompt-injected tool calls reach the
  // host filesystem without confirmation.
  getZoneGraph() {
    return {
      zones: [
        { id: "net", label: "Network / Cloud", trustLevel: 0 },
        { id: "mcp", label: "MCP / Extensions", trustLevel: 1 },
        { id: "approval", label: "Approval Layer", trustLevel: 2 },
        { id: "host", label: "Connected Folders", trustLevel: 3 }
      ],
      components: [
        { id: "inbound", label: "Network / Remote MCP", zone: "net" },
        {
          id: "mcp-transport",
          label: "MCP Servers + .mcpb Extensions",
          zone: "mcp",
          guardCheckIds: ["CD-003", "CD-004", "CD-005"]
        },
        {
          id: "approval",
          label: "Tool Approval",
          zone: "approval",
          guardCheckIds: ["CD-006", "CD-009"]
        },
        {
          id: "fs",
          label: "Connected Folders",
          zone: "host",
          guardCheckIds: ["CD-001", "CD-002", "CD-007"]
        }
      ],
      edges: [
        { from: "inbound", to: "mcp-transport", kind: "data" },
        { from: "mcp-transport", to: "approval", kind: "control" },
        { from: "approval", to: "fs", kind: "data" },
        {
          from: "inbound",
          to: "fs",
          label: "approval bypass",
          triggerCheckIds: ["CD-005", "CD-006"]
        }
      ]
    };
  }
};

// src/adapters/chatgpt-desktop.ts
init_local_fs_provider();
import { join as join15 } from "path";
import * as plist from "plist";
var APP_BUNDLE_PATH3 = "/Applications/ChatGPT.app";
var BUNDLE_ID = "com.openai.chat";
var APP_SUPPORT_REL = ["Library", "Application Support", BUNDLE_ID];
var PREFS_REL = ["Library", "Preferences"];
var PLISTS = {
  main: "com.openai.chat.plist",
  helper: "ChatGPTHelper.plist",
  statsig: "com.openai.chat.StatsigService.plist",
  // Workspace-namespaced; real filename is com.openai.chat.RemoteFeatureFlags.<workspace>.plist.
  // Resolved at runtime by listing the Preferences dir.
  remoteFlagsPrefix: "com.openai.chat.RemoteFeatureFlags."
};
var PAIRING_DIR = "app_pairing_extensions";
async function loadPlistAsObject(filePath, fs) {
  if (!await fs.access(filePath)) return void 0;
  try {
    const result = await fs.exec(
      "plutil",
      ["-convert", "xml1", "-o", "-", filePath],
      { timeout: 3e3 }
    );
    if (result.exitCode !== 0 || !result.stdout) return void 0;
    const parsed = plist.parse(result.stdout);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return void 0;
    return normalizeForJson(parsed);
  } catch {
    return void 0;
  }
}
function normalizeForJson(value) {
  if (value instanceof Date) return { __date: value.toISOString() };
  if (Buffer.isBuffer(value)) return { __data: value.toString("base64") };
  if (Array.isArray(value)) {
    return value.map((v) => normalizeValue(v));
  }
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = normalizeValue(v);
    }
    return out;
  }
  return value;
}
function normalizeValue(value) {
  if (value instanceof Date) return value.toISOString();
  if (Buffer.isBuffer(value)) return value.toString("base64");
  if (Array.isArray(value)) return value.map(normalizeValue);
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = normalizeValue(v);
    }
    return out;
  }
  return value;
}
function asConfig(filePath, data) {
  return {
    raw: JSON.stringify(data),
    format: "json",
    filePath,
    data
  };
}
async function findRemoteFlagsPlist(prefsDir, fs) {
  try {
    const entries = await fs.readdirEntries(prefsDir);
    for (const e of entries) {
      if (!e.isFile) continue;
      if (e.name.startsWith(PLISTS.remoteFlagsPrefix) && e.name.endsWith(".plist")) {
        return join15(prefsDir, e.name);
      }
    }
  } catch {
  }
  return void 0;
}
async function readAppVersion2(fs) {
  if (!await fs.access(APP_BUNDLE_PATH3)) return void 0;
  try {
    const result = await fs.exec(
      "defaults",
      ["read", `${APP_BUNDLE_PATH3}/Contents/Info.plist`, "CFBundleShortVersionString"],
      { timeout: 3e3 }
    );
    if (result.exitCode === 0) {
      const v = result.stdout.trim();
      if (v.length > 0) return v;
    }
  } catch {
  }
  return void 0;
}
var chatgptDesktopAdapter = {
  agent: "chatgpt-desktop",
  displayName: "ChatGPT Desktop",
  async detect(options) {
    const fs = options?.fs ?? new LocalFSProvider();
    if (fs.platform !== "darwin") return [];
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations = [];
    const appExists = await fs.access(APP_BUNDLE_PATH3);
    const version = appExists ? await readAppVersion2(fs) : void 0;
    for (const { home, user } of userDirs) {
      const supportDir = join15(home, ...APP_SUPPORT_REL);
      const prefsDir = join15(home, ...PREFS_REL);
      const hasSupportDir = await fs.access(supportDir);
      if (!hasSupportDir && !appExists) continue;
      const configFiles = [];
      const mainPath = join15(prefsDir, PLISTS.main);
      const mainData = await loadPlistAsObject(mainPath, fs);
      if (mainData) configFiles.push(asConfig(mainPath, mainData));
      const statsigPath = join15(prefsDir, PLISTS.statsig);
      const statsigData = await loadPlistAsObject(statsigPath, fs);
      if (statsigData) configFiles.push(asConfig(statsigPath, statsigData));
      const remoteFlagsPath = await findRemoteFlagsPlist(prefsDir, fs);
      if (remoteFlagsPath) {
        const flags = await loadPlistAsObject(remoteFlagsPath, fs);
        if (flags) configFiles.push(asConfig(remoteFlagsPath, flags));
      }
      const helperPath = join15(prefsDir, PLISTS.helper);
      const helperData = await loadPlistAsObject(helperPath, fs);
      if (helperData) configFiles.push(asConfig(helperPath, helperData));
      installations.push({
        agent: "chatgpt-desktop",
        version,
        installDir: supportDir,
        configFiles,
        models: this.getModels?.(configFiles),
        user: options?.allUsers ? user : void 0,
        appBundle: appExists ? APP_BUNDLE_PATH3 : void 0
      });
    }
    return installations;
  },
  getConfigPaths() {
    const fs = new LocalFSProvider();
    if (fs.platform !== "darwin") return [];
    const home = fs.homedir();
    const prefsDir = join15(home, ...PREFS_REL);
    return [
      join15(prefsDir, PLISTS.main),
      join15(prefsDir, PLISTS.statsig),
      join15(prefsDir, PLISTS.helper)
    ];
  },
  getSkillsDir(installDir) {
    return join15(installDir, PAIRING_DIR);
  },
  getGatewayInfo(_config) {
    return void 0;
  },
  getModels(configs) {
    for (const file of configs) {
      if (!file.filePath.endsWith(PLISTS.main)) continue;
      for (const [k, v] of Object.entries(file.data)) {
        if (!k.startsWith("lastAccountSettingsResponse_")) continue;
        if (typeof v !== "string") continue;
        try {
          const parsed = JSON.parse(v);
          const settings = parsed.settings;
          const cfg = settings?.lastUsedModelConfig;
          const slugs = cfg?.slugs;
          const def = slugs?.default;
          if (typeof def === "string" && def.length > 0) {
            return [{ id: def, provider: "openai" }];
          }
        } catch {
        }
      }
    }
    return [];
  },
  getMemoryFiles() {
    return [];
  },
  getCredentialPaths(installDir) {
    return [installDir];
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/Library/Preferences/com.openai.chat.plist",
        "~/Library/Preferences/com.openai.chat.StatsigService.plist",
        "~/Library/Preferences/ChatGPTHelper.plist"
      ],
      globPatterns: [
        "~/Library/Preferences/com.openai.chat.RemoteFeatureFlags.*.plist",
        "~/Library/Application Support/com.openai.chat/app_pairing_extensions/**",
        "~/Library/Application Support/com.openai.chat/conversations-v3-*/**"
      ],
      commands: [
        { id: "chatgpt-version", cmd: "defaults", args: ["read", `${APP_BUNDLE_PATH3}/Contents/Info.plist`, "CFBundleShortVersionString"], timeout: 3e3 },
        { id: "chatgpt-codesign", cmd: "codesign", args: ["-dv", APP_BUNDLE_PATH3], timeout: 5e3 },
        // Per-user plists need `~` expansion done by the probe — see
        // expandArgsPerUser in collector.go. plutil converts binary plists
        // (the macOS default) to XML so the JS plist parser can read them
        // through the snapshot transport. The RemoteFeatureFlags plist's
        // filename is workspace-namespaced and only knowable after a dir
        // listing, so it's not capture-friendly via a static manifest and
        // remains local-FS-only for now.
        { id: "chatgpt-plist-main", cmd: "plutil", args: ["-convert", "xml1", "-o", "-", `~/Library/Preferences/${PLISTS.main}`], timeout: 3e3 },
        { id: "chatgpt-plist-statsig", cmd: "plutil", args: ["-convert", "xml1", "-o", "-", `~/Library/Preferences/${PLISTS.statsig}`], timeout: 3e3 },
        { id: "chatgpt-plist-helper", cmd: "plutil", args: ["-convert", "xml1", "-o", "-", `~/Library/Preferences/${PLISTS.helper}`], timeout: 3e3 }
      ],
      directoryListings: [
        "~/Library/Application Support/com.openai.chat",
        "~/Library/Application Support/com.openai.chat/app_pairing_extensions",
        "~/Library/Preferences"
      ],
      envPrefixes: ["OPENAI_"],
      systemPaths: [APP_BUNDLE_PATH3],
      systemDirListings: []
    };
  },
  // Privilege gradient: untrusted network → on-disk artifacts (encrypted but
  // mode-permissive) → app capability surface (Apple Events, paired connectors)
  // → host filesystem reach. Inversion fires when the .app bundle codesign
  // doesn't match the expected Team ID — that's a swapped/impersonated app
  // running under the user's existing TCC grants.
  getZoneGraph() {
    return {
      zones: [
        { id: "net", label: "Network / Cloud", trustLevel: 0 },
        { id: "disk", label: "On-disk Artifacts", trustLevel: 1 },
        { id: "cap", label: "App Capabilities", trustLevel: 2 },
        { id: "host", label: "Host Reach", trustLevel: 3 }
      ],
      components: [
        { id: "inbound", label: "Network / Sentry", zone: "net" },
        {
          id: "artifacts",
          label: "Conversations + Drafts",
          zone: "disk",
          guardCheckIds: ["CG-001", "CG-002"]
        },
        {
          id: "capabilities",
          label: "Privacy + Connector Caps",
          zone: "cap",
          guardCheckIds: ["CG-003", "CG-004", "CG-006"]
        },
        {
          id: "host",
          label: "Apple Events / Apps",
          zone: "host",
          guardCheckIds: ["CG-005"]
        }
      ],
      edges: [
        { from: "inbound", to: "artifacts", kind: "data" },
        { from: "artifacts", to: "capabilities", kind: "control" },
        { from: "capabilities", to: "host", kind: "data" },
        {
          from: "inbound",
          to: "host",
          label: "app impersonation",
          triggerCheckIds: ["CG-005"]
        }
      ]
    };
  }
};

// src/adapters/codex.ts
init_local_fs_provider();
init_config_loader();
import { join as join16 } from "path";
var CODEX_DIR_NAME = ".codex";
var CONFIG_FILES = ["config.toml", "auth.json"];
var NPM_PACKAGE_NAME2 = "@openai/codex";
var SYSTEM_CLI_PATHS7 = [
  "/usr/local/bin/codex",
  "/opt/homebrew/bin/codex",
  "/usr/bin/codex"
];
var USER_CLI_RELATIVE_PATHS7 = [
  ".local/bin/codex",
  ".npm-global/bin/codex",
  ".volta/bin/codex",
  ".bun/bin/codex",
  ".cargo/bin/codex"
];
async function findLatestSessionModel(fs, sessionsDir) {
  let dir = sessionsDir;
  for (let depth = 0; depth < 3; depth++) {
    let entries2;
    try {
      entries2 = await fs.readdirEntries(dir);
    } catch {
      return void 0;
    }
    const subdirs = entries2.filter((e) => e.isDirectory).map((e) => e.name).filter((n) => /^\d+$/.test(n)).sort();
    if (subdirs.length === 0) return void 0;
    dir = `${dir}/${subdirs[subdirs.length - 1]}`;
  }
  let entries;
  try {
    entries = await fs.readdirEntries(dir);
  } catch {
    return void 0;
  }
  const rollouts = entries.filter((e) => e.isFile && e.name.startsWith("rollout-") && e.name.endsWith(".jsonl")).map((e) => e.name).sort();
  if (rollouts.length === 0) return void 0;
  const latestPath = `${dir}/${rollouts[rollouts.length - 1]}`;
  let content;
  try {
    content = await fs.readFile(latestPath);
  } catch {
    return void 0;
  }
  const re = /"model":"([^"]+)"/g;
  let last;
  let m;
  while ((m = re.exec(content)) !== null) last = m[1];
  return last;
}
async function findCLIBinary9(home, fs) {
  for (const p of SYSTEM_CLI_PATHS7) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS7) {
    const p = join16(home, rel);
    if (await fs.access(p)) return p;
  }
  const nvm = await findNvmBinary(home, fs, "codex");
  if (nvm) return nvm;
  try {
    const result = fs.execSync("which", ["codex"], { timeout: 3e3 }).trim();
    if (result) return result;
  } catch {
  }
  return void 0;
}
var codexAdapter = {
  agent: "codex",
  displayName: "Codex",
  async detect(options) {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations = [];
    for (const { home, user } of userDirs) {
      const codexDir = join16(home, CODEX_DIR_NAME);
      const cliBinary = await findCLIBinary9(home, fs);
      const hasCodexDir = await fs.access(codexDir);
      if (!hasCodexDir && !cliBinary) continue;
      const configFiles = [];
      if (hasCodexDir) {
        for (const filename of CONFIG_FILES) {
          const filePath = join16(codexDir, filename);
          if (!await fs.access(filePath)) continue;
          try {
            configFiles.push(await loadConfig(filePath, fs));
          } catch {
          }
        }
      }
      if (configFiles.length === 0 && !cliBinary) continue;
      const version = queryCliVersion(cliBinary, fs) ?? await readPackageVersion(cliBinary, fs, NPM_PACKAGE_NAME2);
      installations.push({
        agent: "codex",
        version,
        installDir: codexDir,
        configFiles,
        models: await this.getModels?.(configFiles, fs),
        user: options?.allUsers ? user : void 0,
        cliBinary
      });
    }
    return installations;
  },
  getConfigPaths() {
    const home = new LocalFSProvider().homedir();
    const codexDir = join16(home, CODEX_DIR_NAME);
    return CONFIG_FILES.map((f) => join16(codexDir, f));
  },
  getSkillsDir(_installDir) {
    return void 0;
  },
  getGatewayInfo(_config) {
    return void 0;
  },
  async getModels(configs, fs) {
    const main = configs.find((c) => c.filePath.endsWith("config.toml"));
    const id = main?.data?.model;
    if (id) {
      const provider = main?.data?.model_provider;
      return [{ id, provider }];
    }
    if (!fs) return [];
    const home = fs.homedir();
    const sessionsDir = `${home}/.codex/sessions`;
    const found = await findLatestSessionModel(fs, sessionsDir);
    return found ? [{ id: found, via: "last session" }] : [];
  },
  getMemoryFiles(installDir) {
    return [
      join16(installDir, "instructions.md"),
      join16(installDir, "AGENTS.md"),
      join16(installDir, "history.jsonl")
    ];
  },
  getCredentialPaths(installDir) {
    return [
      join16(installDir, "auth.json")
    ];
  },
  getCLICommand() {
    return "codex";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.codex/config.toml",
        "~/.codex/auth.json",
        "~/.codex/instructions.md",
        "~/.codex/AGENTS.md",
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        "~/.local/bin/codex",
        "~/.npm-global/bin/codex",
        "~/.volta/bin/codex",
        "~/.bun/bin/codex",
        "~/.cargo/bin/codex"
      ],
      globPatterns: [
        // Session jsonls record `turn_context.model` per turn, so the latest
        // session reveals the active model when ~/.codex/config.toml has none.
        "~/.codex/sessions/*/*/*/rollout-*.jsonl",
        nvmBinaryGlob("codex"),
        ...npmPackageJsonGlobs(NPM_PACKAGE_NAME2)
      ],
      commands: [
        { id: "codex-which", cmd: "which", args: ["codex"], timeout: 3e3 },
        { id: "codex-version", cmd: "codex", args: ["--version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.codex",
        "~/.codex/sessions"
      ],
      envPrefixes: ["CODEX_", "OPENAI_"],
      systemPaths: SYSTEM_CLI_PATHS7,
      systemDirListings: []
    };
  },
  getZoneGraph() {
    return {
      zones: [
        { id: "net", label: "Network", trustLevel: 0 },
        { id: "mcp", label: "MCP Transport", trustLevel: 1 },
        { id: "sbx", label: "Sandbox Mode", trustLevel: 2 },
        { id: "host", label: "Host FS", trustLevel: 3 }
      ],
      components: [
        { id: "inbound", label: "Network / Remote MCP", zone: "net" },
        {
          id: "mcp-transport",
          label: "MCP Transport",
          zone: "mcp",
          guardCheckIds: ["CDX-004"]
        },
        {
          id: "sandbox",
          label: "Sandbox Mode (read/workspace/danger)",
          zone: "sbx",
          guardCheckIds: ["CDX-001", "CDX-002", "CDX-005", "CDX-006", "CDX-008"]
        },
        {
          id: "fs",
          label: "Host Filesystem",
          zone: "host",
          guardCheckIds: ["CDX-003", "CDX-007", "CDX-009"]
        }
      ],
      edges: [
        { from: "inbound", to: "mcp-transport", kind: "data" },
        { from: "mcp-transport", to: "sandbox", kind: "control" },
        { from: "sandbox", to: "fs", kind: "data" },
        {
          from: "inbound",
          to: "fs",
          label: "sandbox bypass",
          triggerCheckIds: ["CDX-001", "CDX-002"]
        }
      ]
    };
  }
};

// src/adapters/opencode.ts
init_local_fs_provider();
import { join as join17 } from "path";

// src/core/jsonc.ts
function stripJsonc(raw) {
  let out = "";
  let i = 0;
  let inString = false;
  let stringQuote;
  while (i < raw.length) {
    const c = raw[i];
    const next = raw[i + 1];
    if (inString) {
      out += c;
      if (c === "\\" && i + 1 < raw.length) {
        out += raw[i + 1];
        i += 2;
        continue;
      }
      if (c === stringQuote) {
        inString = false;
        stringQuote = void 0;
      }
      i++;
      continue;
    }
    if (c === '"' || c === "'") {
      inString = true;
      stringQuote = c;
      out += c;
      i++;
      continue;
    }
    if (c === "/" && next === "/") {
      while (i < raw.length && raw[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && next === "*") {
      i += 2;
      while (i < raw.length && !(raw[i] === "*" && raw[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    out += c;
    i++;
  }
  return out.replace(/,(\s*[\]}])/g, "$1");
}

// src/adapters/opencode.ts
var SYSTEM_CLI_PATHS8 = [
  "/usr/local/bin/opencode",
  "/opt/homebrew/bin/opencode",
  "/usr/bin/opencode"
];
var USER_CLI_RELATIVE_PATHS8 = [
  ".opencode/bin/opencode",
  ".local/bin/opencode",
  ".bun/bin/opencode",
  ".npm-global/bin/opencode"
];
function xdgConfigDir(home, fs) {
  return fs.getEnv("XDG_CONFIG_HOME")?.trim() ? join17(fs.getEnv("XDG_CONFIG_HOME"), "opencode") : join17(home, ".config", "opencode");
}
function xdgDataDir(home, fs) {
  return fs.getEnv("XDG_DATA_HOME")?.trim() ? join17(fs.getEnv("XDG_DATA_HOME"), "opencode") : join17(home, ".local", "share", "opencode");
}
var CONFIG_FILENAMES5 = ["opencode.jsonc", "opencode.json"];
async function loadOpenCodeConfig(filePath, fs) {
  try {
    const raw = await fs.readFile(filePath);
    const data = JSON.parse(stripJsonc(raw));
    return { raw, format: "json", filePath, data };
  } catch {
    return void 0;
  }
}
async function findCLIBinary10(home, fs) {
  for (const p of SYSTEM_CLI_PATHS8) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS8) {
    const p = join17(home, rel);
    if (await fs.access(p)) return p;
  }
  const nvm = await findNvmBinary(home, fs, "opencode");
  if (nvm) return nvm;
  try {
    const result = fs.execSync("which", ["opencode"], { timeout: 3e3 }).trim();
    if (result) return result;
  } catch {
  }
  return void 0;
}
function splitProviderModel(spec) {
  const idx = spec.indexOf("/");
  if (idx === -1) return { id: spec };
  return { provider: spec.slice(0, idx), id: spec.slice(idx + 1) };
}
var opencodeAdapter = {
  agent: "opencode",
  displayName: "OpenCode",
  async detect(options) {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations = [];
    for (const { home, user } of userDirs) {
      const configDir = xdgConfigDir(home, fs);
      const dataDir = xdgDataDir(home, fs);
      const cliBinary = await findCLIBinary10(home, fs);
      const configFiles = [];
      for (const name of CONFIG_FILENAMES5) {
        const filePath = join17(configDir, name);
        if (!await fs.access(filePath)) continue;
        const parsed = await loadOpenCodeConfig(filePath, fs);
        if (parsed) configFiles.push(parsed);
      }
      const authPath = join17(dataDir, "auth.json");
      const hasAuth2 = await fs.access(authPath);
      if (configFiles.length === 0 && !hasAuth2 && !cliBinary) continue;
      const version = queryCliVersion(cliBinary, fs) ?? await readPackageVersion(cliBinary, fs);
      installations.push({
        agent: "opencode",
        version,
        installDir: configDir,
        configFiles,
        models: await this.getModels?.(configFiles),
        user: options?.allUsers ? user : void 0,
        cliBinary
      });
    }
    return installations;
  },
  getConfigPaths() {
    const fs = new LocalFSProvider();
    const home = fs.homedir();
    const configDir = xdgConfigDir(home, fs);
    return CONFIG_FILENAMES5.map((f) => join17(configDir, f));
  },
  getSkillsDir(_installDir) {
    return void 0;
  },
  getGatewayInfo(_config) {
    return void 0;
  },
  getModels(configs) {
    const refs = [];
    for (const c of configs) {
      const model = c.data.model;
      if (typeof model === "string" && model.length > 0) {
        refs.push(splitProviderModel(model));
      }
      const small = c.data.small_model;
      if (typeof small === "string" && small.length > 0) {
        refs.push({ ...splitProviderModel(small), via: "small_model" });
      }
    }
    return refs;
  },
  getMemoryFiles(installDir) {
    return [
      join17(installDir, "AGENTS.md"),
      join17(installDir, "CLAUDE.md")
    ];
  },
  getCredentialPaths(_installDir) {
    const fs = new LocalFSProvider();
    const home = fs.homedir();
    return [join17(xdgDataDir(home, fs), "auth.json")];
  },
  getCLICommand() {
    return "opencode";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.config/opencode/opencode.json",
        "~/.config/opencode/opencode.jsonc",
        "~/.config/opencode/AGENTS.md",
        "~/.config/opencode/CLAUDE.md",
        "~/.local/share/opencode/auth.json",
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        "~/.opencode/bin/opencode",
        "~/.local/bin/opencode",
        "~/.bun/bin/opencode",
        "~/.npm-global/bin/opencode"
      ],
      globPatterns: [
        "~/.config/opencode/agent/*.md",
        "~/.config/opencode/plugin/*.{ts,js}",
        "~/.config/opencode/plugins/*.{ts,js}",
        nvmBinaryGlob("opencode")
      ],
      commands: [
        { id: "opencode-which", cmd: "which", args: ["opencode"], timeout: 3e3 },
        { id: "opencode-version", cmd: "opencode", args: ["--version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.config/opencode",
        "~/.local/share/opencode",
        "~/.opencode/bin"
      ],
      envPrefixes: ["OPENCODE_", "XDG_"],
      systemPaths: SYSTEM_CLI_PATHS8,
      systemDirListings: []
    };
  },
  // OpenCode's privilege gradient runs through three gates: the permission
  // layer (ask/allow/deny on bash/edit/etc.), the MCP transport, and the plugin
  // loader. Failures in any of those let untrusted input reach the host FS.
  // Inversion edges fire when sharing is auto-enabled or when permissions are
  // globally allowed — both bypass the intended gate.
  getZoneGraph() {
    return {
      zones: [
        { id: "net", label: "Network / Cloud Sync", trustLevel: 0 },
        { id: "ext", label: "MCP + Plugins", trustLevel: 1 },
        { id: "perm", label: "Permission Layer", trustLevel: 2 },
        { id: "host", label: "Host Filesystem", trustLevel: 3 }
      ],
      components: [
        {
          id: "inbound",
          label: "Network / Cloud Sync",
          zone: "net",
          guardCheckIds: ["OPC-004", "OPC-009"]
        },
        {
          id: "mcp-plugins",
          label: "MCP Servers + Plugins",
          zone: "ext",
          guardCheckIds: ["OPC-003", "OPC-005", "OPC-010"]
        },
        {
          id: "permission",
          label: "Permission Layer",
          zone: "perm",
          guardCheckIds: ["OPC-002", "OPC-006", "OPC-008"]
        },
        {
          id: "fs",
          label: "Host Filesystem",
          zone: "host",
          guardCheckIds: ["OPC-001", "OPC-007"]
        }
      ],
      edges: [
        { from: "inbound", to: "mcp-plugins", kind: "data" },
        { from: "mcp-plugins", to: "permission", kind: "control" },
        { from: "permission", to: "fs", kind: "data" },
        {
          from: "inbound",
          to: "fs",
          label: "permission bypass",
          triggerCheckIds: ["OPC-002", "OPC-008"]
        }
      ]
    };
  }
};

// src/adapters/gemini.ts
init_local_fs_provider();
import { join as join18, basename as basename4 } from "path";
var GEMINI_DIR_NAME = ".gemini";
var SETTINGS_FILE = "settings.json";
var AUTH_FILES = ["oauth_creds.json", "google_accounts.json", "mcp-oauth-tokens.json", "a2a-oauth-tokens.json"];
var NPM_PACKAGE_NAME3 = "@google/gemini-cli";
var SYSTEM_CLI_PATHS9 = [
  "/usr/local/bin/gemini",
  "/opt/homebrew/bin/gemini",
  "/usr/bin/gemini"
];
var USER_CLI_RELATIVE_PATHS9 = [
  ".local/bin/gemini",
  ".npm-global/bin/gemini",
  ".volta/bin/gemini",
  ".bun/bin/gemini"
];
async function findCLIBinary11(home, fs) {
  for (const p of SYSTEM_CLI_PATHS9) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS9) {
    const p = join18(home, rel);
    if (await fs.access(p)) return p;
  }
  const nvm = await findNvmBinary(home, fs, "gemini");
  if (nvm) return nvm;
  try {
    const result = fs.execSync("which", ["gemini"], { timeout: 3e3 }).trim();
    if (result) return result;
  } catch {
  }
  return void 0;
}
async function loadJsoncConfig(filePath, fs) {
  try {
    const raw = await fs.readFile(filePath);
    const data = JSON.parse(stripJsonc(raw));
    return { raw, format: "json", filePath, data };
  } catch {
    return void 0;
  }
}
async function loadSettings(dir, fs) {
  const out = [];
  const filePath = join18(dir, SETTINGS_FILE);
  if (!await fs.access(filePath)) return out;
  const parsed = await loadJsoncConfig(filePath, fs);
  if (parsed) out.push(parsed);
  return out;
}
async function findLatestSessionModel2(fs, tmpDir) {
  let projects;
  try {
    projects = await fs.readdirEntries(tmpDir);
  } catch {
    return void 0;
  }
  let latestPath;
  let latestName = "";
  for (const proj of projects) {
    if (!proj.isDirectory) continue;
    const chatsDir = `${tmpDir}/${proj.name}/chats`;
    let entries;
    try {
      entries = await fs.readdirEntries(chatsDir);
    } catch {
      continue;
    }
    for (const e of entries) {
      if (!e.isFile) continue;
      if (!e.name.startsWith("session-") || !e.name.endsWith(".jsonl")) continue;
      if (e.name > latestName) {
        latestName = e.name;
        latestPath = `${chatsDir}/${e.name}`;
      }
    }
  }
  if (!latestPath) return void 0;
  let content;
  try {
    content = await fs.readFile(latestPath);
  } catch {
    return void 0;
  }
  const re = /"model":"([^"]+)"/g;
  let last;
  let m;
  while ((m = re.exec(content)) !== null) last = m[1];
  return last;
}
async function extractModels(configs, fs) {
  const envModel = fs?.getEnv?.("GEMINI_MODEL");
  if (envModel) return [{ id: envModel, provider: "google", via: "GEMINI_MODEL" }];
  for (const c of configs) {
    const model = c.data.model;
    if (typeof model === "string" && model.length > 0) {
      return [{ id: model, provider: "google" }];
    }
    if (model && typeof model === "object") {
      const name = model.name;
      if (typeof name === "string" && name.length > 0) {
        return [{ id: name, provider: "google" }];
      }
    }
  }
  if (fs) {
    const home = fs.homedir();
    const tmpDir = `${home}/.gemini/tmp`;
    const found = await findLatestSessionModel2(fs, tmpDir);
    if (found) return [{ id: found, provider: "google", via: "last session" }];
  }
  return [];
}
var geminiAdapter = {
  agent: "gemini-cli",
  displayName: "Gemini CLI",
  async detect(options) {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations = [];
    for (const { home, user } of userDirs) {
      const geminiDir = join18(home, GEMINI_DIR_NAME);
      const cliBinary = await findCLIBinary11(home, fs);
      const hasGeminiDir = await fs.access(geminiDir);
      if (!hasGeminiDir && !cliBinary) continue;
      const configFiles = hasGeminiDir ? await loadSettings(geminiDir, fs) : [];
      if (configFiles.length === 0 && !cliBinary) continue;
      const version = queryCliVersion(cliBinary, fs) ?? await readPackageVersion(cliBinary, fs, NPM_PACKAGE_NAME3);
      installations.push({
        agent: "gemini-cli",
        version,
        installDir: geminiDir,
        configFiles,
        models: await extractModels(configFiles, fs),
        user: options?.allUsers ? user : void 0,
        cliBinary
      });
    }
    const cwd = process.cwd();
    const projectGeminiDir = join18(cwd, GEMINI_DIR_NAME);
    if (await fs.access(projectGeminiDir)) {
      const projectConfigs = await loadSettings(projectGeminiDir, fs);
      if (projectConfigs.length > 0) {
        installations.push({
          agent: "gemini-cli",
          agentName: `project:${basename4(cwd)}`,
          installDir: projectGeminiDir,
          configFiles: projectConfigs,
          models: await extractModels(projectConfigs, fs),
          profile: "project"
        });
      }
    }
    return installations;
  },
  getConfigPaths() {
    const home = new LocalFSProvider().homedir();
    const geminiDir = join18(home, GEMINI_DIR_NAME);
    return [join18(geminiDir, SETTINGS_FILE)];
  },
  getSkillsDir(installDir) {
    void installDir;
    return void 0;
  },
  getGatewayInfo(_config) {
    return void 0;
  },
  async getModels(configs, fs) {
    return extractModels(configs, fs);
  },
  getMemoryFiles(installDir) {
    return [
      join18(installDir, "memory.md"),
      join18(installDir, "GEMINI.md")
    ];
  },
  getCredentialPaths(installDir) {
    return AUTH_FILES.map((f) => join18(installDir, f));
  },
  getCLICommand() {
    return "gemini";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.gemini/settings.json",
        "~/.gemini/memory.md",
        "~/.gemini/GEMINI.md",
        "~/.gemini/oauth_creds.json",
        "~/.gemini/google_accounts.json",
        "~/.gemini/mcp-oauth-tokens.json",
        "~/.gemini/a2a-oauth-tokens.json",
        "~/.gemini/installation_id",
        "~/.gemini/trustedFolders.json",
        "~/.gemini/policy_integrity.json",
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        "~/.local/bin/gemini",
        "~/.npm-global/bin/gemini",
        "~/.volta/bin/gemini",
        "~/.bun/bin/gemini"
      ],
      globPatterns: [
        "~/.gemini/agents/*.md",
        "~/.gemini/commands/*",
        "~/.gemini/policies/*",
        "~/.gemini/extensions/**",
        // Session transcripts hold per-message `model` field — the empirical
        // active model when settings.json has no `model.name`.
        "~/.gemini/tmp/*/chats/session-*.jsonl",
        nvmBinaryGlob("gemini"),
        ...npmPackageJsonGlobs(NPM_PACKAGE_NAME3)
      ],
      commands: [
        { id: "gemini-which", cmd: "which", args: ["gemini"], timeout: 3e3 },
        { id: "gemini-version", cmd: "gemini", args: ["--version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.gemini",
        "~/.gemini/agents",
        "~/.gemini/commands",
        "~/.gemini/extensions",
        "~/.gemini/policies",
        "~/.gemini/tmp"
      ],
      envPrefixes: ["GEMINI_", "GOOGLE_"],
      systemPaths: SYSTEM_CLI_PATHS9,
      systemDirListings: []
    };
  },
  // Gemini's privilege gradient: untrusted network → MCP transport → tool
  // approval layer (defaultApprovalMode + tools.allowed) → host filesystem.
  // Inversion fires when YOLO is unguarded or `tools.allowed` is overbroad,
  // letting prompt-injected tool calls reach the host without confirmation.
  getZoneGraph() {
    return {
      zones: [
        { id: "net", label: "Network / Cloud", trustLevel: 0 },
        { id: "mcp", label: "MCP Transport", trustLevel: 1 },
        { id: "approval", label: "Approval Layer", trustLevel: 2 },
        { id: "host", label: "Host Filesystem", trustLevel: 3 }
      ],
      components: [
        { id: "inbound", label: "Network / Remote MCP", zone: "net" },
        {
          id: "mcp-transport",
          label: "MCP Transport",
          zone: "mcp",
          guardCheckIds: ["GEM-007", "GEM-008"]
        },
        {
          id: "approval",
          label: "Approval / Sandbox",
          zone: "approval",
          guardCheckIds: ["GEM-003", "GEM-004", "GEM-005", "GEM-006", "GEM-009"]
        },
        {
          id: "fs",
          label: "Host Filesystem",
          zone: "host",
          guardCheckIds: ["GEM-001", "GEM-002", "GEM-010"]
        }
      ],
      edges: [
        { from: "inbound", to: "mcp-transport", kind: "data" },
        { from: "mcp-transport", to: "approval", kind: "control" },
        { from: "approval", to: "fs", kind: "data" },
        {
          from: "inbound",
          to: "fs",
          label: "approval bypass",
          triggerCheckIds: ["GEM-003", "GEM-004"]
        }
      ]
    };
  }
};

// src/adapters/qwen-code.ts
init_local_fs_provider();
import { join as join19, basename as basename5 } from "path";
var QWEN_DIR_NAME = ".qwen";
var SETTINGS_FILE2 = "settings.json";
var AUTH_FILES2 = ["oauth_creds.json", "mcp-oauth-tokens.json", "google_accounts.json"];
var NPM_PACKAGE_NAME4 = "@qwen-code/qwen-code";
var SYSTEM_CLI_PATHS10 = [
  "/usr/local/bin/qwen",
  "/opt/homebrew/bin/qwen",
  "/usr/bin/qwen"
];
var USER_CLI_RELATIVE_PATHS10 = [
  ".local/bin/qwen",
  ".npm-global/bin/qwen",
  ".volta/bin/qwen",
  ".bun/bin/qwen",
  ".qwen/bin/qwen"
];
async function findCLIBinary12(home, fs) {
  for (const p of SYSTEM_CLI_PATHS10) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS10) {
    const p = join19(home, rel);
    if (await fs.access(p)) return p;
  }
  const nvm = await findNvmBinary(home, fs, "qwen");
  if (nvm) return nvm;
  try {
    const result = fs.execSync("which", ["qwen"], { timeout: 3e3 }).trim();
    if (result) return result;
  } catch {
  }
  return void 0;
}
async function loadJsoncConfig2(filePath, fs) {
  try {
    const raw = await fs.readFile(filePath);
    const data = JSON.parse(stripJsonc(raw));
    return { raw, format: "json", filePath, data };
  } catch {
    return void 0;
  }
}
async function loadSettings2(dir, fs) {
  const out = [];
  const filePath = join19(dir, SETTINGS_FILE2);
  if (!await fs.access(filePath)) return out;
  const parsed = await loadJsoncConfig2(filePath, fs);
  if (parsed) out.push(parsed);
  return out;
}
function extractModels2(configs) {
  for (const c of configs) {
    const security = c.data.security;
    const auth = security?.auth;
    const provider = auth?.selectedType?.toLowerCase();
    const model = c.data.model;
    let id;
    if (typeof model === "string") id = model;
    else if (model && typeof model.name === "string") {
      id = model.name;
    }
    if (id) return [{ id, provider }];
    const providers = c.data.modelProviders;
    if (Array.isArray(providers)) {
      const match = providers.find((p) => typeof p.id === "string" && (!provider || p.id.toLowerCase().includes(provider)));
      const fallback = match ?? providers[0];
      if (fallback && typeof fallback.id === "string") {
        return [{ id: fallback.id, provider }];
      }
    }
  }
  return [];
}
var qwenCodeAdapter = {
  agent: "qwen-code",
  displayName: "Qwen Code",
  async detect(options) {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations = [];
    for (const { home, user } of userDirs) {
      const qwenDir = join19(home, QWEN_DIR_NAME);
      const cliBinary = await findCLIBinary12(home, fs);
      const hasQwenDir = await fs.access(qwenDir);
      if (!hasQwenDir && !cliBinary) continue;
      const configFiles = hasQwenDir ? await loadSettings2(qwenDir, fs) : [];
      if (configFiles.length === 0 && !cliBinary) continue;
      const version = queryCliVersion(cliBinary, fs) ?? await readPackageVersion(cliBinary, fs, NPM_PACKAGE_NAME4);
      installations.push({
        agent: "qwen-code",
        version,
        installDir: qwenDir,
        configFiles,
        models: extractModels2(configFiles),
        user: options?.allUsers ? user : void 0,
        cliBinary
      });
    }
    const cwd = process.cwd();
    const projectQwenDir = join19(cwd, QWEN_DIR_NAME);
    if (await fs.access(projectQwenDir)) {
      const projectConfigs = await loadSettings2(projectQwenDir, fs);
      if (projectConfigs.length > 0) {
        installations.push({
          agent: "qwen-code",
          agentName: `project:${basename5(cwd)}`,
          installDir: projectQwenDir,
          configFiles: projectConfigs,
          models: extractModels2(projectConfigs),
          profile: "project"
        });
      }
    }
    return installations;
  },
  getConfigPaths() {
    const home = new LocalFSProvider().homedir();
    const qwenDir = join19(home, QWEN_DIR_NAME);
    return [join19(qwenDir, SETTINGS_FILE2)];
  },
  getSkillsDir(_installDir) {
    return void 0;
  },
  getGatewayInfo(_config) {
    return void 0;
  },
  getModels(configs) {
    return extractModels2(configs);
  },
  getMemoryFiles(installDir) {
    return [
      join19(installDir, "memory.md"),
      join19(installDir, "AGENTS.md")
    ];
  },
  getCredentialPaths(installDir) {
    return AUTH_FILES2.map((f) => join19(installDir, f));
  },
  getCLICommand() {
    return "qwen";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.qwen/settings.json",
        "~/.qwen/memory.md",
        "~/.qwen/AGENTS.md",
        "~/.qwen/oauth_creds.json",
        "~/.qwen/mcp-oauth-tokens.json",
        "~/.qwen/google_accounts.json",
        "~/.qwen/installation_id",
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        "~/.local/bin/qwen",
        "~/.npm-global/bin/qwen",
        "~/.volta/bin/qwen",
        "~/.bun/bin/qwen",
        "~/.qwen/bin/qwen"
      ],
      globPatterns: [
        "~/.qwen/commands/*",
        "~/.qwen/extensions/**",
        "~/.qwen/skills/**",
        "~/.qwen/rules/*",
        nvmBinaryGlob("qwen"),
        ...npmPackageJsonGlobs(NPM_PACKAGE_NAME4)
      ],
      commands: [
        { id: "qwen-which", cmd: "which", args: ["qwen"], timeout: 3e3 },
        { id: "qwen-version", cmd: "qwen", args: ["--version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.qwen",
        "~/.qwen/commands",
        "~/.qwen/extensions",
        "~/.qwen/skills"
      ],
      envPrefixes: ["QWEN_", "DASHSCOPE_", "BAILIAN_"],
      systemPaths: SYSTEM_CLI_PATHS10,
      systemDirListings: []
    };
  },
  // Qwen mirrors Gemini's gradient but adds an explicit MCP-trust gate
  // (mcpServers.<name>.trust = true bypasses approval). Inversion fires when
  // approvalMode=yolo, MCP-trust is set, or permissions.allow is broad with
  // empty deny — all let untrusted input reach the host without confirmation.
  getZoneGraph() {
    return {
      zones: [
        { id: "net", label: "Network / Cloud", trustLevel: 0 },
        { id: "mcp", label: "MCP Transport", trustLevel: 1 },
        { id: "approval", label: "Approval / Permissions", trustLevel: 2 },
        { id: "host", label: "Host Filesystem", trustLevel: 3 }
      ],
      components: [
        { id: "inbound", label: "Network / Remote MCP", zone: "net" },
        {
          id: "mcp-transport",
          label: "MCP Transport",
          zone: "mcp",
          guardCheckIds: ["QC-004", "QC-006", "QC-007"]
        },
        {
          id: "approval",
          label: "Approval / Permissions",
          zone: "approval",
          guardCheckIds: ["QC-003", "QC-005", "QC-008"]
        },
        {
          id: "fs",
          label: "Host Filesystem",
          zone: "host",
          guardCheckIds: ["QC-001", "QC-002", "QC-009", "QC-010"]
        }
      ],
      edges: [
        { from: "inbound", to: "mcp-transport", kind: "data" },
        { from: "mcp-transport", to: "approval", kind: "control" },
        { from: "approval", to: "fs", kind: "data" },
        {
          from: "inbound",
          to: "fs",
          label: "approval bypass",
          triggerCheckIds: ["QC-003", "QC-004"]
        }
      ]
    };
  }
};

// src/adapters/copilot-cli.ts
init_local_fs_provider();
init_config_loader();
import { join as join20, basename as basename6 } from "path";
var COPILOT_DIR_NAME = ".copilot";
var USER_CONFIG_FILES = ["config.json", "settings.json", "lsp-config.json"];
var PROJECT_CONFIG_FILES = [".mcp.json"];
var SYSTEM_CLI_PATHS11 = [
  "/usr/local/bin/copilot",
  "/opt/homebrew/bin/copilot",
  "/usr/bin/copilot"
];
var USER_CLI_RELATIVE_PATHS11 = [
  ".local/bin/copilot",
  ".npm-global/bin/copilot",
  ".volta/bin/copilot",
  ".bun/bin/copilot"
];
async function findCLIBinary13(home, fs) {
  for (const p of SYSTEM_CLI_PATHS11) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS11) {
    const p = join20(home, rel);
    if (await fs.access(p)) return p;
  }
  const nvm = await findNvmBinary(home, fs, "copilot");
  if (nvm) return nvm;
  try {
    const result = fs.execSync("which", ["copilot"], { timeout: 3e3 }).trim();
    if (result) return result;
  } catch {
  }
  return void 0;
}
async function loadFiles(dir, names, fs) {
  const out = [];
  for (const name of names) {
    const filePath = join20(dir, name);
    if (!await fs.access(filePath)) continue;
    if (name.endsWith(".json")) {
      try {
        const raw = await fs.readFile(filePath);
        const data = JSON.parse(stripJsonc(raw));
        out.push({ raw, format: "json", filePath, data });
        continue;
      } catch {
      }
    }
    try {
      out.push(await loadConfig(filePath, fs));
    } catch {
    }
  }
  return out;
}
function extractModels3(configs) {
  for (const c of configs) {
    if (!c.filePath.endsWith("settings.json") && !c.filePath.endsWith("config.json")) continue;
    const id = c.data.model;
    if (typeof id === "string" && id.length > 0) {
      return [{ id, provider: "github-copilot" }];
    }
  }
  return [];
}
var copilotCliAdapter = {
  agent: "copilot-cli",
  displayName: "GitHub Copilot CLI",
  async detect(options) {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations = [];
    for (const { home, user } of userDirs) {
      const copilotDir = join20(home, COPILOT_DIR_NAME);
      const cliBinary = await findCLIBinary13(home, fs);
      const hasCopilotDir = await fs.access(copilotDir);
      if (!hasCopilotDir && !cliBinary) continue;
      const configFiles = hasCopilotDir ? await loadFiles(copilotDir, USER_CONFIG_FILES, fs) : [];
      if (configFiles.length === 0 && !cliBinary) continue;
      const version = queryCliVersion(cliBinary, fs) ?? await readPackageVersion(cliBinary, fs);
      installations.push({
        agent: "copilot-cli",
        version,
        installDir: copilotDir,
        configFiles,
        models: extractModels3(configFiles),
        user: options?.allUsers ? user : void 0,
        cliBinary
      });
    }
    const cwd = process.cwd();
    const projectConfigs = [];
    for (const name of PROJECT_CONFIG_FILES) {
      const filePath = join20(cwd, name);
      if (!await fs.access(filePath)) continue;
      try {
        projectConfigs.push(await loadConfig(filePath, fs));
      } catch {
      }
    }
    const githubLspPath = join20(cwd, ".github", "lsp.json");
    if (await fs.access(githubLspPath)) {
      try {
        projectConfigs.push(await loadConfig(githubLspPath, fs));
      } catch {
      }
    }
    if (projectConfigs.length > 0) {
      installations.push({
        agent: "copilot-cli",
        agentName: `project:${basename6(cwd)}`,
        installDir: cwd,
        configFiles: projectConfigs,
        profile: "project"
      });
    }
    return installations;
  },
  getConfigPaths() {
    const home = new LocalFSProvider().homedir();
    const copilotDir = join20(home, COPILOT_DIR_NAME);
    return USER_CONFIG_FILES.map((f) => join20(copilotDir, f));
  },
  getSkillsDir(_installDir) {
    return void 0;
  },
  getGatewayInfo(_config) {
    return void 0;
  },
  getModels(configs) {
    return extractModels3(configs);
  },
  getMemoryFiles(installDir) {
    return [
      join20(installDir, "instructions"),
      join20(installDir, "command-history-state.json"),
      join20(installDir, "session-state")
    ];
  },
  getCredentialPaths(installDir) {
    return [
      join20(installDir, "config.json"),
      join20(installDir, "settings.json"),
      join20(installDir, "command-history-state.json"),
      join20(installDir, "session-state")
    ];
  },
  getCLICommand() {
    return "copilot";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.copilot/config.json",
        "~/.copilot/settings.json",
        "~/.copilot/lsp-config.json",
        "~/.copilot/command-history-state.json",
        "~/.config/gh/hosts.yml",
        // User-relative CLI install locations
        "~/.local/bin/copilot",
        "~/.npm-global/bin/copilot",
        "~/.volta/bin/copilot",
        "~/.bun/bin/copilot"
      ],
      globPatterns: [
        "~/.copilot/instructions/*.instructions.md",
        "~/.copilot/session-state/*.json",
        nvmBinaryGlob("copilot")
      ],
      commands: [
        { id: "copilot-which", cmd: "which", args: ["copilot"], timeout: 3e3 },
        { id: "copilot-version", cmd: "copilot", args: ["--version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.copilot",
        "~/.copilot/instructions",
        "~/.copilot/session-state",
        "~/.copilot/logs"
      ],
      envPrefixes: ["COPILOT_", "GH_", "GITHUB_"],
      systemPaths: SYSTEM_CLI_PATHS11,
      systemDirListings: []
    };
  },
  // Copilot CLI's gradient runs through MCP/LSP transports and the per-tool
  // approval layer (default: explicit approval; allowAllPermissions disables
  // it). Inversion fires when allowAllPermissions is set or LSP commands
  // contain shell metacharacters — both let untrusted input reach the host.
  getZoneGraph() {
    return {
      zones: [
        { id: "net", label: "Network / GitHub", trustLevel: 0 },
        { id: "mcp", label: "MCP + LSP", trustLevel: 1 },
        { id: "approval", label: "Approval Layer", trustLevel: 2 },
        { id: "host", label: "Host Filesystem", trustLevel: 3 }
      ],
      components: [
        { id: "inbound", label: "Network / GitHub", zone: "net" },
        {
          id: "mcp-lsp",
          label: "MCP + LSP Servers",
          zone: "mcp",
          guardCheckIds: ["GHC-004", "GHC-007"]
        },
        {
          id: "approval",
          label: "Approval Layer",
          zone: "approval",
          guardCheckIds: ["GHC-002", "GHC-005", "GHC-006"]
        },
        {
          id: "fs",
          label: "Host Filesystem",
          zone: "host",
          guardCheckIds: ["GHC-001", "GHC-003", "GHC-008"]
        }
      ],
      edges: [
        { from: "inbound", to: "mcp-lsp", kind: "data" },
        { from: "mcp-lsp", to: "approval", kind: "control" },
        { from: "approval", to: "fs", kind: "data" },
        {
          from: "inbound",
          to: "fs",
          label: "approval bypass",
          triggerCheckIds: ["GHC-002", "GHC-007"]
        }
      ]
    };
  }
};

// src/adapters/cursor-cli.ts
init_local_fs_provider();
init_config_loader();
import { join as join21, basename as basename7 } from "path";
var CURSOR_DIR_NAME = ".cursor";
var USER_CONFIG_FILES2 = ["cli-config.json", "mcp.json"];
var SYSTEM_CLI_PATHS12 = [
  "/usr/local/bin/cursor-agent",
  "/opt/homebrew/bin/cursor-agent",
  "/usr/bin/cursor-agent"
];
var USER_CLI_RELATIVE_PATHS12 = [
  ".local/bin/cursor-agent",
  ".npm-global/bin/cursor-agent",
  ".volta/bin/cursor-agent",
  ".bun/bin/cursor-agent",
  ".local/bin/agent",
  ".cursor/bin/agent"
];
async function findCLIBinary14(home, fs) {
  for (const p of SYSTEM_CLI_PATHS12) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS12) {
    const p = join21(home, rel);
    if (await fs.access(p)) return p;
  }
  const nvm = await findNvmBinary(home, fs, "cursor-agent");
  if (nvm) return nvm;
  try {
    const result = fs.execSync("which", ["cursor-agent"], { timeout: 3e3 }).trim();
    if (result) return result;
  } catch {
  }
  return void 0;
}
async function loadFiles2(dir, names, fs) {
  const out = [];
  for (const name of names) {
    const filePath = join21(dir, name);
    if (!await fs.access(filePath)) continue;
    try {
      out.push(await loadConfig(filePath, fs));
    } catch {
    }
  }
  return out;
}
function extractModels4(configs) {
  for (const c of configs) {
    const data = c.data;
    const selected = data.selectedModel;
    const selectedId = selected?.modelId;
    if (typeof selectedId === "string" && selectedId.length > 0) {
      return [{ id: selectedId, provider: "cursor" }];
    }
    const model = data.model;
    const modelId = model?.modelId;
    if (typeof modelId === "string" && modelId.length > 0) {
      return [{ id: modelId, provider: "cursor" }];
    }
  }
  return [];
}
var cursorCliAdapter = {
  agent: "cursor-cli",
  displayName: "Cursor CLI",
  async detect(options) {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations = [];
    for (const { home, user } of userDirs) {
      const cursorDir = join21(home, CURSOR_DIR_NAME);
      const cliBinary = await findCLIBinary14(home, fs);
      const hasCursorDir = await fs.access(cursorDir);
      if (!hasCursorDir && !cliBinary) continue;
      const configFiles = hasCursorDir ? await loadFiles2(cursorDir, USER_CONFIG_FILES2, fs) : [];
      if (configFiles.length === 0 && !cliBinary) continue;
      const version = queryCliVersion(cliBinary, fs) ?? await readPackageVersion(cliBinary, fs);
      installations.push({
        agent: "cursor-cli",
        version,
        installDir: cursorDir,
        configFiles,
        models: extractModels4(configFiles),
        user: options?.allUsers ? user : void 0,
        cliBinary
      });
    }
    const cwd = process.cwd();
    const projectCursorDir = join21(cwd, CURSOR_DIR_NAME);
    if (await fs.access(projectCursorDir)) {
      const projectConfigs = await loadFiles2(projectCursorDir, ["mcp.json", "cli.json"], fs);
      if (projectConfigs.length > 0) {
        installations.push({
          agent: "cursor-cli",
          agentName: `project:${basename7(cwd)}`,
          installDir: projectCursorDir,
          configFiles: projectConfigs,
          profile: "project"
        });
      }
    }
    return installations;
  },
  getConfigPaths() {
    const home = new LocalFSProvider().homedir();
    const cursorDir = join21(home, CURSOR_DIR_NAME);
    return USER_CONFIG_FILES2.map((f) => join21(cursorDir, f));
  },
  getSkillsDir(_installDir) {
    return void 0;
  },
  getGatewayInfo(_config) {
    return void 0;
  },
  getModels(configs) {
    return extractModels4(configs);
  },
  getMemoryFiles(installDir) {
    return [
      join21(installDir, "rules")
    ];
  },
  getCredentialPaths(installDir) {
    return USER_CONFIG_FILES2.map((f) => join21(installDir, f));
  },
  getCLICommand() {
    return "cursor-agent";
  },
  getProbeManifest() {
    return {
      filePaths: [
        "~/.cursor/cli-config.json",
        "~/.cursor/mcp.json",
        // User-relative CLI install locations — both names supported
        "~/.local/bin/cursor-agent",
        "~/.npm-global/bin/cursor-agent",
        "~/.volta/bin/cursor-agent",
        "~/.bun/bin/cursor-agent",
        "~/.local/bin/agent",
        "~/.cursor/bin/agent"
      ],
      globPatterns: [
        "~/.cursor/rules/*.mdc",
        "~/.cursor/extensions/**",
        nvmBinaryGlob("cursor-agent")
      ],
      commands: [
        { id: "cursor-agent-which", cmd: "which", args: ["cursor-agent"], timeout: 3e3 },
        { id: "cursor-agent-version", cmd: "cursor-agent", args: ["--version"], timeout: 15e3 }
      ],
      directoryListings: [
        "~/.cursor",
        "~/.cursor/rules",
        "~/.cursor/extensions"
      ],
      envPrefixes: ["CURSOR_"],
      systemPaths: SYSTEM_CLI_PATHS12,
      systemDirListings: []
    };
  },
  // Cursor's privilege gradient runs through the permission allow/deny layer
  // and the sandbox layer. Inversion fires when sandbox is disabled, an
  // unsafe approval mode is set, or Shell(*) lands in allow without a deny
  // net — any of which lets remote-controlled tool calls reach the host.
  getZoneGraph() {
    return {
      zones: [
        { id: "net", label: "Network / Cursor Cloud", trustLevel: 0 },
        { id: "mcp", label: "MCP Transport", trustLevel: 1 },
        { id: "perm", label: "Permission + Sandbox Layer", trustLevel: 2 },
        { id: "host", label: "Host Filesystem", trustLevel: 3 }
      ],
      components: [
        {
          id: "inbound",
          label: "Network / Remote MCP",
          zone: "net",
          guardCheckIds: ["CUR-007"]
        },
        {
          id: "mcp-transport",
          label: "MCP Transport",
          zone: "mcp",
          guardCheckIds: ["CUR-006"]
        },
        {
          id: "permission",
          label: "Permission Layer",
          zone: "perm",
          guardCheckIds: ["CUR-001", "CUR-002", "CUR-003", "CUR-005", "CUR-008", "CUR-009"]
        },
        {
          id: "fs",
          label: "Host Filesystem",
          zone: "host",
          guardCheckIds: ["CUR-004", "CUR-010"]
        }
      ],
      edges: [
        { from: "inbound", to: "mcp-transport", kind: "data" },
        { from: "mcp-transport", to: "permission", kind: "control" },
        { from: "permission", to: "fs", kind: "data" },
        {
          from: "inbound",
          to: "fs",
          label: "permission bypass",
          triggerCheckIds: ["CUR-001", "CUR-002", "CUR-003"]
        }
      ]
    };
  }
};

// src/checks/index.ts
init_check_registry();
init_owasp_agentic();

// src/core/check-builder.ts
function defineCheck(args) {
  const { run, fix, ...meta } = args;
  const helpers = {
    result(r) {
      return {
        id: meta.id,
        name: meta.name,
        category: meta.category,
        severity: r.severity ?? meta.severity,
        passed: r.passed,
        message: r.message,
        evidence: r.evidence && r.evidence.length > 0 ? r.evidence : void 0,
        fixable: r.fixable,
        fixDescription: r.fixDescription
      };
    },
    fromEvidence(evidence, opts) {
      return helpers.result({
        passed: evidence.length === 0,
        message: evidence.length === 0 ? opts.passed : opts.failed(evidence.length),
        evidence,
        severity: opts.severity,
        fixable: opts.fixable,
        fixDescription: opts.fixDescription
      });
    },
    passed(message) {
      return helpers.result({ passed: true, message });
    }
  };
  const module = {
    ...meta,
    run: (ctx) => run(ctx, helpers)
  };
  if (fix) module.fix = fix;
  return module;
}

// src/checks/config/cfg-001-gateway-binding.ts
init_types();
init_config_writer();
init_utils();
var cfg001 = defineCheck({
  id: "CFG-001",
  name: "Gateway Binding",
  category: "config",
  severity: "critical",
  description: "Check if gateway is bound to 0.0.0.0 (all interfaces), exposing it to the network",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const host = getNestedValue(config.data, "gateway.host") ?? getNestedValue(config.data, "server.host") ?? getNestedValue(config.data, "host") ?? config.data.GATEWAY_HOST;
      const WILDCARD_BINDS = ["0.0.0.0", "[::]", "::"];
      if (typeof host === "string" && WILDCARD_BINDS.includes(host)) {
        evidence.push({
          file: config.filePath,
          detail: `Gateway bound to ${host} \u2014 accessible from all network interfaces`
        });
      }
      const hasWildcard = WILDCARD_BINDS.some((w) => config.raw.includes(w));
      if (hasWildcard) {
        const lines = config.raw.split("\n");
        for (let i = 0; i < lines.length; i++) {
          const hasMatch = WILDCARD_BINDS.some((w) => lines[i].includes(w));
          if (hasMatch && /host|bind|listen/i.test(lines[i])) {
            evidence.push({
              file: config.filePath,
              line: i + 1,
              snippet: lines[i].trim()
            });
          }
        }
      }
    }
    const uniqueEvidence = evidence.filter(
      (e, i, arr) => arr.findIndex((x) => x.file === e.file && x.line === e.line) === i
    );
    return h.result({
      passed: uniqueEvidence.length === 0,
      message: uniqueEvidence.length === 0 ? "Gateway is not bound to 0.0.0.0" : "Gateway is bound to 0.0.0.0 \u2014 accessible from all network interfaces",
      evidence: uniqueEvidence,
      fixable: true,
      fixDescription: "Rebind gateway to 127.0.0.1"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "CFG-001",
      env: "GATEWAY_HOST",
      path: "gateway.host",
      value: "127.0.0.1",
      message: "Set gateway host to 127.0.0.1",
      noConfigMessage: "No config file found"
    });
  }
});

// src/core/patterns.ts
var API_KEY_PATTERNS = [
  { pattern: /sk-[a-zA-Z0-9]{20,}/, name: "OpenAI API key" },
  { pattern: /sk-ant-[a-zA-Z0-9-]{20,}/, name: "Anthropic API key" },
  { pattern: /AKIA[0-9A-Z]{16,}/, name: "AWS Access Key" },
  { pattern: /ghp_[a-zA-Z0-9]{36,}/, name: "GitHub PAT" },
  { pattern: /gho_[a-zA-Z0-9]{36,}/, name: "GitHub OAuth token" },
  { pattern: /glpat-[a-zA-Z0-9\-_]{20,}/, name: "GitLab PAT" },
  { pattern: /xoxb-[0-9]+-[0-9a-zA-Z]+/, name: "Slack Bot token" },
  { pattern: /xoxp-[0-9]+-[0-9a-zA-Z]+/, name: "Slack User token" },
  { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, name: "Private key" },
  { pattern: /\b[0-9]{10}:[A-Za-z0-9_-]{35,}\b/, name: "Telegram Bot token" }
];
var OAUTH_SECRET_PATTERNS = [
  { pattern: /^client_secret$/i, name: "OAuth client secret (key name)" },
  { pattern: /^oauth[_-]?(?:client[_-]?)?secret$/i, name: "OAuth secret (key name)" },
  { pattern: /^(?:access|refresh)[_-]?token$/i, name: "OAuth token (key name)" },
  { pattern: /^oauth[_-]?(?:access|refresh)?[_-]?token$/i, name: "OAuth token (key name)" },
  { pattern: /^authorization[_-]?code$/i, name: "OAuth authorization code (key name)" }
];
var OAUTH_TOKEN_VALUE_PATTERNS = [
  { pattern: /^ya29\.[a-zA-Z0-9_-]+/, name: "Google OAuth access token" },
  { pattern: /^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/, name: "JWT bearer token" },
  { pattern: /^ory_at_[a-zA-Z0-9_-]+/, name: "Ory OAuth access token" }
];
function redactSecret(token) {
  if (token.length <= 12) return `[REDACTED:${token.length}c]`;
  return `${token.slice(0, 4)}...${token.slice(-4)}`;
}
function withGlobalFlag(pattern) {
  return pattern.flags.includes("g") ? pattern : new RegExp(pattern.source, pattern.flags + "g");
}
function redactSecretsInLine(line, maxLen = 80) {
  let redacted = line;
  for (const { pattern } of API_KEY_PATTERNS) {
    redacted = redacted.replace(withGlobalFlag(pattern), (m) => redactSecret(m));
  }
  const trimmed = redacted.trim();
  return trimmed.length > maxLen ? trimmed.slice(0, maxLen) + "..." : trimmed;
}

// src/checks/config/cfg-002-api-key-exposure.ts
var cfg002 = defineCheck({
  id: "CFG-002",
  name: "API Key Exposure",
  category: "config",
  severity: "critical",
  description: "Check for exposed API keys and secrets in config files",
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (config.format === "env") continue;
      const lines = config.raw.split("\n");
      for (let i = 0; i < lines.length; i++) {
        for (const { pattern, name } of API_KEY_PATTERNS) {
          if (pattern.test(lines[i])) {
            evidence.push({
              file: config.filePath,
              line: i + 1,
              snippet: redactSecretsInLine(lines[i]),
              detail: `Found ${name}`
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No API keys found in config files",
      failed: (n) => `Found ${n} exposed API key(s) in config files`
    });
  }
});

// src/checks/config/cfg-003-file-permissions.ts
init_config_writer();
var cfg003 = defineCheck({
  id: "CFG-003",
  name: "Credential Config Permissions",
  category: "config",
  severity: "warning",
  description: "Check that credential-bearing config files have restrictive permissions (600 or tighter)",
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const credentialPaths = new Set(ctx.credentialPaths ?? []);
    if (credentialPaths.size === 0) {
      return h.passed("Adapter does not declare credential paths; skipping");
    }
    const evidence = [];
    for (const config of ctx.configs) {
      if (!credentialPaths.has(config.filePath)) continue;
      try {
        const stats = await ctx.fs.stat(config.filePath);
        const mode = stats.mode & 511;
        if (mode & 63) {
          evidence.push({
            file: config.filePath,
            detail: `Permissions: ${mode.toString(8)} (should be 600 or tighter)`
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All credential config files have restrictive permissions",
      failed: (n) => `${n} credential config file(s) have overly permissive permissions`,
      fixable: true,
      fixDescription: "Set permissions to 600 (chmod 600)"
    });
  },
  async fix(ctx) {
    const credentialPaths = new Set(ctx.credentialPaths ?? []);
    let fixed = 0;
    for (const config of ctx.configs) {
      if (!credentialPaths.has(config.filePath)) continue;
      try {
        await chmodFile(config.filePath, 384);
        fixed++;
      } catch {
      }
    }
    return {
      checkId: "CFG-003",
      applied: fixed > 0,
      message: fixed > 0 ? `Set permissions to 600 on ${fixed} file(s)` : "No files to fix"
    };
  }
});

// src/checks/config/cfg-004-tls-config.ts
init_types();
var cfg004 = defineCheck({
  id: "CFG-004",
  name: "TLS Not Configured",
  category: "config",
  severity: "warning",
  description: "Check if TLS/HTTPS is configured for the gateway",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    if (!ctx.installation.gateway) {
      return h.passed("No gateway configured \u2014 TLS check not applicable");
    }
    const gw = ctx.installation.gateway;
    const hasTls = gw.tls === true;
    let tlsInConfig = false;
    for (const config of ctx.configs) {
      if (/\btls\b.*:\s*true/i.test(config.raw) || /\bssl\b.*:\s*true/i.test(config.raw)) {
        tlsInConfig = true;
      }
    }
    const passed = hasTls || tlsInConfig;
    return h.result({
      passed,
      message: passed ? "TLS is configured for the gateway" : "TLS is not configured \u2014 traffic is unencrypted"
    });
  }
});

// src/checks/config/cfg-005-shell-allowlist.ts
init_types();
init_config_writer();
init_utils();
var cfg005 = defineCheck({
  id: "CFG-005",
  name: "Missing Shell Allowlist",
  category: "config",
  severity: "warning",
  description: "Check if a shell command allowlist (safeBins) is configured",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    let found = false;
    for (const config of ctx.configs) {
      const safeBins = getNestedValue(config.data, "security.safeBins") ?? getNestedValue(config.data, "safeBins") ?? getNestedValue(config.data, "shell.allowlist") ?? config.data.SAFE_BINS;
      if (safeBins && (Array.isArray(safeBins) ? safeBins.length > 0 : true)) {
        found = true;
        break;
      }
    }
    return h.result({
      passed: found,
      message: found ? "Shell command allowlist (safeBins) is configured" : "No shell command allowlist \u2014 agents can execute any command",
      fixable: true,
      fixDescription: "Add safeBins allowlist to config"
    });
  },
  async fix(ctx) {
    const safeBins = ["ls", "cat", "grep", "head", "tail", "wc", "echo", "date"];
    return fixFirstConfig(ctx.configs, {
      checkId: "CFG-005",
      env: "SAFE_BINS",
      path: "security.safeBins",
      value: safeBins,
      envValue: safeBins.join(","),
      message: "Added safeBins allowlist with safe defaults",
      noConfigMessage: "No config file found"
    });
  }
});

// src/checks/config/cfg-006-workspace-restriction.ts
init_types();
init_utils();
var cfg006 = defineCheck({
  id: "CFG-006",
  name: "No Workspace Restriction",
  category: "config",
  severity: "warning",
  description: "Check if filesystem access is restricted to a workspace directory",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    let found = false;
    for (const config of ctx.configs) {
      const workspace = getNestedValue(config.data, "workspace") ?? getNestedValue(config.data, "security.workspace") ?? getNestedValue(config.data, "fs.root") ?? getNestedValue(config.data, "filesystem.restricted") ?? config.data.WORKSPACE_DIR;
      if (workspace) {
        found = true;
        break;
      }
    }
    return h.result({
      passed: found,
      message: found ? "Filesystem access is restricted to a workspace directory" : "No workspace restriction \u2014 agent has unrestricted filesystem access"
    });
  }
});

// src/checks/config/cfg-007-webhook-auth.ts
init_types();
init_utils();
var cfg007 = defineCheck({
  id: "CFG-007",
  name: "Webhook Missing Auth",
  category: "config",
  severity: "warning",
  description: "Check if webhooks are configured without authentication",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const webhooks = getNestedValue(config.data, "webhooks") ?? getNestedValue(config.data, "webhook");
      if (!webhooks) continue;
      const webhookList = Array.isArray(webhooks) ? webhooks : [webhooks];
      for (const wh of webhookList) {
        if (typeof wh === "object" && wh !== null) {
          const hook = wh;
          if (!hook.secret && !hook.auth && !hook.token && !hook.hmac) {
            evidence.push({
              file: config.filePath,
              detail: `Webhook "${hook.url ?? hook.endpoint ?? "unknown"}" has no authentication`
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No unauthenticated webhooks found",
      failed: (n) => `${n} webhook(s) configured without authentication`
    });
  }
});

// src/checks/config/cfg-008-sandbox-disabled.ts
init_types();
init_config_writer();
init_utils();
var cfg008 = defineCheck({
  id: "CFG-008",
  name: "Sandbox Disabled",
  category: "config",
  severity: "critical",
  description: "Check if code sandbox/isolation is disabled",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    for (const config of ctx.configs) {
      const sandbox = getNestedValue(config.data, "sandbox") ?? getNestedValue(config.data, "security.sandbox") ?? getNestedValue(config.data, "isolation");
      if (sandbox === false || sandbox === "disabled" || sandbox === "off" || sandbox === "none") {
        return h.result({
          passed: false,
          message: "Code sandbox is explicitly disabled \u2014 skills run without isolation",
          evidence: [{ file: config.filePath, detail: `sandbox: ${String(sandbox)}` }],
          fixable: true,
          fixDescription: "Enable sandbox mode"
        });
      }
    }
    return h.passed("Sandbox is not explicitly disabled");
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "CFG-008",
      env: "SANDBOX",
      path: "sandbox",
      value: true,
      message: "Enabled sandbox mode",
      noConfigMessage: "No config file found"
    });
  }
});

// src/checks/config/cfg-009-default-credentials.ts
init_utils();
var WEAK_PATTERNS = [
  /\bpassword\b/i,
  /\b(admin|root|test|demo|default|changeme|password123|12345|qwerty)\b/i
];
var CREDENTIAL_KEYS = ["password", "secret", "token", "api_key", "apiKey", "auth_token"];
var cfg009 = defineCheck({
  id: "CFG-009",
  name: "Default/Weak Credentials",
  category: "config",
  severity: "critical",
  description: "Check for default or weak credentials in config files",
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      for (const key of CREDENTIAL_KEYS) {
        const paths = [key, `auth.${key}`, `gateway.auth.${key}`, `security.${key}`];
        for (const path of paths) {
          const value = getNestedValue(config.data, path);
          if (typeof value === "string") {
            for (const pattern of WEAK_PATTERNS) {
              if (pattern.test(value)) {
                evidence.push({
                  file: config.filePath,
                  detail: `Weak credential in "${path}": value matches common default pattern`
                });
                break;
              }
            }
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No default or weak credentials found",
      failed: (n) => `Found ${n} default/weak credential(s)`
    });
  }
});

// src/checks/config/cfg-010-rate-limiting.ts
init_types();
init_config_writer();
init_utils();
var cfg010 = defineCheck({
  id: "CFG-010",
  name: "No Rate Limiting",
  category: "config",
  severity: "warning",
  description: "Check if rate limiting is configured for the gateway",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    let found = false;
    for (const config of ctx.configs) {
      const rateLimit = getNestedValue(config.data, "rateLimit") ?? getNestedValue(config.data, "gateway.rateLimit") ?? getNestedValue(config.data, "security.rateLimit") ?? getNestedValue(config.data, "rateLimiting") ?? config.data.RATE_LIMIT;
      if (rateLimit) {
        found = true;
        break;
      }
    }
    return h.result({
      passed: found,
      message: found ? "Rate limiting is configured" : "No rate limiting configured \u2014 gateway is vulnerable to abuse",
      fixable: true,
      fixDescription: "Add rate limiting configuration"
    });
  },
  async fix(ctx) {
    const rateLimit = { max: 60, window: "1m" };
    return fixFirstConfig(ctx.configs, {
      checkId: "CFG-010",
      env: "RATE_LIMIT",
      path: "rateLimit",
      value: rateLimit,
      envValue: "60/1m",
      message: "Added rate limiting (60 requests per minute)",
      noConfigMessage: "No config file found"
    });
  }
});

// src/checks/config/cfg-011-node-cve.ts
var VULNERABLE_RANGES = [
  { major: 18, minorMax: 20 },
  { major: 20, minorMax: 18 },
  { major: 22, minorMax: 12 }
];
var cfg011 = defineCheck({
  id: "CFG-011",
  name: "Node.js CVE-2026-21636",
  category: "config",
  severity: "warning",
  description: "Check if the Node.js version is vulnerable to CVE-2026-21636",
  async run(_ctx, h) {
    let nodeVersion;
    try {
      nodeVersion = process.version;
    } catch {
      return h.passed("Could not determine Node.js version");
    }
    const match = nodeVersion.match(/^v(\d+)\.(\d+)\.\d+/);
    if (!match) {
      return h.passed(`Could not parse Node.js version: ${nodeVersion}`);
    }
    const major = parseInt(match[1], 10);
    const minor = parseInt(match[2], 10);
    const vulnerable = VULNERABLE_RANGES.some(
      (range) => major === range.major && minor <= range.minorMax
    );
    return h.result({
      passed: !vulnerable,
      message: vulnerable ? `Node.js ${nodeVersion} is vulnerable to CVE-2026-21636 \u2014 update recommended` : `Node.js ${nodeVersion} is not affected by CVE-2026-21636`
    });
  }
});

// src/checks/config/cfg-012-auth-bypass.ts
init_types();
init_config_writer();
init_utils();
var cfg012 = defineCheck({
  id: "CFG-012",
  name: "Auth Bypass Enabled",
  category: "config",
  severity: "critical",
  description: "Check if authentication bypass is enabled in configuration",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const authBypass = getNestedValue(config.data, "auth.bypass") ?? getNestedValue(config.data, "gateway.auth.bypass") ?? getNestedValue(config.data, "security.authBypass") ?? getNestedValue(config.data, "noAuth");
      if (authBypass === true || authBypass === "true" || authBypass === 1) {
        evidence.push({
          file: config.filePath,
          detail: "Authentication bypass is enabled"
        });
      }
      const authMode = getNestedValue(config.data, "gateway.auth.mode") ?? getNestedValue(config.data, "auth.mode");
      if (authMode === "none" || authMode === "disabled") {
        evidence.push({
          file: config.filePath,
          detail: `Auth mode set to "${authMode}"`
        });
      }
    }
    return h.result({
      passed: evidence.length === 0,
      message: evidence.length === 0 ? "Authentication bypass is not enabled" : "Authentication bypass is enabled \u2014 anyone can access the agent",
      evidence,
      fixable: true,
      fixDescription: "Disable auth bypass and set proper auth mode"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "CFG-012",
      env: "AUTH_BYPASS",
      path: "auth.bypass",
      value: false,
      message: "Disabled auth bypass",
      noConfigMessage: "No config file found"
    });
  }
});

// src/checks/config/cfg-013-dm-policy.ts
init_types();
init_config_writer();
init_utils();
var cfg013 = defineCheck({
  id: "CFG-013",
  name: "DM Policy Open",
  category: "config",
  severity: "warning",
  description: "Check if direct message policy allows unrestricted messaging",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    for (const config of ctx.configs) {
      const dmPolicy = getNestedValue(config.data, "dm.policy") ?? getNestedValue(config.data, "messaging.dm") ?? getNestedValue(config.data, "directMessage.policy");
      if (dmPolicy === "open" || dmPolicy === "unrestricted" || dmPolicy === "allow_all") {
        return h.result({
          passed: false,
          message: "DM policy is set to open \u2014 anyone can message the agent directly",
          evidence: [{ file: config.filePath, detail: `DM policy: ${String(dmPolicy)}` }],
          fixable: true,
          fixDescription: "Set DM policy to restricted or allowlist-only"
        });
      }
    }
    return h.passed("DM policy is not set to open");
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "CFG-013",
      env: "DM_POLICY",
      path: "dm.policy",
      value: "restricted",
      message: "Set DM policy to restricted",
      noConfigMessage: "No config file found"
    });
  }
});

// src/checks/config/cfg-014-tool-policy.ts
init_types();
init_utils();
var cfg014 = defineCheck({
  id: "CFG-014",
  name: "Tool Policy Permissive",
  category: "config",
  severity: "warning",
  description: "Check if the tool execution policy is too permissive",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    for (const config of ctx.configs) {
      const toolPolicy = getNestedValue(config.data, "tools.policy") ?? getNestedValue(config.data, "security.toolPolicy") ?? getNestedValue(config.data, "skillPolicy");
      if (toolPolicy === "allow_all" || toolPolicy === "permissive" || toolPolicy === "unrestricted") {
        return h.result({
          passed: false,
          message: "Tool policy is permissive \u2014 any skill/tool can be executed without approval",
          evidence: [{ file: config.filePath, detail: `Tool policy: ${String(toolPolicy)}` }]
        });
      }
    }
    return h.passed("Tool policy is not overly permissive");
  }
});

// src/checks/config/cfg-015-mdns-broadcast.ts
init_types();
init_utils();
var cfg015 = defineCheck({
  id: "CFG-015",
  name: "mDNS Full Broadcast",
  category: "config",
  severity: "info",
  description: "Check if mDNS/Bonjour is broadcasting full agent info on the local network",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    for (const config of ctx.configs) {
      const mdns = getNestedValue(config.data, "mdns") ?? getNestedValue(config.data, "discovery.mdns") ?? getNestedValue(config.data, "bonjour");
      if (mdns === true || typeof mdns === "object" && mdns !== null) {
        const mdnsObj = typeof mdns === "object" ? mdns : {};
        const broadcast = mdnsObj.broadcast ?? mdnsObj.enabled ?? true;
        if (broadcast === true || broadcast === "full") {
          return h.result({
            passed: false,
            message: "mDNS is broadcasting agent information on the local network",
            evidence: [{ file: config.filePath, detail: "mDNS/Bonjour broadcasting is enabled" }]
          });
        }
      }
    }
    return h.passed("mDNS broadcasting is not enabled");
  }
});

// src/checks/config/cfg-016-nemoclaw-hardening.ts
import { join as join22 } from "path";
var cfg016 = defineCheck({
  id: "CFG-016",
  name: "NemoClaw Hardening",
  category: "config",
  severity: "info",
  description: "Check if NemoClaw sandbox hardening is installed for OpenClaw",
  supportedAgents: ["openclaw", "nemoclaw"],
  async run(ctx, h) {
    const nemoDir = join22(ctx.fs.homedir(), ".nemoclaw");
    const stateFile = join22(nemoDir, "state", "nemoclaw.json");
    const configFile = join22(nemoDir, "config.json");
    const dirExists = await ctx.fs.access(nemoDir);
    if (!dirExists) {
      return h.result({
        passed: false,
        message: "NemoClaw sandbox hardening is not installed \u2014 consider deploying NemoClaw for Landlock + seccomp + network isolation"
      });
    }
    const evidence = [];
    evidence.push({ file: nemoDir, detail: "NemoClaw directory detected" });
    if (await ctx.fs.access(stateFile)) {
      try {
        const raw = await ctx.fs.readFile(stateFile);
        const state = JSON.parse(raw);
        const action = state.lastAction;
        const version = state.blueprintVersion;
        evidence.push({
          file: stateFile,
          detail: `State: action=${action ?? "unknown"}, blueprint=${version ?? "unknown"}`
        });
      } catch {
        evidence.push({ file: stateFile, detail: "State file exists but unreadable" });
      }
    }
    if (await ctx.fs.access(configFile)) {
      try {
        const raw = await ctx.fs.readFile(configFile);
        const config = JSON.parse(raw);
        const provider = config.endpointType;
        evidence.push({
          file: configFile,
          detail: `Inference provider: ${provider ?? "unknown"}`
        });
      } catch {
        evidence.push({ file: configFile, detail: "Config file exists but unreadable" });
      }
    }
    return h.result({
      passed: true,
      message: "NemoClaw sandbox hardening is installed",
      evidence
    });
  }
});

// src/checks/config/cfg-017-nemoclaw-sandbox-active.ts
import { join as join23 } from "path";
var cfg017 = defineCheck({
  id: "CFG-017",
  name: "NemoClaw Sandbox Active",
  category: "config",
  severity: "warning",
  description: "Check if NemoClaw sandbox is actively deployed (not just installed)",
  supportedAgents: ["openclaw", "nemoclaw"],
  async run(ctx, h) {
    const stateFile = join23(ctx.fs.homedir(), ".nemoclaw", "state", "nemoclaw.json");
    if (!await ctx.fs.access(stateFile)) {
      return h.result({
        passed: false,
        message: "NemoClaw state file not found \u2014 sandbox not deployed"
      });
    }
    try {
      const raw = await ctx.fs.readFile(stateFile);
      const state = JSON.parse(raw);
      const lastAction = state.lastAction;
      const sandboxName = state.sandboxName;
      const lastRunId = state.lastRunId;
      if (!lastRunId && !lastAction) {
        return h.result({
          passed: false,
          message: "NemoClaw is installed but no sandbox has been deployed"
        });
      }
      return h.result({
        passed: true,
        message: `NemoClaw sandbox "${sandboxName ?? "openclaw"}" is deployed (action: ${lastAction ?? "unknown"})`,
        evidence: [{
          file: stateFile,
          detail: `runId=${lastRunId ?? "none"}, action=${lastAction ?? "none"}, sandbox=${sandboxName ?? "default"}`
        }]
      });
    } catch {
      return h.result({
        passed: false,
        message: "NemoClaw state file exists but could not be parsed"
      });
    }
  }
});

// src/checks/config/cfg-018-nemoclaw-network-policy.ts
import { join as join24 } from "path";
var cfg018 = defineCheck({
  id: "CFG-018",
  name: "NemoClaw Network Policy",
  category: "config",
  severity: "warning",
  description: "Check if NemoClaw enforces deny-by-default network policy with controlled egress",
  supportedAgents: ["openclaw", "nemoclaw"],
  async run(ctx, h) {
    const stateFile = join24(ctx.fs.homedir(), ".nemoclaw", "state", "nemoclaw.json");
    if (!await ctx.fs.access(stateFile)) {
      return h.result({
        passed: false,
        message: "NemoClaw not deployed \u2014 no network policy enforcement"
      });
    }
    let blueprintDir;
    try {
      const raw = await ctx.fs.readFile(stateFile);
      const state = JSON.parse(raw);
      const version = state.blueprintVersion;
      if (version) {
        const candidate = join24(ctx.fs.homedir(), ".nemoclaw", "blueprints", version);
        if (await ctx.fs.access(candidate)) {
          blueprintDir = candidate;
        }
      }
    } catch {
    }
    if (!blueprintDir) {
      const globalPaths = [
        "/usr/local/lib/node_modules/nemoclaw/nemoclaw-blueprint",
        join24(ctx.fs.homedir(), ".npm-global", "lib", "node_modules", "nemoclaw", "nemoclaw-blueprint")
      ];
      for (const p of globalPaths) {
        if (await ctx.fs.access(p)) {
          blueprintDir = p;
          break;
        }
      }
    }
    if (!blueprintDir) {
      return h.result({
        passed: true,
        message: "NemoClaw is deployed but blueprint policies could not be located for inspection",
        evidence: [{ file: stateFile, detail: "Sandbox deployed \u2014 network policy assumed active via OpenShell enforcement" }]
      });
    }
    const evidence = [];
    const policyFile = join24(blueprintDir, "policies", "openclaw-sandbox.yaml");
    if (await ctx.fs.access(policyFile)) {
      try {
        const content = await ctx.fs.readFile(policyFile);
        const hasDenyDefault = /default\s*:\s*deny/i.test(content) || /policy\s*:\s*deny/i.test(content) || content.includes("deny-by-default");
        const allowMatches = content.match(/allow:/gi);
        const endpointCount = allowMatches ? allowMatches.length : 0;
        evidence.push({
          file: policyFile,
          detail: `Baseline policy: ${hasDenyDefault ? "deny-by-default" : "custom"}, ${endpointCount} allow rule(s)`
        });
      } catch {
        evidence.push({ file: policyFile, detail: "Policy file exists but unreadable" });
      }
    }
    const presetsDir = join24(blueprintDir, "policies", "presets");
    if (await ctx.fs.access(presetsDir)) {
      try {
        const presets = await ctx.fs.readdir(presetsDir);
        const yamlPresets = presets.filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"));
        if (yamlPresets.length > 0) {
          evidence.push({
            file: presetsDir,
            detail: `Available policy presets: ${yamlPresets.map((f) => f.replace(/\.ya?ml$/, "")).join(", ")}`
          });
        }
      } catch {
      }
    }
    return h.result({
      passed: true,
      message: "NemoClaw network policy is configured with controlled egress",
      evidence
    });
  }
});

// src/checks/config/cfg-019-nemoclaw-blueprint-integrity.ts
import { join as join25 } from "path";
var cfg019 = defineCheck({
  id: "CFG-019",
  name: "NemoClaw Blueprint Integrity",
  category: "config",
  severity: "info",
  description: "Check if NemoClaw blueprint uses digest verification and version pinning",
  supportedAgents: ["openclaw", "nemoclaw"],
  async run(ctx, h) {
    const nemoDir = join25(ctx.fs.homedir(), ".nemoclaw");
    if (!await ctx.fs.access(nemoDir)) {
      return h.result({
        passed: false,
        message: "NemoClaw not installed \u2014 blueprint integrity check not applicable"
      });
    }
    const evidence = [];
    const pluginPaths = [
      "/usr/local/lib/node_modules/nemoclaw/nemoclaw/openclaw.plugin.json",
      join25(ctx.fs.homedir(), ".npm-global", "lib", "node_modules", "nemoclaw", "nemoclaw", "openclaw.plugin.json")
    ];
    let usesLatest = false;
    for (const pluginPath of pluginPaths) {
      if (await ctx.fs.access(pluginPath)) {
        try {
          const raw = await ctx.fs.readFile(pluginPath);
          const manifest = JSON.parse(raw);
          const blueprintVersion = manifest.blueprintVersion;
          if (blueprintVersion === "latest") {
            usesLatest = true;
            evidence.push({
              file: pluginPath,
              detail: 'Blueprint version set to "latest" \u2014 consider pinning to a specific version'
            });
          } else if (blueprintVersion) {
            evidence.push({
              file: pluginPath,
              detail: `Blueprint version pinned to ${blueprintVersion}`
            });
          }
        } catch {
        }
        break;
      }
    }
    const blueprintsDir = join25(nemoDir, "blueprints");
    if (await ctx.fs.access(blueprintsDir)) {
      try {
        const versions = await ctx.fs.readdir(blueprintsDir);
        for (const ver of versions) {
          const manifestPath = join25(blueprintsDir, ver, "blueprint.yaml");
          if (await ctx.fs.access(manifestPath)) {
            evidence.push({
              file: manifestPath,
              detail: `Cached blueprint v${ver} with manifest`
            });
          }
        }
      } catch {
      }
    }
    const stateFile = join25(nemoDir, "state", "nemoclaw.json");
    if (await ctx.fs.access(stateFile)) {
      try {
        const raw = await ctx.fs.readFile(stateFile);
        const state = JSON.parse(raw);
        if (state.migrationSnapshot || state.hostBackupPath) {
          evidence.push({
            file: stateFile,
            detail: "Migration snapshot exists \u2014 rollback capability available"
          });
        }
      } catch {
      }
    }
    const passed = evidence.length > 0;
    return h.result({
      passed,
      message: passed ? `NemoClaw blueprint integrity verified${usesLatest ? ' (warning: using "latest" tag)' : ""}` : "NemoClaw installed but no blueprint artifacts found",
      evidence
    });
  }
});

// src/checks/config/cfg-020-nemoclaw-api-key-exposure.ts
import { join as join26 } from "path";
init_config_writer();
var CREDENTIAL_FILE = "credentials.json";
var cfg020 = defineCheck({
  id: "CFG-020",
  name: "NemoClaw API Key Exposure",
  category: "config",
  severity: "critical",
  description: "Check if NemoClaw credentials.json stores API keys in plaintext with unsafe file permissions",
  supportedAgents: ["openclaw", "nemoclaw"],
  async run(ctx, h) {
    const credPath = join26(ctx.fs.homedir(), ".nemoclaw", CREDENTIAL_FILE);
    if (!await ctx.fs.access(credPath)) {
      return h.passed("No NemoClaw credentials file found");
    }
    const evidence = [];
    let hasPlaintextKey = false;
    let hasLoosePerms = false;
    if (ctx.fs.platform === "darwin" || ctx.fs.platform === "linux") {
      try {
        const stats = await ctx.fs.stat(credPath);
        const mode = stats.mode & 511;
        if (mode & 63) {
          hasLoosePerms = true;
          evidence.push({
            file: credPath,
            detail: `Permissions: ${mode.toString(8)} \u2014 group/other can read credentials (should be 600)`
          });
        }
      } catch {
      }
    }
    try {
      const raw = await ctx.fs.readFile(credPath);
      const creds = JSON.parse(raw);
      for (const [key, value] of Object.entries(creds)) {
        if (typeof value === "string" && value.length > 0) {
          const isApiKey = /api[_-]?key|token|secret|password/i.test(key);
          const looksLikeKey = /^(nvapi-|sk-|key-|ghp_|ghs_|glpat-)/.test(value) || value.length >= 32 && /^[A-Za-z0-9+/=_-]+$/.test(value);
          if (isApiKey || looksLikeKey) {
            hasPlaintextKey = true;
            const redacted = value.slice(0, 8) + "..." + value.slice(-4);
            evidence.push({
              file: credPath,
              detail: `Plaintext key "${key}": ${redacted} (${value.length} chars)`
            });
          }
        }
      }
    } catch {
      evidence.push({ file: credPath, detail: "Credentials file exists but could not be parsed" });
    }
    const passed = !hasPlaintextKey && !hasLoosePerms;
    return h.result({
      passed,
      message: passed ? "NemoClaw credentials are properly secured" : `NemoClaw credentials at risk: ${[
        hasPlaintextKey && "plaintext API keys",
        hasLoosePerms && "overly permissive file permissions"
      ].filter(Boolean).join(", ")}`,
      evidence,
      fixable: hasLoosePerms,
      fixDescription: hasLoosePerms ? "Set credentials.json permissions to 600 (owner read/write only)" : void 0
    });
  },
  async fix(ctx) {
    const credPath = join26(ctx.fs.homedir(), ".nemoclaw", CREDENTIAL_FILE);
    if (!await ctx.fs.access(credPath)) {
      return { checkId: "CFG-020", applied: false, message: "Credentials file not found" };
    }
    try {
      await chmodFile(credPath, 384);
      return {
        checkId: "CFG-020",
        applied: true,
        message: "Set credentials.json permissions to 600 (owner read/write only)"
      };
    } catch (err) {
      return {
        checkId: "CFG-020",
        applied: false,
        message: `Failed to fix permissions: ${err instanceof Error ? err.message : String(err)}`
      };
    }
  }
});

// src/checks/config/cfg-021-nemoclaw-gpu-isolation.ts
import { join as join27 } from "path";
var SANDBOXES_FILE = "sandboxes.json";
var cfg021 = defineCheck({
  id: "CFG-021",
  name: "NemoClaw GPU Isolation",
  category: "config",
  severity: "warning",
  description: "Check if GPU-enabled NemoClaw sandboxes use NIM container isolation",
  supportedAgents: ["openclaw", "nemoclaw"],
  async run(ctx, h) {
    const sandboxesPath = join27(ctx.fs.homedir(), ".nemoclaw", SANDBOXES_FILE);
    if (!await ctx.fs.access(sandboxesPath)) {
      return h.passed("No NemoClaw sandboxes configuration found");
    }
    let config;
    try {
      const raw = await ctx.fs.readFile(sandboxesPath);
      config = JSON.parse(raw);
    } catch {
      return h.result({
        passed: false,
        message: "NemoClaw sandboxes.json exists but could not be parsed"
      });
    }
    if (!config.sandboxes || Object.keys(config.sandboxes).length === 0) {
      return h.passed("No sandboxes defined in NemoClaw configuration");
    }
    const evidence = [];
    let unsafeCount = 0;
    for (const [name, sandbox] of Object.entries(config.sandboxes)) {
      if (sandbox.gpuEnabled && !sandbox.nimContainer) {
        unsafeCount++;
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": GPU enabled but nimContainer is ${sandbox.nimContainer === null ? "null" : "not set"} \u2014 GPU passthrough without NIM container isolation`
        });
      } else if (sandbox.gpuEnabled && sandbox.nimContainer) {
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": GPU isolated via NIM container "${sandbox.nimContainer}"`
        });
      }
    }
    return h.result({
      passed: unsafeCount === 0,
      message: unsafeCount === 0 ? "All GPU-enabled sandboxes use NIM container isolation" : `${unsafeCount} sandbox(es) have GPU passthrough without NIM container isolation`,
      evidence
    });
  }
});

// src/checks/config/cfg-022-nemoclaw-policy-scope.ts
import { join as join28 } from "path";
var SANDBOXES_FILE2 = "sandboxes.json";
var RECOMMENDED_POLICIES = ["filesystem", "network", "syscall", "pypi", "npm"];
var cfg022 = defineCheck({
  id: "CFG-022",
  name: "NemoClaw Policy Scope",
  category: "config",
  severity: "warning",
  description: "Check if NemoClaw sandbox policies cover filesystem, network, and syscall restrictions beyond package management",
  supportedAgents: ["openclaw", "nemoclaw"],
  async run(ctx, h) {
    const sandboxesPath = join28(ctx.fs.homedir(), ".nemoclaw", SANDBOXES_FILE2);
    if (!await ctx.fs.access(sandboxesPath)) {
      return h.passed("No NemoClaw sandboxes configuration found");
    }
    let config;
    try {
      const raw = await ctx.fs.readFile(sandboxesPath);
      config = JSON.parse(raw);
    } catch {
      return h.result({
        passed: false,
        message: "NemoClaw sandboxes.json exists but could not be parsed"
      });
    }
    if (!config.sandboxes || Object.keys(config.sandboxes).length === 0) {
      return h.passed("No sandboxes defined in NemoClaw configuration");
    }
    const evidence = [];
    let narrowCount = 0;
    for (const [name, sandbox] of Object.entries(config.sandboxes)) {
      const policies = sandbox.policies ?? [];
      const missing = RECOMMENDED_POLICIES.filter((p) => !policies.includes(p));
      if (missing.length > 0) {
        narrowCount++;
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": active policies [${policies.join(", ") || "none"}] \u2014 missing: [${missing.join(", ")}]`
        });
      } else {
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": full policy coverage [${policies.join(", ")}]`
        });
      }
    }
    return h.result({
      passed: narrowCount === 0,
      message: narrowCount === 0 ? "All sandboxes have comprehensive policy coverage" : `${narrowCount} sandbox(es) have narrow policy scope \u2014 missing filesystem, network, or syscall restrictions`,
      evidence
    });
  }
});

// src/checks/config/cfg-023-nemoclaw-model-pinning.ts
import { join as join29 } from "path";
var SANDBOXES_FILE3 = "sandboxes.json";
var cfg023 = defineCheck({
  id: "CFG-023",
  name: "NemoClaw Model Pinning",
  category: "config",
  severity: "info",
  description: "Check if NemoClaw sandboxes pin models to specific versions to prevent model swap attacks",
  supportedAgents: ["openclaw", "nemoclaw"],
  async run(ctx, h) {
    const sandboxesPath = join29(ctx.fs.homedir(), ".nemoclaw", SANDBOXES_FILE3);
    if (!await ctx.fs.access(sandboxesPath)) {
      return h.passed("No NemoClaw sandboxes configuration found");
    }
    let config;
    try {
      const raw = await ctx.fs.readFile(sandboxesPath);
      config = JSON.parse(raw);
    } catch {
      return h.result({
        passed: false,
        message: "NemoClaw sandboxes.json exists but could not be parsed"
      });
    }
    if (!config.sandboxes || Object.keys(config.sandboxes).length === 0) {
      return h.passed("No sandboxes defined in NemoClaw configuration");
    }
    const evidence = [];
    let unpinnedCount = 0;
    const mutableTags = ["latest", "stable", "nightly", "dev", "canary"];
    for (const [name, sandbox] of Object.entries(config.sandboxes)) {
      const model = sandbox.model;
      if (!model) {
        unpinnedCount++;
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": no model specified \u2014 will use provider default (unpinned)`
        });
        continue;
      }
      const parts = model.split(":");
      const tag = parts.length > 1 ? parts[parts.length - 1] : void 0;
      const isMutable = tag !== void 0 && mutableTags.includes(tag.toLowerCase());
      const hasVersion = /[-:][\dv]/.test(model) || /\d+[bB]/.test(model);
      if (isMutable) {
        unpinnedCount++;
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": model "${model}" uses mutable tag "${tag}" \u2014 vulnerable to server-side model swap`
        });
      } else if (hasVersion) {
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": model "${model}" appears version-pinned`
        });
      } else {
        unpinnedCount++;
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": model "${model}" has no version specifier \u2014 consider pinning to a specific version`
        });
      }
    }
    return h.result({
      passed: unpinnedCount === 0,
      message: unpinnedCount === 0 ? "All sandbox models are pinned to specific versions" : `${unpinnedCount} sandbox(es) use unpinned or mutable model references`,
      evidence
    });
  }
});

// src/checks/config/cfg-024-nemoclaw-default-sandbox.ts
import { join as join30 } from "path";
var SANDBOXES_FILE4 = "sandboxes.json";
var cfg024 = defineCheck({
  id: "CFG-024",
  name: "NemoClaw Default Sandbox",
  category: "config",
  severity: "warning",
  description: "Check if NemoClaw defaultSandbox references an existing sandbox to prevent fallback to unprotected execution",
  supportedAgents: ["openclaw", "nemoclaw"],
  async run(ctx, h) {
    const sandboxesPath = join30(ctx.fs.homedir(), ".nemoclaw", SANDBOXES_FILE4);
    if (!await ctx.fs.access(sandboxesPath)) {
      return h.passed("No NemoClaw sandboxes configuration found");
    }
    let config;
    try {
      const raw = await ctx.fs.readFile(sandboxesPath);
      config = JSON.parse(raw);
    } catch {
      return h.result({
        passed: false,
        message: "NemoClaw sandboxes.json exists but could not be parsed"
      });
    }
    const evidence = [];
    if (!config.defaultSandbox) {
      return h.result({
        passed: false,
        message: "No defaultSandbox set \u2014 NemoClaw may not apply sandbox policies automatically",
        evidence: [{ file: sandboxesPath, detail: "defaultSandbox field is missing or empty" }]
      });
    }
    const sandboxNames = Object.keys(config.sandboxes ?? {});
    if (sandboxNames.length === 0) {
      return h.result({
        passed: false,
        message: `defaultSandbox "${config.defaultSandbox}" is set but no sandboxes are defined`,
        evidence: [{ file: sandboxesPath, detail: `Dangling reference: "${config.defaultSandbox}" \u2192 no sandboxes exist` }]
      });
    }
    if (!sandboxNames.includes(config.defaultSandbox)) {
      return h.result({
        passed: false,
        message: `defaultSandbox "${config.defaultSandbox}" does not match any defined sandbox`,
        evidence: [{
          file: sandboxesPath,
          detail: `Dangling reference: "${config.defaultSandbox}" not in [${sandboxNames.join(", ")}]`
        }]
      });
    }
    evidence.push({
      file: sandboxesPath,
      detail: `defaultSandbox "${config.defaultSandbox}" resolves to a valid sandbox`
    });
    return h.result({
      passed: true,
      message: `Default sandbox "${config.defaultSandbox}" is correctly configured`,
      evidence
    });
  }
});

// src/checks/config/index.ts
var configChecks = [
  cfg001,
  cfg002,
  cfg003,
  cfg004,
  cfg005,
  cfg006,
  cfg007,
  cfg008,
  cfg009,
  cfg010,
  cfg011,
  cfg012,
  cfg013,
  cfg014,
  cfg015,
  cfg016,
  cfg017,
  cfg018,
  cfg019,
  cfg020,
  cfg021,
  cfg022,
  cfg023,
  cfg024
];

// src/analyzers/ast-analyzer.ts
import { parse as parse2 } from "@babel/parser";
import _traverse from "@babel/traverse";
var traverse = typeof _traverse === "function" ? _traverse : _traverse.default;
var SOURCES = /* @__PURE__ */ new Set([
  "readFile",
  "readFileSync",
  "readdir",
  "readdirSync",
  "createReadStream"
]);
var SINKS = /* @__PURE__ */ new Set([
  "fetch",
  "request",
  "get",
  "post",
  "put",
  "patch",
  "send",
  "write",
  "emit"
]);
var NETWORK_MODULES = /* @__PURE__ */ new Set([
  "http",
  "https",
  "net",
  "dgram",
  "axios",
  "got",
  "node-fetch",
  "undici",
  "request"
]);
var EXEC_FUNCTIONS = /* @__PURE__ */ new Set([
  "eval",
  "Function",
  "exec",
  "execSync",
  "spawn",
  "spawnSync",
  "execFile",
  "execFileSync",
  "fork"
]);
var SENSITIVE_PATHS = [
  /\/\.ssh\//i,
  /\/\.aws\//i,
  /\/\.gnupg\//i,
  /\/\.kube\//i,
  /\/\.env/i,
  /\/etc\/(?:passwd|shadow|hosts)/i,
  /\/\.docker\/config/i,
  /credentials/i,
  /secret/i
];
function analyzeCode(code, filename = "unknown.js") {
  const results = [];
  let ast;
  try {
    ast = parse2(code, {
      sourceType: "unambiguous",
      plugins: ["typescript", "jsx", "decorators"],
      errorRecovery: true
    });
  } catch {
    return results;
  }
  const sourceVars = /* @__PURE__ */ new Set();
  const networkImports = /* @__PURE__ */ new Set();
  try {
    traverse(ast, {
      ImportDeclaration(path) {
        const source = path.node.source.value;
        if (NETWORK_MODULES.has(source)) {
          for (const spec of path.node.specifiers) {
            networkImports.add(spec.local.name);
          }
        }
        if (source === "child_process") {
          for (const spec of path.node.specifiers) {
            networkImports.add(spec.local.name);
          }
        }
      },
      CallExpression(path) {
        const node = path.node;
        const line = node.loc?.start.line ?? 0;
        const snippet = code.split("\n")[line - 1]?.trim() ?? "";
        if (node.callee.type === "Identifier" && EXEC_FUNCTIONS.has(node.callee.name)) {
          results.push({
            type: "eval-exec",
            line,
            snippet: snippet.slice(0, 120),
            description: `${node.callee.name}() call detected`
          });
        }
        if (node.callee.type === "Identifier" && node.callee.name === "require" && node.arguments[0]?.type === "StringLiteral") {
          const mod = node.arguments[0].value;
          if (NETWORK_MODULES.has(mod) || mod === "child_process") {
            networkImports.add(mod);
          }
        }
        if (node.callee.type === "Identifier" && SOURCES.has(node.callee.name)) {
          const firstArg = node.arguments[0];
          if (firstArg?.type === "StringLiteral") {
            for (const pattern of SENSITIVE_PATHS) {
              if (pattern.test(firstArg.value)) {
                results.push({
                  type: "fs-access",
                  source: firstArg.value,
                  line,
                  snippet: snippet.slice(0, 120),
                  description: `Reading sensitive path: ${firstArg.value}`
                });
              }
            }
          }
          const parent = path.parent;
          if (parent?.type === "VariableDeclarator" && parent.id.type === "Identifier") {
            sourceVars.add(parent.id.name);
          }
        }
        if (node.callee.type === "MemberExpression") {
          const prop = node.callee.property;
          const propName = prop.type === "Identifier" ? prop.name : "";
          if (SOURCES.has(propName)) {
            const firstArg = node.arguments[0];
            if (firstArg?.type === "StringLiteral") {
              for (const pattern of SENSITIVE_PATHS) {
                if (pattern.test(firstArg.value)) {
                  results.push({
                    type: "fs-access",
                    source: firstArg.value,
                    line,
                    snippet: snippet.slice(0, 120),
                    description: `Reading sensitive path: ${firstArg.value}`
                  });
                }
              }
            }
            const parent = path.parent;
            if (parent?.type === "VariableDeclarator" && parent.id.type === "Identifier") {
              sourceVars.add(parent.id.name);
            }
          }
          if (SINKS.has(propName) || networkImports.has(propName)) {
            const argStr = code.slice(node.arguments[0]?.start ?? 0, node.arguments[node.arguments.length - 1]?.end ?? 0);
            for (const sourceVar of sourceVars) {
              if (argStr.includes(sourceVar)) {
                results.push({
                  type: "source-to-sink",
                  source: sourceVar,
                  sink: propName,
                  line,
                  snippet: snippet.slice(0, 120),
                  description: `Data flows from "${sourceVar}" to network sink "${propName}"`
                });
              }
            }
          }
          if (propName === "env" && node.callee.object.type === "Identifier" && node.callee.object.name === "process") {
            sourceVars.add("process.env");
          }
          if (EXEC_FUNCTIONS.has(propName)) {
            const obj = node.callee.object;
            if (obj.type === "Identifier" && (networkImports.has(obj.name) || obj.name === "child_process")) {
              results.push({
                type: "eval-exec",
                line,
                snippet: snippet.slice(0, 120),
                description: `${obj.name}.${propName}() \u2014 command execution`
              });
            }
          }
        }
        if (node.callee.type === "Identifier") {
          if (node.callee.name === "fetch") {
            const firstArg = node.arguments[0];
            if (firstArg?.type === "StringLiteral") {
              const url = firstArg.value;
              if (!url.startsWith("http://localhost") && !url.startsWith("http://127.0.0.1") && !url.startsWith("https://")) {
                results.push({
                  type: "suspicious-network",
                  sink: url,
                  line,
                  snippet: snippet.slice(0, 120),
                  description: `Non-localhost HTTP or non-HTTPS fetch: ${url}`
                });
              }
            }
            for (const sourceVar of sourceVars) {
              const argStr = code.slice(
                node.arguments[0]?.start ?? 0,
                node.arguments[node.arguments.length - 1]?.end ?? 0
              );
              if (argStr.includes(sourceVar)) {
                results.push({
                  type: "source-to-sink",
                  source: sourceVar,
                  sink: "fetch",
                  line,
                  snippet: snippet.slice(0, 120),
                  description: `Data flows from "${sourceVar}" to fetch()`
                });
              }
            }
          }
        }
      },
      // Track variable assignments from sources
      VariableDeclarator(path) {
        const init = path.node.init;
        if (!init) return;
        const id = path.node.id;
        if (id.type !== "Identifier") return;
        if (init.type === "MemberExpression" && init.object.type === "MemberExpression" && init.object.object.type === "Identifier" && init.object.object.name === "process" && init.object.property.type === "Identifier" && init.object.property.name === "env") {
          sourceVars.add(id.name);
        }
      },
      // Detect new Function() and new WebSocket()
      NewExpression(path) {
        const node = path.node;
        if (node.callee.type === "Identifier" && node.callee.name === "Function") {
          const line = node.loc?.start.line ?? 0;
          const snippet = code.split("\n")[line - 1]?.trim() ?? "";
          results.push({
            type: "eval-exec",
            line,
            snippet: snippet.slice(0, 120),
            description: "new Function() constructor \u2014 dynamic code execution"
          });
        }
        if (node.callee.type === "Identifier" && node.callee.name === "WebSocket") {
          const line = node.loc?.start.line ?? 0;
          const snippet = code.split("\n")[line - 1]?.trim() ?? "";
          results.push({
            type: "suspicious-network",
            sink: "WebSocket",
            line,
            snippet: snippet.slice(0, 120),
            description: "WebSocket connection created"
          });
        }
      }
    });
  } catch {
  }
  return results;
}

// src/checks/skills/skl-001-data-exfiltration.ts
init_utils();
var skl001 = defineCheck({
  id: "SKL-001",
  name: "Data Exfiltration Flow",
  category: "skills",
  severity: "critical",
  description: "Detect data flows from file/env sources to network sinks (AST-based)",
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const evidence = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);
    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        const flows = analyzeCode(code, file);
        const exfil = flows.filter((f) => f.type === "source-to-sink");
        for (const flow of exfil) {
          evidence.push({
            file,
            line: flow.line,
            snippet: flow.snippet,
            detail: flow.description
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No data exfiltration flows detected",
      failed: (n) => `Found ${n} data exfiltration flow(s) \u2014 data flowing from sources to network sinks`
    });
  }
});

// src/analyzers/entropy.ts
var HIGH_ENTROPY_THRESHOLD = 5.5;
var MIN_BLOCK_LENGTH = 40;
function shannonEntropy(str) {
  if (str.length === 0) return 0;
  const freq = /* @__PURE__ */ new Map();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}
function findHighEntropyBlocks(code, threshold = HIGH_ENTROPY_THRESHOLD, minLength = MIN_BLOCK_LENGTH) {
  const results = [];
  const lines = code.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.length < minLength) continue;
    if (line.startsWith("//") || line.startsWith("*") || line.startsWith("#")) continue;
    const strings = extractStrings(line);
    for (const str of strings) {
      if (str.length < minLength) continue;
      const entropy = shannonEntropy(str);
      if (entropy > threshold) {
        results.push({
          line: i + 1,
          entropy: Math.round(entropy * 100) / 100,
          snippet: str.slice(0, 80) + (str.length > 80 ? "..." : "")
        });
      }
    }
  }
  return results;
}
function extractStrings(line) {
  const strings = [];
  const patterns = [
    /"([^"]{10,})"/g,
    /'([^']{10,})'/g,
    /`([^`]{10,})`/g
  ];
  for (const regex of patterns) {
    let match;
    while ((match = regex.exec(line)) !== null) {
      strings.push(match[1]);
    }
  }
  return strings;
}

// src/analyzers/obfuscation.ts
var OBFUSCATION_PATTERNS = [
  { pattern: /(\\x[0-9a-fA-F]{2}){6,}/, label: "Hex escape sequence chain" },
  { pattern: /[A-Za-z0-9+/]{60,}={0,2}/, label: "Long base64-encoded string" },
  { pattern: /String\.fromCharCode\s*\([\s\S]*?,[\s\S]*?,/, label: "String.fromCharCode with multiple args" },
  { pattern: /\batob\s*\(/, label: "atob() decoding" }
];
var DECODER_PATTERNS = [
  { pattern: /Buffer\.from\s*\([^,)]*,\s*['"`]base64['"`]\s*\)/, label: "Buffer.from(\u2026, 'base64')" },
  { pattern: /\batob\s*\(/, label: "atob()" },
  { pattern: /String\.fromCharCode(?:\.apply)?\s*\(/, label: "String.fromCharCode()" },
  { pattern: /\bunescape\s*\(/, label: "unescape()" },
  { pattern: /\bdecodeURIComponent\s*\(\s*escape\s*\(/, label: "decodeURIComponent(escape(\u2026))" }
];
var ENCODED_LITERAL = /['"`][A-Za-z0-9+/]{16,}={0,2}['"`]/g;
var STRING_TABLE_MIN_LITERALS = 3;
function isComment(line) {
  const t = line.trimStart();
  return t.startsWith("//") || t.startsWith("*") || t.startsWith("#");
}
function analyzeObfuscation(code) {
  const lines = code.split("\n");
  const hits = [];
  let encodedLiteralCount = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isComment(line)) continue;
    const encoded = line.match(ENCODED_LITERAL);
    if (encoded) encodedLiteralCount += encoded.length;
    for (const { pattern, label } of OBFUSCATION_PATTERNS) {
      if (pattern.test(line)) {
        const trimmed = line.trim();
        hits.push({
          line: i + 1,
          snippet: trimmed.slice(0, 80) + (trimmed.length > 80 ? "..." : ""),
          label
        });
        break;
      }
    }
  }
  const decoderLabels = [];
  for (const { pattern, label } of DECODER_PATTERNS) {
    if (pattern.test(code)) decoderLabels.push(label);
  }
  let tier = "none";
  if (decoderLabels.length > 0 && encodedLiteralCount >= STRING_TABLE_MIN_LITERALS) {
    tier = "string-table";
  } else if (hits.length > 0) {
    tier = "encoded";
  }
  return { tier, decoderLabels, encodedLiteralCount, hits };
}

// src/checks/skills/skl-002-obfuscated-code.ts
init_utils();
var skl002 = defineCheck({
  id: "SKL-002",
  name: "Obfuscated Code",
  category: "skills",
  severity: "warning",
  description: "Detect obfuscated code using Shannon entropy analysis and pattern matching",
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const evidence = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);
    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        const blocks = findHighEntropyBlocks(code);
        for (const block of blocks) {
          evidence.push({
            file,
            line: block.line,
            snippet: block.snippet,
            detail: `Entropy: ${block.entropy} bits/char (threshold: 5.5)`
          });
        }
        const lines = code.split("\n");
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.trimStart().startsWith("//") || line.trimStart().startsWith("#")) continue;
          for (const { pattern, label } of OBFUSCATION_PATTERNS) {
            if (pattern.test(line)) {
              const alreadyReported = evidence.some((e) => e.file === file && e.line === i + 1);
              if (!alreadyReported) {
                evidence.push({
                  file,
                  line: i + 1,
                  snippet: line.trim().slice(0, 80) + (line.trim().length > 80 ? "..." : ""),
                  detail: `Pattern match: ${label}`
                });
              }
            }
          }
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No obfuscated code blocks detected",
      failed: (n) => `Found ${n} obfuscated code block(s) \u2014 possible obfuscation`
    });
  }
});

// src/checks/skills/skl-003-eval-exec.ts
init_utils();
var skl003 = defineCheck({
  id: "SKL-003",
  name: "Eval/Exec Usage",
  category: "skills",
  severity: "critical",
  description: "Detect eval(), new Function(), exec(), and other dynamic code execution",
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const evidence = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);
    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        const flows = analyzeCode(code, file);
        const execFlows = flows.filter((f) => f.type === "eval-exec");
        for (const flow of execFlows) {
          evidence.push({
            file,
            line: flow.line,
            snippet: flow.snippet,
            detail: flow.description
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No eval/exec usage detected",
      failed: (n) => `Found ${n} dynamic code execution call(s)`
    });
  }
});

// src/analyzers/pattern-engine.ts
var SECURITY_PATTERNS = [
  // Reverse shells (from B@dskills + openclaw-security-monitor)
  { id: "RS-001", pattern: /\b(?:bash|sh|zsh)\s+-i\s+>&?\s*\/dev\/tcp\//i, category: "reverse-shell", severity: "critical", description: "Bash reverse shell pattern" },
  { id: "RS-002", pattern: /\bnc\b.*-e\s+(?:\/bin\/(?:ba)?sh|cmd)/i, category: "reverse-shell", severity: "critical", description: "Netcat reverse shell" },
  { id: "RS-003", pattern: /\bnet\.connect\s*\(.*\bchild_process\b/i, category: "reverse-shell", severity: "critical", description: "Node.js net.connect reverse shell" },
  { id: "RS-004", pattern: /\bnew\s+WebSocket\b.*\bchild_process\b/is, category: "reverse-shell", severity: "critical", description: "WebSocket reverse shell" },
  { id: "RS-005", pattern: /\bSocket\b.*\b(?:subprocess|exec|spawn)\b/i, category: "reverse-shell", severity: "critical", description: "Socket-based reverse shell" },
  { id: "RS-006", pattern: /python\S*\s+-c\s+['"]import\s+socket/i, category: "reverse-shell", severity: "critical", description: "Python reverse shell" },
  { id: "RS-007", pattern: /\bsocat\b.*\bexec:/i, category: "reverse-shell", severity: "critical", description: "Socat reverse shell" },
  // Curl-pipe execution
  { id: "CP-001", pattern: /curl\s+[^|]*\|\s*(?:ba)?sh/i, category: "curl-pipe", severity: "critical", description: "Curl-pipe-shell execution" },
  { id: "CP-002", pattern: /wget\s+[^|]*\|\s*(?:ba)?sh/i, category: "curl-pipe", severity: "critical", description: "Wget-pipe-shell execution" },
  { id: "CP-003", pattern: /curl\s+[^|]*\|\s*python/i, category: "curl-pipe", severity: "critical", description: "Curl-pipe-python execution" },
  // Credential harvesting (from B@dskills)
  { id: "CH-001", pattern: /\/\.ssh\/(?:id_rsa|id_ed25519|authorized_keys|config)/i, category: "credential-harvest", severity: "critical", description: "SSH key access" },
  { id: "CH-002", pattern: /\/\.aws\/credentials/i, category: "credential-harvest", severity: "critical", description: "AWS credentials access" },
  { id: "CH-003", pattern: /\/\.gnupg\//i, category: "credential-harvest", severity: "critical", description: "GPG key access" },
  { id: "CH-004", pattern: /\/\.kube\/config/i, category: "credential-harvest", severity: "critical", description: "Kubernetes config access" },
  { id: "CH-005", pattern: /\/\.docker\/config\.json/i, category: "credential-harvest", severity: "critical", description: "Docker config access" },
  { id: "CH-006", pattern: /\/\.netrc/i, category: "credential-harvest", severity: "warning", description: ".netrc file access" },
  { id: "CH-007", pattern: /\/\.npmrc/i, category: "credential-harvest", severity: "warning", description: ".npmrc file access (may contain auth tokens)" },
  { id: "CH-008", pattern: /keychain|SecItemCopyMatching|security\s+find-generic-password/i, category: "credential-harvest", severity: "critical", description: "macOS Keychain access" },
  // Exfiltration (from openclaw-security-monitor + B@dskills)
  { id: "EX-001", pattern: /\.postMessage\s*\(.*\btransfer\b/i, category: "exfiltration", severity: "warning", description: "postMessage with transfer" },
  { id: "EX-002", pattern: /\bwebhook\b.*\bsend|post\b/i, category: "exfiltration", severity: "warning", description: "Webhook exfiltration pattern" },
  { id: "EX-003", pattern: /dns.*(?:lookup|resolve).*(?:encode|btoa|Buffer)/i, category: "exfiltration", severity: "critical", description: "DNS exfiltration" },
  // Prompt injection indicators
  { id: "PI-001", pattern: /ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions/i, category: "prompt-injection", severity: "warning", description: "Prompt injection \u2014 instruction override" },
  { id: "PI-002", pattern: /you\s+are\s+now\s+(?:a|an|in)\s+/i, category: "prompt-injection", severity: "warning", description: "Prompt injection \u2014 role reassignment" },
  { id: "PI-003", pattern: /system\s*:\s*you\s+(?:must|should|are)/i, category: "prompt-injection", severity: "warning", description: "Prompt injection \u2014 fake system prompt" },
  { id: "PI-004", pattern: /\[SYSTEM\]|\[ADMIN\]|<\|system\|>/i, category: "prompt-injection", severity: "warning", description: "Prompt injection \u2014 delimiter escape" },
  // Crypto wallet targeting (from openclaw-security-monitor)
  { id: "CW-001", pattern: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/, category: "crypto-wallet", severity: "warning", description: "Bitcoin address pattern" },
  { id: "CW-002", pattern: /\b0x[0-9a-fA-F]{40}\b/, category: "crypto-wallet", severity: "warning", description: "Ethereum address pattern" },
  { id: "CW-003", pattern: /\bcoinbase\b.*\bapi|key|secret\b/i, category: "crypto-wallet", severity: "warning", description: "Coinbase API access" },
  // Obfuscation indicators (from Sclawhub)
  { id: "OB-001", pattern: /\bBuffer\.from\s*\([^,]+,\s*['"]base64['"]\)/i, category: "obfuscation", severity: "warning", description: "Base64 decode operation" },
  { id: "OB-002", pattern: /\batob\s*\(/i, category: "obfuscation", severity: "warning", description: "atob decode" },
  { id: "OB-003", pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}/i, category: "obfuscation", severity: "warning", description: "Hex-encoded string (6+ bytes)" },
  { id: "OB-004", pattern: /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}/i, category: "obfuscation", severity: "warning", description: "Unicode-encoded string (6+ chars)" },
  // Code execution (from Sclawhub)
  { id: "CE-001", pattern: /\beval\s*\(/i, category: "code-exec", severity: "critical", description: "eval() usage" },
  { id: "CE-002", pattern: /\bnew\s+Function\s*\(/i, category: "code-exec", severity: "critical", description: "new Function() constructor" },
  { id: "CE-003", pattern: /child_process.*\b(?:exec|execSync|spawn|spawnSync)\b/i, category: "code-exec", severity: "critical", description: "child_process execution" },
  { id: "CE-004", pattern: /\brequire\s*\(\s*['"]child_process['"]\s*\)/i, category: "code-exec", severity: "critical", description: "child_process require" }
];
function scanWithPatterns(code, rules) {
  const patterns = rules ?? SECURITY_PATTERNS;
  const matches = [];
  const lines = code.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trimStart();
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
    for (const rule of patterns) {
      if (rule.pattern.test(line)) {
        matches.push({
          pattern: rule.id,
          category: rule.category,
          line: i + 1,
          snippet: line.trim().slice(0, 120),
          severity: rule.severity,
          description: rule.description
        });
      }
    }
  }
  return matches;
}

// src/checks/skills/skl-004-curl-pipe.ts
init_utils();
var CURL_PIPE_RULES = SECURITY_PATTERNS.filter((r) => r.category === "curl-pipe");
var skl004 = defineCheck({
  id: "SKL-004",
  name: "Curl-Pipe Execution",
  category: "skills",
  severity: "critical",
  description: "Detect curl|sh, wget|bash, and similar pipe-to-shell execution",
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const evidence = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);
    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        const matches = scanWithPatterns(code, CURL_PIPE_RULES);
        for (const match of matches) {
          evidence.push({
            file,
            line: match.line,
            snippet: match.snippet,
            detail: match.description
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No curl-pipe execution patterns detected",
      failed: (n) => `Found ${n} curl-pipe execution pattern(s)`
    });
  }
});

// src/checks/skills/skl-005-reverse-shell.ts
init_utils();
var REVERSE_SHELL_RULES = SECURITY_PATTERNS.filter((r) => r.category === "reverse-shell");
var skl005 = defineCheck({
  id: "SKL-005",
  name: "Reverse Shell Patterns",
  category: "skills",
  severity: "critical",
  description: "Detect reverse shell patterns (Bash, netcat, Node.js, Python, etc.)",
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const evidence = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);
    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        const matches = scanWithPatterns(code, REVERSE_SHELL_RULES);
        for (const match of matches) {
          evidence.push({
            file,
            line: match.line,
            snippet: match.snippet,
            detail: match.description
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No reverse shell patterns detected",
      failed: (n) => `Found ${n} reverse shell pattern(s)`
    });
  }
});

// src/checks/skills/skl-006-credential-harvesting.ts
init_utils();
var CRED_HARVEST_RULES = SECURITY_PATTERNS.filter((r) => r.category === "credential-harvest");
var skl006 = defineCheck({
  id: "SKL-006",
  name: "Credential Harvesting",
  category: "skills",
  severity: "critical",
  description: "Detect access to .ssh, .aws, .env, and other credential stores",
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const evidence = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);
    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        const matches = scanWithPatterns(code, CRED_HARVEST_RULES);
        for (const match of matches) {
          evidence.push({
            file,
            line: match.line,
            snippet: match.snippet,
            detail: match.description
          });
        }
        const flows = analyzeCode(code, file);
        const fsAccess2 = flows.filter((f) => f.type === "fs-access");
        for (const flow of fsAccess2) {
          evidence.push({
            file,
            line: flow.line,
            snippet: flow.snippet,
            detail: flow.description
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No credential harvesting patterns detected",
      failed: (n) => `Found ${n} credential harvesting indicator(s)`
    });
  }
});

// src/checks/skills/skl-007-prompt-injection.ts
import { join as join31, extname as extname3 } from "path";
var DOC_EXTENSIONS = /* @__PURE__ */ new Set([".md", ".txt", ".rst"]);
var PROMPT_INJECTION_RULES = SECURITY_PATTERNS.filter((r) => r.category === "prompt-injection");
async function getDocFiles(dir, fs) {
  const files = [];
  try {
    const entries = await fs.readdirEntries(dir, { recursive: true });
    for (const entry of entries) {
      if (entry.isFile) {
        const ext = extname3(entry.name);
        const name = entry.name.toUpperCase();
        if (DOC_EXTENSIONS.has(ext) || name === "SKILL.MD" || name === "README.MD") {
          const fullPath = entry.parentPath ? join31(entry.parentPath, entry.name) : join31(dir, entry.name);
          files.push(fullPath);
        }
      }
    }
  } catch {
  }
  return files;
}
var skl007 = defineCheck({
  id: "SKL-007",
  name: "Prompt Injection in SKILL.md",
  category: "skills",
  severity: "warning",
  description: "Detect prompt injection patterns in skill documentation files",
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const evidence = [];
    const files = await getDocFiles(skillsDir, ctx.fs);
    for (const file of files) {
      try {
        const content = await ctx.fs.readFile(file);
        const matches = scanWithPatterns(content, PROMPT_INJECTION_RULES);
        for (const match of matches) {
          evidence.push({
            file,
            line: match.line,
            snippet: match.snippet,
            detail: match.description
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No prompt injection patterns found in skill docs",
      failed: (n) => `Found ${n} prompt injection pattern(s) in skill documentation`
    });
  }
});

// src/checks/skills/skl-008-suspicious-network.ts
init_utils();
var skl008 = defineCheck({
  id: "SKL-008",
  name: "Suspicious Network Calls",
  category: "skills",
  severity: "warning",
  description: "Detect non-localhost, non-HTTPS network calls",
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const evidence = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);
    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        const flows = analyzeCode(code, file);
        const suspicious = flows.filter((f) => f.type === "suspicious-network");
        for (const flow of suspicious) {
          evidence.push({
            file,
            line: flow.line,
            snippet: flow.snippet,
            detail: flow.description
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No suspicious network calls detected",
      failed: (n) => `Found ${n} suspicious network call(s)`
    });
  }
});

// src/checks/skills/skl-009-crypto-wallet.ts
init_utils();
var CRYPTO_RULES = SECURITY_PATTERNS.filter((r) => r.category === "crypto-wallet");
var skl009 = defineCheck({
  id: "SKL-009",
  name: "Crypto Wallet Targeting",
  category: "skills",
  severity: "warning",
  description: "Detect crypto wallet address patterns and API targeting",
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const evidence = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);
    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        const matches = scanWithPatterns(code, CRYPTO_RULES);
        for (const match of matches) {
          evidence.push({
            file,
            line: match.line,
            snippet: match.snippet,
            detail: match.description
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No crypto wallet targeting patterns detected",
      failed: (n) => `Found ${n} crypto wallet targeting pattern(s)`
    });
  }
});

// src/checks/skills/skl-010-unauthorized-fs.ts
init_utils();
var skl010 = defineCheck({
  id: "SKL-010",
  name: "Unauthorized FS Access",
  category: "skills",
  severity: "warning",
  description: "Detect file operations accessing paths outside the workspace",
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const evidence = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);
    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        const flows = analyzeCode(code, file);
        const fsAccess2 = flows.filter((f) => f.type === "fs-access");
        for (const flow of fsAccess2) {
          evidence.push({
            file,
            line: flow.line,
            snippet: flow.snippet,
            detail: flow.description
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No unauthorized filesystem access detected",
      failed: (n) => `Found ${n} unauthorized filesystem access(es)`
    });
  }
});

// src/checks/skills/skl-011-dependency-audit.ts
import { join as join33 } from "path";
init_database();
var MALICIOUS_PACKAGES = /* @__PURE__ */ new Set([
  "event-stream",
  "flatmap-stream",
  "ua-parser-js",
  "coa",
  "rc",
  "colors",
  "faker",
  "node-ipc",
  "peacenotwar",
  "es5-ext"
]);
var LOCKFILES = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"];
var skl011 = defineCheck({
  id: "SKL-011",
  name: "Dependency Audit",
  category: "skills",
  severity: "warning",
  description: "Check skill package.json dependencies against known malicious packages and verify lockfile presence",
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const db = getIOCDatabase();
    let entries;
    try {
      entries = await ctx.fs.readdirEntries(skillsDir);
    } catch {
      return h.passed("Skills directory not accessible");
    }
    const evidence = [];
    for (const entry of entries) {
      if (!entry.isDirectory) continue;
      const skillDir = entry.parentPath ? join33(entry.parentPath, entry.name) : join33(skillsDir, entry.name);
      const pkgPath = join33(skillDir, "package.json");
      let pkgData;
      try {
        const raw = await ctx.fs.readFile(pkgPath);
        pkgData = JSON.parse(raw);
      } catch {
        continue;
      }
      const allDeps = {
        ...pkgData.dependencies ?? {},
        ...pkgData.devDependencies ?? {}
      };
      const depNames = Object.keys(allDeps);
      if (depNames.length === 0) continue;
      for (const dep of depNames) {
        if (MALICIOUS_PACKAGES.has(dep)) {
          evidence.push({
            file: pkgPath,
            detail: `Known malicious package: ${dep}`
          });
        }
        const scopeMatch = dep.match(/^@([^/]+)\//);
        if (scopeMatch && db.maliciousPublishers.includes(scopeMatch[1])) {
          evidence.push({
            file: pkgPath,
            detail: `Package from malicious publisher: ${dep}`
          });
        }
      }
      let hasLockfile = false;
      for (const lockfile of LOCKFILES) {
        if (await ctx.fs.access(join33(skillDir, lockfile))) {
          hasLockfile = true;
          break;
        }
      }
      if (!hasLockfile) {
        evidence.push({
          file: pkgPath,
          detail: "No lockfile found (package-lock.json, yarn.lock, or pnpm-lock.yaml) \u2014 dependencies not pinned"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All skill dependencies are clean",
      failed: (n) => `Found ${n} dependency issue(s)`
    });
  }
});

// src/checks/skills/skl-012-code-complexity.ts
import { parse as parse3 } from "@babel/parser";
import _traverse2 from "@babel/traverse";
init_utils();
var traverse2 = typeof _traverse2 === "function" ? _traverse2 : _traverse2.default;
var COMPLEXITY_THRESHOLD = 15;
var DECISION_NODES = /* @__PURE__ */ new Set([
  "IfStatement",
  "ConditionalExpression",
  "SwitchCase",
  "ForStatement",
  "ForInStatement",
  "ForOfStatement",
  "WhileStatement",
  "DoWhileStatement",
  "CatchClause",
  "LogicalExpression"
]);
var skl012 = defineCheck({
  id: "SKL-012",
  name: "Code Complexity",
  category: "skills",
  severity: "info",
  description: "Measure cyclomatic complexity per function via Babel AST; flag functions exceeding threshold",
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const evidence = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);
    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        let ast;
        try {
          ast = parse3(code, {
            sourceType: "unambiguous",
            plugins: ["typescript", "jsx", "decorators"],
            errorRecovery: true
          });
        } catch {
          continue;
        }
        traverse2(ast, {
          "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression|ObjectMethod"(path) {
            let complexity = 1;
            path.traverse({
              enter(innerPath) {
                if (DECISION_NODES.has(innerPath.node.type)) {
                  complexity++;
                }
              }
            });
            if (complexity > COMPLEXITY_THRESHOLD) {
              const node = path.node;
              const id = node.id;
              const key = node.key;
              const funcName = id?.name ?? (key && "name" in key ? key.name : void 0) ?? "<anonymous>";
              const line = path.node.loc?.start.line ?? 0;
              evidence.push({
                file,
                line,
                detail: `Function "${funcName}" has cyclomatic complexity ${complexity} (threshold: ${COMPLEXITY_THRESHOLD})`
              });
            }
          }
        });
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All functions are within complexity threshold",
      failed: (n) => `Found ${n} function(s) exceeding complexity threshold of ${COMPLEXITY_THRESHOLD}`
    });
  }
});

// src/checks/skills/skl-013-symlink-escape.ts
import { isAbsolute, join as join34, resolve, relative as relative2, dirname as dirname3 } from "path";
init_utils();

// src/analyzers/sensitive-paths.ts
var SENSITIVE_SINKS = [
  { re: /(^|\/)\.ssh(\/|$)/i, label: "SSH keys/config (~/.ssh)" },
  { re: /authorized_keys/i, label: "SSH authorized_keys (remote-access persistence)" },
  { re: /(^|\/)\.aws(\/|$)/i, label: "AWS credentials (~/.aws)" },
  { re: /(^|\/)\.gnupg(\/|$)/i, label: "GnuPG keyring (~/.gnupg)" },
  { re: /(^|\/)\.kube(\/|$)/i, label: "Kubernetes credentials (~/.kube)" },
  { re: /(^|\/)\.docker(\/|$)/i, label: "Docker credentials (~/.docker)" },
  { re: /(^|\/)\.(bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|zlogin)$/i, label: "shell startup file (code-execution persistence)" },
  { re: /^\/etc(\/|$)/i, label: "system configuration (/etc)" }
];
function classifySensitivePath(path) {
  if (!path || path.startsWith("-")) return [];
  return SENSITIVE_SINKS.filter((s) => s.re.test(path)).map((s) => s.label);
}

// src/checks/skills/skl-013-symlink-escape.ts
function resolveTarget(rawTarget, linkDir, home) {
  let t = rawTarget;
  if (t === "~" || t.startsWith("~/")) {
    t = join34(home, t.slice(1));
  }
  if (isAbsolute(t)) return resolve(t);
  return resolve(linkDir, t);
}
function escapesRoot(root, resolvedTarget) {
  const rel = relative2(root, resolvedTarget);
  return rel === "" ? false : rel.startsWith("..") || isAbsolute(rel);
}
var skl013 = defineCheck({
  id: "SKL-013",
  name: "Workspace Symlink Escape",
  category: "skills",
  severity: "critical",
  description: "Detect symlinks in a skill/workspace directory that resolve outside it (GhostApproval / CWE-61), especially to credential stores or shell startup files",
  async run(ctx, h) {
    const dirs = getAllSkillsDirs(ctx.installation);
    if (dirs.length === 0) return h.passed("No skills/workspace directory to scan for symlinks");
    if (typeof ctx.fs.readlink !== "function") {
      return h.passed("Symlink status unavailable for this scan source");
    }
    const findings = [];
    const seen = /* @__PURE__ */ new Set();
    for (const dir of dirs) {
      const root = resolve(dir);
      let entries;
      try {
        entries = await ctx.fs.readdirEntries(dir, { recursive: true });
      } catch {
        continue;
      }
      for (const entry of entries) {
        if (!entry.isSymbolicLink) continue;
        const linkPath = entry.parentPath ? join34(entry.parentPath, entry.name) : join34(dir, entry.name);
        if (seen.has(linkPath)) continue;
        seen.add(linkPath);
        let rawTarget;
        try {
          rawTarget = await ctx.fs.readlink(linkPath);
        } catch {
          continue;
        }
        const resolvedTarget = resolveTarget(rawTarget, dirname3(linkPath), ctx.fs.homedir());
        if (!escapesRoot(root, resolvedTarget)) continue;
        const sensitiveLabels = [
          .../* @__PURE__ */ new Set([
            ...classifySensitivePath(resolvedTarget),
            ...classifySensitivePath(rawTarget)
          ])
        ];
        findings.push({ linkPath, rawTarget, resolvedTarget, sensitiveLabels });
      }
    }
    if (findings.length === 0) {
      return h.passed("No symlinks escape the scanned workspace directory");
    }
    const anySensitive = findings.some((f) => f.sensitiveLabels.length > 0);
    const evidence = findings.map((f) => ({
      file: f.linkPath,
      snippet: `${f.linkPath} \u2192 ${f.rawTarget}`,
      detail: f.sensitiveLabels.length > 0 ? `Symlink resolves outside the workspace to ${f.sensitiveLabels.join(", ")} (${f.resolvedTarget}). An agent instructed to edit this "local" file writes to the sensitive target instead \u2014 GhostApproval-style informed-consent bypass.` : `Symlink resolves outside the workspace to ${f.resolvedTarget}. A write the user believes is workspace-local lands outside the project.`
    }));
    const severity = anySensitive ? "critical" : "warning";
    const sensitiveCount = findings.filter((f) => f.sensitiveLabels.length > 0).length;
    return h.result({
      passed: false,
      severity,
      message: anySensitive ? `${findings.length} workspace symlink(s) escape the directory, ${sensitiveCount} reaching credential stores or shell startup files` : `${findings.length} workspace symlink(s) resolve outside the scanned directory`,
      evidence,
      fixDescription: "Remove or replace out-of-workspace symlinks; never let an agent write to a path it presents as workspace-local. Prefer a coding agent that resolves symlinks and warns before writing outside the project."
    });
  }
});

// src/checks/skills/index.ts
var skillChecks = [
  skl001,
  skl002,
  skl003,
  skl004,
  skl005,
  skl006,
  skl007,
  skl008,
  skl009,
  skl010,
  skl011,
  skl012,
  skl013
];

// src/checks/ioc/ioc-001-c2-ips.ts
import { join as join35, extname as extname4 } from "path";
init_database();
init_utils();

// src/checks/ioc/boundary.ts
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function ipBoundaryRegex(ip) {
  return new RegExp(`(?<![\\d.])${escapeRegex(ip)}(?![\\d.])`);
}
function domainBoundaryRegex(domain) {
  return new RegExp(`(?<![a-zA-Z0-9-])${escapeRegex(domain)}(?![a-zA-Z0-9.-])`, "i");
}

// src/checks/ioc/ioc-001-c2-ips.ts
var SCAN_EXTENSIONS = /* @__PURE__ */ new Set([".js", ".ts", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".env", ".sh"]);
async function getAllFilesViaCtx(ctx, dirs) {
  const files = [];
  for (const dir of dirs) {
    try {
      const entries = await ctx.fs.readdirEntries(dir, { recursive: true });
      for (const entry of entries) {
        if (entry.isFile && SCAN_EXTENSIONS.has(extname4(entry.name))) {
          const fullPath = entry.parentPath ? join35(entry.parentPath, entry.name) : join35(dir, entry.name);
          files.push(fullPath);
        }
      }
    } catch {
    }
  }
  return files;
}
var ioc001 = defineCheck({
  id: "IOC-001",
  name: "C2 IP Detection",
  category: "ioc",
  severity: "critical",
  description: "Scan code and configs for known C2 (command and control) IP addresses",
  async run(ctx, h) {
    const evidence = [];
    const db = getIOCDatabase();
    const dirs = [ctx.installation.installDir, ...getAllSkillsDirs(ctx.installation)];
    const ipRegexes = db.c2Ips.map((ip) => ({ ip, re: ipBoundaryRegex(ip) }));
    const scan = (file, content) => {
      for (const { ip, re } of ipRegexes) {
        if (!re.test(content)) continue;
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (re.test(lines[i])) {
            evidence.push({
              file,
              line: i + 1,
              snippet: lines[i].trim(),
              detail: `Known C2 IP: ${ip}`
            });
          }
        }
      }
    };
    for (const config of ctx.configs) {
      scan(config.filePath, config.raw);
    }
    const files = await getAllFilesViaCtx(ctx, dirs);
    for (const file of files) {
      try {
        scan(file, await ctx.fs.readFile(file));
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No known C2 IP addresses found",
      failed: (n) => `Found ${n} reference(s) to known C2 IP addresses`
    });
  }
});

// src/checks/ioc/ioc-002-malicious-domains.ts
import { join as join36, extname as extname5 } from "path";
init_database();
init_utils();
var SCAN_EXTENSIONS2 = /* @__PURE__ */ new Set([".js", ".ts", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".env", ".sh", ".md"]);
async function getAllFilesViaCtx2(ctx, dirs) {
  const files = [];
  for (const dir of dirs) {
    try {
      const entries = await ctx.fs.readdirEntries(dir, { recursive: true });
      for (const entry of entries) {
        if (entry.isFile && SCAN_EXTENSIONS2.has(extname5(entry.name))) {
          const fullPath = entry.parentPath ? join36(entry.parentPath, entry.name) : join36(dir, entry.name);
          files.push(fullPath);
        }
      }
    } catch {
    }
  }
  return files;
}
var ioc002 = defineCheck({
  id: "IOC-002",
  name: "Malicious Domains",
  category: "ioc",
  severity: "critical",
  description: "Scan for known malicious domains in code and configs",
  async run(ctx, h) {
    const evidence = [];
    const db = getIOCDatabase();
    const dirs = [ctx.installation.installDir, ...getAllSkillsDirs(ctx.installation)];
    const domainRegexes = db.maliciousDomains.map((domain) => ({
      domain,
      re: domainBoundaryRegex(domain)
    }));
    const allContent = [];
    for (const config of ctx.configs) {
      allContent.push({ file: config.filePath, content: config.raw });
    }
    const files = await getAllFilesViaCtx2(ctx, dirs);
    for (const file of files) {
      try {
        allContent.push({ file, content: await ctx.fs.readFile(file) });
      } catch {
      }
    }
    for (const { file, content } of allContent) {
      for (const { domain, re } of domainRegexes) {
        if (!re.test(content)) continue;
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (re.test(lines[i])) {
            evidence.push({
              file,
              line: i + 1,
              snippet: lines[i].trim(),
              detail: `Known malicious domain: ${domain}`
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No known malicious domains found",
      failed: (n) => `Found ${n} reference(s) to known malicious domains`
    });
  }
});

// src/checks/ioc/ioc-003-file-hash.ts
import { createHash } from "crypto";
init_database();
init_utils();
var ioc003 = defineCheck({
  id: "IOC-003",
  name: "File Hash Match",
  category: "ioc",
  severity: "critical",
  description: "SHA-256 hash skill files and compare against known malicious hashes",
  async run(ctx, h) {
    const evidence = [];
    const db = getIOCDatabase();
    const hashSet = new Set(db.fileHashes);
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);
    for (const file of files) {
      try {
        const content = await ctx.fs.readFile(file);
        const hash = createHash("sha256").update(content).digest("hex");
        if (hashSet.has(hash)) {
          evidence.push({
            file,
            detail: `SHA-256 hash matches known malicious file: ${hash}`
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No known malicious file hashes found",
      failed: (n) => `Found ${n} file(s) matching known malicious hashes`
    });
  }
});

// src/checks/ioc/ioc-004-malicious-publishers.ts
import { join as join37 } from "path";
init_database();
var ioc004 = defineCheck({
  id: "IOC-004",
  name: "Malicious Publishers",
  category: "ioc",
  severity: "critical",
  description: "Check skill metadata for known malicious publishers",
  async run(ctx, h) {
    const evidence = [];
    const db = getIOCDatabase();
    const publisherSet = new Set(db.maliciousPublishers.map((p) => p.toLowerCase()));
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    try {
      const entries = await ctx.fs.readdirEntries(skillsDir);
      for (const entry of entries) {
        if (!entry.isDirectory) continue;
        const metadataFiles = ["package.json", "skill.json", "metadata.json"];
        for (const metaFile of metadataFiles) {
          const metaPath = join37(skillsDir, entry.name, metaFile);
          try {
            const content = await ctx.fs.readFile(metaPath);
            const data = JSON.parse(content);
            const author = (data.author?.name ?? data.author ?? data.publisher ?? "").toLowerCase();
            if (publisherSet.has(author)) {
              evidence.push({
                file: metaPath,
                detail: `Skill "${entry.name}" by known malicious publisher: ${author}`
              });
            }
          } catch {
          }
        }
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "No known malicious publishers found",
      failed: (n) => `Found ${n} skill(s) from known malicious publishers`
    });
  }
});

// src/checks/ioc/ioc-005-typosquatting.ts
init_database();

// src/ioc/typosquat.ts
function levenshteinDistance(a, b) {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        // deletion
        dp[i][j - 1] + 1,
        // insertion
        dp[i - 1][j - 1] + cost
        // substitution
      );
    }
  }
  return dp[m][n];
}
function detectTyposquatting(skillName, trustedNames, maxDistance = 2) {
  const normalized = skillName.toLowerCase().replace(/[-_]/g, "");
  for (const trusted of trustedNames) {
    const normalizedTrusted = trusted.toLowerCase().replace(/[-_]/g, "");
    if (normalized === normalizedTrusted) continue;
    const distance = levenshteinDistance(normalized, normalizedTrusted);
    if (distance > 0 && distance <= maxDistance) {
      return { skillName, trustedName: trusted, distance };
    }
  }
  return null;
}

// src/checks/ioc/ioc-005-typosquatting.ts
var ioc005 = defineCheck({
  id: "IOC-005",
  name: "Typosquatting",
  category: "ioc",
  severity: "warning",
  description: "Detect skills with names similar to trusted ones (Levenshtein distance <= 2)",
  async run(ctx, h) {
    const evidence = [];
    const db = getIOCDatabase();
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    try {
      const entries = await ctx.fs.readdirEntries(skillsDir);
      for (const entry of entries) {
        if (!entry.isDirectory) continue;
        const match = detectTyposquatting(entry.name, db.trustedSkillNames);
        if (match) {
          evidence.push({
            file: skillsDir,
            detail: `Skill "${match.skillName}" is similar to trusted "${match.trustedName}" (distance: ${match.distance})`
          });
        }
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "No typosquatting detected",
      failed: (n) => `Found ${n} potential typosquat(s)`
    });
  }
});

// src/checks/ioc/ioc-006-skill-name-patterns.ts
init_database();
var ioc006 = defineCheck({
  id: "IOC-006",
  name: "Skill Name Patterns",
  category: "ioc",
  severity: "warning",
  description: "Match skill names against known malicious naming patterns",
  async run(ctx, h) {
    const evidence = [];
    const db = getIOCDatabase();
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    try {
      const entries = await ctx.fs.readdirEntries(skillsDir);
      for (const entry of entries) {
        if (!entry.isDirectory) continue;
        for (const pattern of db.maliciousSkillPatterns) {
          if (pattern.test(entry.name)) {
            evidence.push({
              file: skillsDir,
              detail: `Skill "${entry.name}" matches malicious name pattern: ${pattern.source}`
            });
            break;
          }
        }
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "No malicious skill name patterns detected",
      failed: (n) => `Found ${n} skill(s) with suspicious names`
    });
  }
});

// src/checks/ioc/ioc-007-binary-patterns.ts
init_database();
init_utils();
function bytesStartWith(haystack, needle) {
  if (haystack.length < needle.length) return false;
  for (let i = 0; i < needle.length; i++) {
    if (haystack[i] !== needle[i]) return false;
  }
  return true;
}
var ioc007 = defineCheck({
  id: "IOC-007",
  name: "Binary Pattern Match",
  category: "ioc",
  severity: "critical",
  description: "YARA-like byte/regex patterns on skill files (ELF/MachO/PE headers anchored at offset 0; shellcode / packed JS via regex)",
  async run(ctx, h) {
    const evidence = [];
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const db = getIOCDatabase();
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);
    for (const file of files) {
      let matched;
      const bufferPatterns = db.binaryPatterns.filter((bp) => bp.type === "buffer");
      if (bufferPatterns.length > 0) {
        try {
          const bytes = await ctx.fs.readBytes(file);
          for (const bp of bufferPatterns) {
            if (bytesStartWith(bytes, bp.pattern)) {
              matched = { name: bp.name };
              break;
            }
          }
        } catch {
        }
      }
      if (!matched) {
        const regexPatterns = db.binaryPatterns.filter((bp) => bp.type === "regex");
        if (regexPatterns.length > 0) {
          try {
            const content = await ctx.fs.readFile(file);
            for (const bp of regexPatterns) {
              if (bp.pattern.test(content)) {
                matched = { name: bp.name };
                break;
              }
            }
          } catch {
          }
        }
      }
      if (matched) {
        evidence.push({
          file,
          detail: `Binary pattern matched: ${matched.name}`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No suspicious binary patterns found in skill files",
      failed: (n) => `Found ${n} file(s) with suspicious binary patterns`
    });
  }
});

// src/checks/ioc/ioc-008-virustotal.ts
import { createHash as createHash2 } from "crypto";
init_utils();
var ioc008 = defineCheck({
  id: "IOC-008",
  name: "VirusTotal Cross-Reference",
  category: "ioc",
  severity: "critical",
  description: "SHA-256 hash skill files and check against VirusTotal API (opt-in via VIRUSTOTAL_API_KEY)",
  async run(ctx, h) {
    const apiKey = process.env["VIRUSTOTAL_API_KEY"];
    if (!apiKey) return h.passed("VirusTotal check skipped \u2014 no VIRUSTOTAL_API_KEY set");
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed("No skills directory found");
    const evidence = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);
    for (const file of files) {
      try {
        const content = await ctx.fs.readFile(file);
        const hash = createHash2("sha256").update(content).digest("hex");
        const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
          headers: { "x-apikey": apiKey }
        });
        if (response.status === 200) {
          const data = await response.json();
          const malicious = data?.data?.attributes?.last_analysis_stats?.malicious ?? 0;
          if (malicious > 0) {
            evidence.push({
              file,
              detail: `VirusTotal: ${malicious} engine(s) flagged this file as malicious (SHA-256: ${hash})`
            });
          }
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No skill files flagged by VirusTotal",
      failed: (n) => `${n} file(s) flagged as malicious by VirusTotal`
    });
  }
});

// src/checks/ioc/index.ts
var iocChecks = [
  ioc001,
  ioc002,
  ioc003,
  ioc004,
  ioc005,
  ioc006,
  ioc007,
  ioc008
];

// src/checks/network/net-001-gateway-exposure.ts
init_types();
var net001 = defineCheck({
  id: "NET-001",
  name: "Gateway Internet Exposure",
  category: "network",
  severity: "critical",
  description: "Check if the gateway is bound to a public address",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    const gw = ctx.installation.gateway;
    if (!gw?.host) return h.passed("No gateway configured");
    const publicBind = gw.host === "0.0.0.0" || gw.host === "::";
    return h.result({
      passed: !publicBind,
      message: publicBind ? `Gateway bound to ${gw.host}:${gw.port ?? "?"} \u2014 exposed to all network interfaces` : `Gateway bound to ${gw.host} \u2014 not publicly exposed`
    });
  }
});

// src/checks/network/net-002-websocket-origin.ts
init_types();
init_utils();
var net002 = defineCheck({
  id: "NET-002",
  name: "WebSocket Origin Validation",
  category: "network",
  severity: "critical",
  description: "Check if WebSocket connections validate the Origin header (CVE-2026-25253)",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const wsOrigin = getNestedValue(config.data, "websocket.validateOrigin") ?? getNestedValue(config.data, "ws.checkOrigin") ?? getNestedValue(config.data, "gateway.websocket.origin");
      if (wsOrigin === false || wsOrigin === "disabled") {
        evidence.push({ file: config.filePath, detail: "WebSocket origin validation is disabled" });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "WebSocket origin validation is not explicitly disabled",
      failed: () => "WebSocket origin validation is disabled \u2014 vulnerable to cross-origin attacks (CVE-2026-25253)"
    });
  }
});

// src/checks/network/net-003-reverse-proxy.ts
init_types();
init_utils();
var net003 = defineCheck({
  id: "NET-003",
  name: "Reverse Proxy Bypass",
  category: "network",
  severity: "warning",
  description: "Check if trusted-proxy is set without proper IP restriction",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const trustProxy = getNestedValue(config.data, "trustProxy") ?? getNestedValue(config.data, "gateway.trustProxy") ?? getNestedValue(config.data, "proxy.trust");
      if (trustProxy === true || trustProxy === "all") {
        evidence.push({ file: config.filePath, detail: `trustProxy: ${String(trustProxy)}` });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No unrestricted proxy trust detected",
      failed: () => "Trusted proxy is set to trust all \u2014 IP spoofing via X-Forwarded-For is possible"
    });
  }
});

// src/checks/network/net-004-port-scan.ts
import { createConnection } from "net";
init_types();
var AGENT_PORTS = [18789, 18790, 3e3, 8080, 8443];
function checkPort(host, port, timeout = 1e3) {
  return new Promise((resolve6) => {
    const socket = createConnection({ host, port });
    socket.setTimeout(timeout);
    socket.on("connect", () => {
      socket.destroy();
      resolve6(true);
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve6(false);
    });
    socket.on("error", () => {
      socket.destroy();
      resolve6(false);
    });
  });
}
var net004 = defineCheck({
  id: "NET-004",
  name: "Agent Service Port Scan",
  category: "network",
  severity: "info",
  description: "Check for agent services listening on known ports",
  excludedAgents: CODING_AGENTS,
  async run(_ctx, h) {
    const evidence = [];
    await Promise.allSettled(
      AGENT_PORTS.map(async (port) => {
        const open = await checkPort("127.0.0.1", port);
        if (open) {
          evidence.push({ file: "localhost", detail: `Port ${port} is open on localhost` });
        }
      })
    );
    return h.result({
      passed: true,
      message: evidence.length === 0 ? "No agent services detected on known ports" : `Found ${evidence.length} open agent port(s)`,
      evidence
    });
  }
});

// src/checks/network/net-005-active-connections.ts
init_types();
init_database();
var IP_REGEX = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;
var net005 = defineCheck({
  id: "NET-005",
  name: "Active Connection Monitoring",
  category: "network",
  severity: "critical",
  description: "Check active network connections against known C2 IP addresses",
  excludedAgents: CODING_AGENTS,
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    const db = getIOCDatabase();
    const c2Set = new Set(db.c2Ips);
    let output = "";
    try {
      if (ctx.platform === "darwin") {
        output = ctx.fs.execSync("netstat", ["-an", "-p", "tcp"], { timeout: 5e3 });
      } else {
        output = ctx.fs.execSync("ss", ["-tn"], { timeout: 5e3 });
      }
    } catch {
      return h.passed("Could not retrieve active connections");
    }
    const lines = output.split("\n");
    for (const line of lines) {
      const lower = line.toLowerCase();
      if (!lower.includes("established") && !lower.includes("estab")) continue;
      const ips = line.match(IP_REGEX);
      if (!ips) continue;
      for (const ip of ips) {
        if (c2Set.has(ip)) {
          evidence.push({
            file: "netstat",
            snippet: line.trim().slice(0, 120),
            detail: `Active connection to known C2 IP: ${ip}`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No active connections to known C2 IP addresses",
      failed: (n) => `Found ${n} active connection(s) to known C2 IP addresses`
    });
  }
});

// src/checks/network/index.ts
var networkChecks = [
  net001,
  net002,
  net003,
  net004,
  net005
];

// src/checks/runtime/run-001-launch-agents.ts
import { join as join38 } from "path";
init_types();
var SUSPICIOUS_KEYWORDS = [
  "claw",
  // catches openclaw, nanoclaw, picoclaw, ironclaw, zeroclaw, nemoclaw, clawdbot
  "nanobot",
  "moltbot",
  "hermes-agent"
  // specific enough to avoid Facebook Hermes / unrelated tooling
];
var run001 = defineCheck({
  id: "RUN-001",
  name: "Unauthorized LaunchAgents",
  category: "runtime",
  severity: "warning",
  description: "Check for unauthorized LaunchAgents (macOS) or systemd services (Linux) referencing agents",
  excludedAgents: CODING_AGENTS,
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    if (ctx.platform === "darwin") {
      const home = ctx.fs.homedir();
      const launchDirs = [
        join38(home, "Library", "LaunchAgents"),
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons"
      ];
      for (const dir of launchDirs) {
        try {
          const entries = await ctx.fs.readdir(dir);
          for (const entry of entries) {
            const lower = entry.toLowerCase();
            for (const keyword of SUSPICIOUS_KEYWORDS) {
              if (lower.includes(keyword)) {
                const filePath = join38(dir, entry);
                let detail = `LaunchAgent references "${keyword}"`;
                try {
                  const content = await ctx.fs.readFile(filePath);
                  if (content.includes("ProgramArguments")) {
                    detail += ` \u2014 has ProgramArguments`;
                  }
                } catch {
                }
                evidence.push({ file: filePath, detail });
                break;
              }
            }
          }
        } catch {
        }
      }
    }
    if (ctx.platform === "linux") {
      const home = ctx.fs.homedir();
      const systemdDirs = [
        join38(home, ".config", "systemd", "user"),
        "/etc/systemd/system"
      ];
      for (const dir of systemdDirs) {
        try {
          const entries = await ctx.fs.readdir(dir);
          for (const entry of entries) {
            const lower = entry.toLowerCase();
            for (const keyword of SUSPICIOUS_KEYWORDS) {
              if (lower.includes(keyword)) {
                evidence.push({
                  file: join38(dir, entry),
                  detail: `Systemd service references "${keyword}"`
                });
                break;
              }
            }
          }
        } catch {
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No suspicious persistence mechanisms found",
      failed: (n) => `Found ${n} suspicious persistence mechanism(s)`
    });
  }
});

// src/checks/runtime/run-002-suspicious-cron.ts
init_types();
var SUSPICIOUS_KEYWORDS2 = [
  "claw",
  "nanobot",
  "moltbot",
  "hermes-agent"
];
var run002 = defineCheck({
  id: "RUN-002",
  name: "Suspicious Cron Entries",
  category: "runtime",
  severity: "warning",
  description: "Check for cron entries referencing agent paths",
  excludedAgents: CODING_AGENTS,
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    try {
      const crontab = ctx.fs.execSync("crontab", ["-l"], { timeout: 5e3 });
      const lines = crontab.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith("#")) continue;
        const lower = line.toLowerCase();
        for (const keyword of SUSPICIOUS_KEYWORDS2) {
          if (lower.includes(keyword)) {
            evidence.push({
              file: "crontab",
              line: i + 1,
              snippet: line.slice(0, 120),
              detail: `Cron entry references "${keyword}"`
            });
            break;
          }
        }
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "No suspicious cron entries found",
      failed: (n) => `Found ${n} suspicious cron entry/entries`
    });
  }
});

// src/checks/runtime/run-003-vscode-trojans.ts
import { join as join39 } from "path";
init_types();
var MALICIOUS_EXTENSIONS = /* @__PURE__ */ new Set([
  "openclaw-tools.unofficial-helper",
  "claw-extensions.free-copilot",
  "ai-agent-plugins.claw-boost",
  "clawhavoc.malicious-skill-loader"
]);
var run003 = defineCheck({
  id: "RUN-003",
  name: "VS Code Extension Trojans",
  category: "runtime",
  severity: "critical",
  description: "Check for known malicious VS Code extension IDs",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    const evidence = [];
    const home = ctx.fs.homedir();
    const extensionDirs = [
      join39(home, ".vscode", "extensions"),
      join39(home, ".vscode-insiders", "extensions"),
      join39(home, ".cursor", "extensions")
    ];
    for (const dir of extensionDirs) {
      try {
        const entries = await ctx.fs.readdir(dir);
        for (const entry of entries) {
          const lower = entry.toLowerCase();
          for (const malId of MALICIOUS_EXTENSIONS) {
            if (lower.startsWith(malId.split(".")[0]) && lower.includes(malId.split(".")[1])) {
              evidence.push({
                file: join39(dir, entry),
                detail: `Known malicious extension: ${malId}`
              });
            }
          }
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No known malicious VS Code extensions found",
      failed: (n) => `Found ${n} malicious VS Code extension(s)`
    });
  }
});

// src/checks/runtime/run-004-docker-security.ts
init_types();
var run004 = defineCheck({
  id: "RUN-004",
  name: "Docker Security",
  category: "runtime",
  severity: "warning",
  description: "Check Docker socket permissions and container security",
  excludedAgents: CODING_AGENTS,
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    try {
      const stats = await ctx.fs.stat("/var/run/docker.sock");
      const mode = stats.mode & 511;
      if (mode & 6) {
        evidence.push({
          file: "/var/run/docker.sock",
          detail: `Docker socket permissions: ${mode.toString(8)} \u2014 world-accessible`
        });
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "Docker security checks passed (or Docker not installed)",
      failed: (n) => `Found ${n} Docker security issue(s)`
    });
  }
});

// src/checks/runtime/run-005-process-ancestry.ts
init_types();
var AGENT_KEYWORDS = ["openclaw", "nanoclaw", "picoclaw", "ironclaw", "nanobot", "zeroclaw"];
var SUSPICIOUS_PARENTS = /* @__PURE__ */ new Set([
  "curl",
  "wget",
  "nc",
  "ncat",
  "netcat",
  "python",
  "python3",
  "ruby",
  "perl"
]);
var SUSPICIOUS_PARENT_PATTERNS = [
  /\bbash\s+-c\b/,
  /\bsh\s+-c\b/,
  /\bpython[23]?\s+-c\b/
];
var run005 = defineCheck({
  id: "RUN-005",
  name: "Process Ancestry Analysis",
  category: "runtime",
  severity: "warning",
  description: "Check agent process ancestry for suspicious parent processes",
  excludedAgents: CODING_AGENTS,
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    let output = "";
    try {
      output = ctx.fs.execSync("ps", ["-eo", "pid,ppid,comm"], { timeout: 5e3 });
    } catch {
      return h.passed("Could not retrieve process list");
    }
    const evidence = [];
    const processMap = /* @__PURE__ */ new Map();
    const agentPids = [];
    const lines = output.split("\n");
    for (const line of lines.slice(1)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length < 3) continue;
      const pid = parseInt(parts[0], 10);
      const ppid = parseInt(parts[1], 10);
      const comm = parts.slice(2).join(" ");
      if (isNaN(pid) || isNaN(ppid)) continue;
      processMap.set(pid, { ppid, comm });
      const commLower = comm.toLowerCase();
      for (const keyword of AGENT_KEYWORDS) {
        if (commLower.includes(keyword)) {
          agentPids.push(pid);
          break;
        }
      }
    }
    for (const agentPid of agentPids) {
      let currentPid = agentPid;
      const agentComm = processMap.get(agentPid)?.comm ?? "unknown";
      for (let depth = 0; depth < 5; depth++) {
        const proc = processMap.get(currentPid);
        if (!proc || proc.ppid === 0 || proc.ppid === currentPid) break;
        const parent = processMap.get(proc.ppid);
        if (!parent) break;
        const parentBaseName = parent.comm.split("/").pop()?.toLowerCase() ?? "";
        if (SUSPICIOUS_PARENTS.has(parentBaseName)) {
          evidence.push({
            file: "ps",
            detail: `Agent process "${agentComm}" (PID ${agentPid}) has suspicious parent "${parent.comm}" (PID ${proc.ppid})`
          });
          break;
        }
        for (const pattern of SUSPICIOUS_PARENT_PATTERNS) {
          if (pattern.test(parent.comm)) {
            evidence.push({
              file: "ps",
              detail: `Agent process "${agentComm}" (PID ${agentPid}) has suspicious parent "${parent.comm}" (PID ${proc.ppid})`
            });
            break;
          }
        }
        if (evidence.length > 0) break;
        currentPid = proc.ppid;
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No suspicious process ancestry detected for agent processes",
      failed: (n) => `Found ${n} agent process(es) with suspicious parent processes`
    });
  }
});

// src/checks/runtime/index.ts
var runtimeChecks = [
  run001,
  run002,
  run003,
  run004,
  run005
];

// src/checks/mcp/mcp-001-config-discovery.ts
var mcp001 = defineCheck({
  id: "MCP-001",
  name: "MCP Config Discovery",
  category: "mcp",
  severity: "info",
  description: "Inventory all configured MCP servers across all agent configs",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        const detail = [
          `Transport: ${server.transport}`,
          server.command ? `Command: ${server.command}` : null,
          server.url ? `URL: ${server.url}` : null,
          server.args?.length ? `Args: ${server.args.join(" ")}` : null,
          server.env ? `Env vars: ${Object.keys(server.env).join(", ")}` : null
        ].filter(Boolean).join(", ");
        evidence.push({
          file: config.filePath,
          snippet: `Server: ${server.name}`,
          detail
        });
      }
    }
    const totalServers = mcpConfigs.reduce((sum, c) => sum + c.servers.length, 0);
    return h.result({
      passed: true,
      message: totalServers === 0 ? "No MCP servers configured" : `Found ${totalServers} MCP server(s) across ${mcpConfigs.length} config(s)`,
      evidence
    });
  }
});

// src/checks/mcp/mcp-002-transport-security.ts
var mcp002 = defineCheck({
  id: "MCP-002",
  name: "Transport Security",
  category: "mcp",
  severity: "critical",
  description: "Check for MCP servers using insecure transports (SSE/HTTP without TLS, binding to 0.0.0.0)",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (server.url) {
          if (server.url.startsWith("http://") && !server.url.includes("localhost") && !server.url.includes("127.0.0.1")) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${server.url}`,
              detail: "Non-localhost HTTP transport without TLS \u2014 traffic is unencrypted"
            });
          }
          if (server.url.includes("0.0.0.0")) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${server.url}`,
              detail: "Bound to 0.0.0.0 \u2014 server is accessible from any network interface"
            });
          }
        }
        if (server.args) {
          const argsStr = server.args.join(" ");
          if (argsStr.includes("0.0.0.0")) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": args contain 0.0.0.0`,
              detail: "Server may be bound to all interfaces via command arguments"
            });
          }
          if (/--no-?tls|--insecure|--disable-ssl/i.test(argsStr)) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": TLS disabled in args`,
              detail: "TLS explicitly disabled via command-line flags"
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All MCP transports use secure configurations",
      failed: (n) => `Found ${n} insecure transport configuration(s)`
    });
  }
});

// src/checks/mcp/mcp-003-credential-exposure.ts
var HIGH_ENTROPY_THRESHOLD2 = 4.5;
var MIN_SECRET_LENGTH = 16;
var mcp003 = defineCheck({
  id: "MCP-003",
  name: "Credential Exposure",
  category: "mcp",
  severity: "critical",
  description: "Check for plaintext secrets in MCP server env blocks and config values",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        const sources = [];
        if (server.env) sources.push(["env block", server.env]);
        if (server.headers) sources.push(["header", server.headers]);
        if (sources.length === 0) continue;
        for (const [location, values] of sources) {
          for (const [key, value] of Object.entries(values)) {
            for (const { pattern, name } of API_KEY_PATTERNS) {
              if (pattern.test(value)) {
                evidence.push({
                  file: config.filePath,
                  snippet: `Server "${server.name}": ${key}=${value.slice(0, 8)}${"*".repeat(Math.max(0, value.length - 8))}`,
                  detail: `Plaintext ${name} in ${location}`
                });
              }
            }
            const secretKeyPattern = /(?:key|token|secret|password|credential|auth|api_key|apikey|pass)/i;
            if (secretKeyPattern.test(key) && value.length >= MIN_SECRET_LENGTH) {
              const entropy = shannonEntropy(value);
              if (entropy > HIGH_ENTROPY_THRESHOLD2) {
                const alreadyCaught = evidence.some(
                  (e) => e.file === config.filePath && e.snippet?.includes(server.name) && e.snippet?.includes(key)
                );
                if (!alreadyCaught) {
                  evidence.push({
                    file: config.filePath,
                    snippet: `Server "${server.name}": ${key}=${value.slice(0, 8)}...`,
                    detail: `High-entropy value (${entropy.toFixed(1)} bits) in secret-named ${location === "header" ? "header" : "env var"}`
                  });
                }
              }
            }
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No plaintext credentials found in MCP configs",
      failed: (n) => `Found ${n} exposed credential(s) in MCP configs`,
      fixable: evidence.length > 0,
      fixDescription: "Move secrets to environment variables or a secrets manager"
    });
  }
});

// src/checks/mcp/mcp-004-overprivileged-tools.ts
var mcp004 = defineCheck({
  id: "MCP-004",
  name: "Overprivileged Tools",
  category: "mcp",
  severity: "critical",
  description: "Detect MCP servers with exec/shell/write capabilities in source code",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const sources = ctx.mcpServerSources ?? [];
    for (const source of sources) {
      if (!source.sourceCode) continue;
      const results = analyzeCode(source.sourceCode, source.localPath ?? source.serverName);
      const execFindings = results.filter((r) => r.type === "eval-exec");
      const fsFindings = results.filter((r) => r.type === "fs-access");
      for (const finding of execFindings) {
        evidence.push({
          file: source.localPath ?? source.serverName,
          line: finding.line,
          snippet: finding.snippet,
          detail: `Command execution: ${finding.description}`
        });
      }
      for (const finding of fsFindings) {
        evidence.push({
          file: source.localPath ?? source.serverName,
          line: finding.line,
          snippet: finding.snippet,
          detail: `Sensitive file access: ${finding.description}`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No overprivileged operations found in MCP server source",
      failed: (n) => `Found ${n} overprivileged operation(s) in MCP server source`
    });
  }
});

// src/checks/mcp/mcp-005-tool-injection.ts
var INJECTION_PATTERNS = [
  { pattern: /exec\s*\(\s*(?:req|input|args|params|query|body|tool_input|message)/i, name: "Command injection via user input" },
  { pattern: /spawn\s*\(\s*(?:req|input|args|params|query|body|tool_input|message)/i, name: "Process spawn with user input" },
  { pattern: /eval\s*\(\s*(?:req|input|args|params|query|body|tool_input|message)/i, name: "Eval with user input" },
  { pattern: /\$\{(?:req|input|args|params|query|body|tool_input|message)/i, name: "Template literal injection" },
  { pattern: /writeFile(?:Sync)?\s*\(\s*(?:req|input|args|params|query|body|tool_input|message)/i, name: "File write with user-controlled path" },
  { pattern: /sql\s*[`"'].*\$\{/i, name: "Potential SQL injection via template literal" },
  { pattern: /\.query\s*\(\s*[`"'].*\+/i, name: "Potential SQL injection via concatenation" },
  { pattern: /child_process.*(?:req|input|args|params|query|body|tool_input)/i, name: "Child process with user input" },
  { pattern: /new\s+Function\s*\(\s*(?:req|input|args|params|query|body|tool_input)/i, name: "Dynamic Function constructor with user input" }
];
var mcp005 = defineCheck({
  id: "MCP-005",
  name: "Tool Input Injection",
  category: "mcp",
  severity: "critical",
  description: "Detect unsanitized LLM/user input flowing to dangerous sinks in MCP server source",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const sources = ctx.mcpServerSources ?? [];
    for (const source of sources) {
      if (!source.sourceCode) continue;
      const lines = source.sourceCode.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
        for (const { pattern, name } of INJECTION_PATTERNS) {
          if (pattern.test(line)) {
            evidence.push({
              file: source.localPath ?? source.serverName,
              line: i + 1,
              snippet: line.trim().slice(0, 120),
              detail: name
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No injection vulnerabilities detected in MCP server source",
      failed: (n) => `Found ${n} potential injection vulnerability(ies) in MCP server source`
    });
  }
});

// src/checks/mcp/mcp-006-data-exfiltration.ts
var mcp006 = defineCheck({
  id: "MCP-006",
  name: "Data Exfiltration Risk",
  category: "mcp",
  severity: "critical",
  description: "Detect sensitive data flowing to network sinks in MCP server source",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const sources = ctx.mcpServerSources ?? [];
    for (const source of sources) {
      if (!source.sourceCode) continue;
      const results = analyzeCode(source.sourceCode, source.localPath ?? source.serverName);
      const exfilFindings = results.filter((r) => r.type === "source-to-sink");
      const suspiciousNet = results.filter((r) => r.type === "suspicious-network");
      for (const finding of exfilFindings) {
        evidence.push({
          file: source.localPath ?? source.serverName,
          line: finding.line,
          snippet: finding.snippet,
          detail: finding.description
        });
      }
      for (const finding of suspiciousNet) {
        evidence.push({
          file: source.localPath ?? source.serverName,
          line: finding.line,
          snippet: finding.snippet,
          detail: finding.description
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No data exfiltration patterns found in MCP server source",
      failed: (n) => `Found ${n} data exfiltration risk(s) in MCP server source`
    });
  }
});

// src/checks/mcp/mcp-007-prompt-injection.ts
var UNSAFE_RETURN_PATTERNS = [
  { pattern: /return\s+(?:await\s+)?(?:fetch|axios|got|request)\s*\(/, name: "Raw HTTP response returned as tool result" },
  { pattern: /return\s+(?:await\s+)?(?:readFile|readFileSync)\s*\(/, name: "Raw file content returned as tool result" },
  { pattern: /return\s+(?:await\s+)?(?:\.text\(\)|\.json\(\)|\.body)/, name: "Raw response body returned as tool result" },
  { pattern: /content\s*:\s*(?:await\s+)?(?:fetch|response|res)/, name: "External content injected into tool result" },
  { pattern: /tool_result.*(?:fetch|http|request)/i, name: "External fetch in tool result handler" },
  { pattern: /innerHTML|outerHTML|document\.write/i, name: "DOM manipulation from external content" }
];
var SANITIZATION_PATTERNS = [
  /sanitize|escape|encode|strip|clean|purify|validate/i,
  /DOMPurify|xss|helmet/i,
  /\.replace\(.*<.*>/i
];
var mcp007 = defineCheck({
  id: "MCP-007",
  name: "Prompt Injection via Tool Results",
  category: "mcp",
  severity: "warning",
  description: "Detect raw external content returned unsanitized in MCP tool results",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const sources = ctx.mcpServerSources ?? [];
    for (const source of sources) {
      if (!source.sourceCode) continue;
      const hasSanitization = SANITIZATION_PATTERNS.some((p) => p.test(source.sourceCode));
      const lines = source.sourceCode.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
        for (const { pattern, name } of UNSAFE_RETURN_PATTERNS) {
          if (pattern.test(line)) {
            evidence.push({
              file: source.localPath ?? source.serverName,
              line: i + 1,
              snippet: line.trim().slice(0, 120),
              detail: hasSanitization ? `${name} (sanitization detected elsewhere \u2014 verify coverage)` : `${name} (no sanitization detected)`
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No prompt injection risks detected in MCP tool results",
      failed: (n) => `Found ${n} potential prompt injection vector(s) in MCP tool results`
    });
  }
});

// src/checks/mcp/mcp-008-server-provenance.ts
init_database();
var mcp008 = defineCheck({
  id: "MCP-008",
  name: "Server Provenance",
  category: "mcp",
  severity: "warning",
  description: "Check MCP server package names for typosquatting, known-malicious publishers, and IOC matches",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    const sources = ctx.mcpServerSources ?? [];
    const ioc = getIOCDatabase();
    const trustedPackages = ioc.trustedMCPPackages ?? [];
    for (const source of sources) {
      const packageName = source.packageName;
      if (!packageName) continue;
      const normalizedPkg = packageName.toLowerCase();
      for (const publisher of ioc.maliciousPublishers) {
        if (normalizedPkg.includes(publisher.toLowerCase())) {
          evidence.push({
            file: findConfigFile(mcpConfigs, source.serverName),
            snippet: `Server "${source.serverName}": package ${packageName}`,
            detail: `Package name matches known malicious publisher: ${publisher}`
          });
        }
      }
      for (const domain of ioc.maliciousDomains) {
        const domainBase = domain.split(".")[0];
        if (normalizedPkg.includes(domainBase)) {
          evidence.push({
            file: findConfigFile(mcpConfigs, source.serverName),
            snippet: `Server "${source.serverName}": package ${packageName}`,
            detail: `Package name matches known malicious domain: ${domain}`
          });
        }
      }
      if (trustedPackages.length > 0) {
        const typosquat = detectTyposquatting(packageName, trustedPackages);
        if (typosquat) {
          evidence.push({
            file: findConfigFile(mcpConfigs, source.serverName),
            snippet: `Server "${source.serverName}": package ${packageName}`,
            detail: `Possible typosquat of "${typosquat.trustedName}" (distance: ${typosquat.distance})`
          });
        }
      }
      for (const pattern of ioc.maliciousSkillPatterns) {
        if (pattern.test(packageName)) {
          evidence.push({
            file: findConfigFile(mcpConfigs, source.serverName),
            snippet: `Server "${source.serverName}": package ${packageName}`,
            detail: `Package name matches suspicious pattern: ${pattern.source}`
          });
        }
      }
    }
    const hasCritical = evidence.some(
      (e) => e.detail?.includes("malicious publisher") || e.detail?.includes("malicious domain")
    );
    return h.fromEvidence(evidence, {
      passed: "All MCP server packages pass provenance checks",
      failed: (n) => `Found ${n} provenance concern(s) for MCP server packages`,
      severity: hasCritical ? "critical" : void 0
    });
  }
});
function findConfigFile(configs, serverName) {
  for (const config of configs) {
    if (config.servers.some((s) => s.name === serverName)) {
      return config.filePath;
    }
  }
  return "unknown";
}

// src/checks/mcp/mcp-009-permission-scope.ts
var OVERPRIVILEGED_PATTERNS = [
  { pattern: /\b(?:admin|root|sudo|superuser)\b/i, name: "Administrative privilege naming" },
  { pattern: /\b(?:all-access|full-access|unrestricted)\b/i, name: "Unrestricted access claim" }
];
var SOURCE_PERMISSION_PATTERNS = [
  { pattern: /chmod\s*\(\s*['"]?(?:0?777|0?666)/i, name: "World-writable permissions" },
  { pattern: /--privileged/i, name: "Docker privileged mode" },
  { pattern: /listen\s*\(\s*(?:0|80|443|8080|3000)\s*[,)]/i, name: "Binding to well-known port" },
  { pattern: /process\.env\.HOME|process\.env\.USERPROFILE/i, name: "Accessing user home directory" },
  { pattern: /glob\s*\(\s*['"](?:\/|\*\*)/i, name: "Recursive filesystem globbing from root" },
  { pattern: /readdir(?:Sync)?\s*\(\s*['"](?:\/|~)/i, name: "Reading root or home directory" }
];
var mcp009 = defineCheck({
  id: "MCP-009",
  name: "Permission Scope",
  category: "mcp",
  severity: "warning",
  description: "Detect MCP servers requesting disproportionate resource access",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    const sources = ctx.mcpServerSources ?? [];
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        for (const { pattern, name } of OVERPRIVILEGED_PATTERNS) {
          if (pattern.test(server.name)) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}"`,
              detail: name
            });
          }
        }
        if (server.args) {
          const argsStr = server.args.join(" ");
          if (/(?:^|\s)\/\s|(?:^|\s)~\s/i.test(argsStr) || argsStr.includes("/**")) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": args=${server.args.join(" ")}`,
              detail: "Server arguments grant access to broad filesystem paths"
            });
          }
        }
      }
    }
    for (const source of sources) {
      if (!source.sourceCode) continue;
      const lines = source.sourceCode.split("\n");
      for (let i = 0; i < lines.length; i++) {
        for (const { pattern, name } of SOURCE_PERMISSION_PATTERNS) {
          if (pattern.test(lines[i])) {
            evidence.push({
              file: source.localPath ?? source.serverName,
              line: i + 1,
              snippet: lines[i].trim().slice(0, 120),
              detail: name
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "MCP server permission scopes appear reasonable",
      failed: (n) => `Found ${n} disproportionate permission scope(s)`
    });
  }
});

// src/checks/mcp/mcp-010-rug-pull-risk.ts
function isVersionPinned(packageArg) {
  if (packageArg.startsWith("@")) {
    const afterScope = packageArg.indexOf("/", 1);
    if (afterScope === -1) return false;
    const rest = packageArg.slice(afterScope + 1);
    const atIdx2 = rest.indexOf("@");
    if (atIdx2 === -1) return false;
    const version2 = rest.slice(atIdx2 + 1);
    return version2 !== "latest" && version2.length > 0;
  }
  const atIdx = packageArg.indexOf("@");
  if (atIdx === -1) return false;
  const version = packageArg.slice(atIdx + 1);
  return version !== "latest" && version.length > 0;
}
var mcp010 = defineCheck({
  id: "MCP-010",
  name: "Rug Pull Risk",
  category: "mcp",
  severity: "warning",
  description: "Detect unpinned versions and missing lockfiles that enable supply chain attacks",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.command || !server.args?.length) continue;
        const cmd = server.command;
        const args = server.args;
        if (cmd === "npx" || cmd === "npx.cmd") {
          const packageArg = args.find((a) => !a.startsWith("-"));
          const isUnpinned = packageArg && !isVersionPinned(packageArg);
          if (isUnpinned) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": npx ${packageArg}`,
              detail: "Package not version-pinned \u2014 npx will always fetch latest, enabling rug-pull attacks"
            });
            if (args.some((a) => a === "-y" || a === "--yes")) {
              evidence.push({
                file: config.filePath,
                snippet: `Server "${server.name}": npx -y (auto-install)`,
                detail: "Auto-install enabled with unpinned package \u2014 will install without confirmation"
              });
            }
          }
        }
        if (cmd === "uvx" || cmd === "uv") {
          const packageArg = args.find((a) => !a.startsWith("-") && a !== "run" && a !== "tool");
          if (packageArg && !packageArg.includes("==") && !packageArg.includes(">=")) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${cmd} ${packageArg}`,
              detail: "Python package not version-pinned \u2014 enables rug-pull attacks"
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "MCP server packages are properly version-pinned",
      failed: (n) => `Found ${n} supply chain risk(s) from unpinned versions`,
      fixable: evidence.length > 0,
      fixDescription: "Pin package versions (e.g., npx @scope/package@1.2.3)"
    });
  }
});

// src/checks/mcp/mcp-011-oauth-endpoint-https.ts
var OAUTH_URL_ENV_PATTERNS = /(?:oauth|auth|token|authorize)[_-]?(?:url|endpoint|uri|server)/i;
var LOCALHOST_EXCEPTIONS = ["localhost", "127.0.0.1", "[::1]"];
function isLocalhostUrl(url) {
  return LOCALHOST_EXCEPTIONS.some((host) => url.includes(host));
}
var SOURCE_HTTP_OAUTH_PATTERNS = [
  { pattern: /authorization_endpoint['":\s]*['"]?http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/, detail: "HTTP authorization_endpoint URL" },
  { pattern: /token_endpoint['":\s]*['"]?http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/, detail: "HTTP token_endpoint URL" },
  { pattern: /\.well-known\/oauth-authorization-server.*http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/, detail: "HTTP OAuth discovery endpoint" },
  { pattern: /http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])[^'"\s]*\/authorize/, detail: "HTTP authorization URL" },
  { pattern: /http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])[^'"\s]*\/oauth\/token/, detail: "HTTP OAuth token URL" },
  { pattern: /http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])[^'"\s]*\/oauth2\//, detail: "HTTP OAuth2 endpoint URL" }
];
var mcp011 = defineCheck({
  id: "MCP-011",
  name: "OAuth Endpoint HTTPS",
  category: "mcp",
  severity: "critical",
  description: "Check for OAuth authorization/token endpoints using HTTP instead of HTTPS (OAuth 2.1 mandates TLS)",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    const mcpServerSources = ctx.mcpServerSources ?? [];
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.env) continue;
        for (const [key, value] of Object.entries(server.env)) {
          if (OAUTH_URL_ENV_PATTERNS.test(key) && value.startsWith("http://") && !isLocalhostUrl(value)) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${key}=${value}`,
              detail: `OAuth endpoint using HTTP \u2014 OAuth 2.1 mandates HTTPS for all endpoints`
            });
          }
        }
      }
    }
    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const lines = source.sourceCode.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const { pattern, detail } of SOURCE_HTTP_OAUTH_PATTERNS) {
          if (pattern.test(line)) {
            evidence.push({
              file: source.localPath ?? source.serverName,
              line: i + 1,
              snippet: line.trim(),
              detail
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All OAuth endpoints use HTTPS",
      failed: (n) => `Found ${n} OAuth endpoint(s) using HTTP instead of HTTPS`,
      fixable: evidence.length > 0,
      fixDescription: "Change all OAuth endpoint URLs from http:// to https://"
    });
  }
});

// src/checks/mcp/mcp-012-oauth-client-secret-exposure.ts
var HIGH_ENTROPY_THRESHOLD3 = 4.5;
var MIN_SECRET_LENGTH2 = 16;
function maskValue(value) {
  if (value.length <= 8) return "*".repeat(value.length);
  return value.slice(0, 8) + "*".repeat(Math.max(0, value.length - 8));
}
var mcp012 = defineCheck({
  id: "MCP-012",
  name: "OAuth Client Secret Exposure",
  category: "mcp",
  severity: "critical",
  description: "Check for plaintext OAuth client secrets, access tokens, and refresh tokens in MCP config env blocks",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.env) continue;
        for (const [key, value] of Object.entries(server.env)) {
          if (/^\$\{.*\}$/.test(value) || /^\$[A-Z_]+$/.test(value)) continue;
          for (const { pattern, name } of OAUTH_SECRET_PATTERNS) {
            if (pattern.test(key)) {
              evidence.push({
                file: config.filePath,
                snippet: `Server "${server.name}": ${key}=${maskValue(value)}`,
                detail: `Plaintext ${name} in env block`
              });
              break;
            }
          }
          for (const { pattern, name } of OAUTH_TOKEN_VALUE_PATTERNS) {
            if (pattern.test(value)) {
              const alreadyCaught = evidence.some(
                (e) => e.file === config.filePath && e.snippet?.includes(server.name) && e.snippet?.includes(key)
              );
              if (!alreadyCaught) {
                evidence.push({
                  file: config.filePath,
                  snippet: `Server "${server.name}": ${key}=${maskValue(value)}`,
                  detail: `Detected ${name} value in env block`
                });
              }
              break;
            }
          }
          const secretKeyPattern = /(?:client[_-]?secret|oauth[_-]?secret|refresh[_-]?token|access[_-]?token)/i;
          if (secretKeyPattern.test(key) && value.length >= MIN_SECRET_LENGTH2) {
            const entropy = shannonEntropy(value);
            if (entropy > HIGH_ENTROPY_THRESHOLD3) {
              const alreadyCaught = evidence.some(
                (e) => e.file === config.filePath && e.snippet?.includes(server.name) && e.snippet?.includes(key)
              );
              if (!alreadyCaught) {
                evidence.push({
                  file: config.filePath,
                  snippet: `Server "${server.name}": ${key}=${maskValue(value)}`,
                  detail: `High-entropy value (${entropy.toFixed(1)} bits) in OAuth secret env var`
                });
              }
            }
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No exposed OAuth credentials found in MCP configs",
      failed: (n) => `Found ${n} exposed OAuth credential(s) in MCP configs`,
      fixable: evidence.length > 0,
      fixDescription: "Move OAuth secrets to a secrets manager or use environment variable references (e.g., ${CLIENT_SECRET})"
    });
  }
});

// src/checks/mcp/mcp-013-missing-pkce.ts
var AUTHORIZE_URL_PATTERN = /\/authorize|\/authorization/;
var CODE_CHALLENGE_PATTERN = /code_challenge/;
var CODE_VERIFIER_PATTERN = /code_verifier/;
var PLAIN_CHALLENGE_PATTERN = /code_challenge_method['":\s]*['"]?plain/i;
var TOKEN_EXCHANGE_PATTERN = /\/token|grant_type|authorization_code/;
var SEARCH_RADIUS = 15;
var mcp013 = defineCheck({
  id: "MCP-013",
  name: "Missing PKCE",
  category: "mcp",
  severity: "critical",
  description: "Detect OAuth authorization flows without PKCE (Proof Key for Code Exchange) protection",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpServerSources = ctx.mcpServerSources ?? [];
    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const lines = source.sourceCode.split("\n");
      const filePath = source.localPath ?? source.serverName;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
        if (AUTHORIZE_URL_PATTERN.test(line)) {
          const start = Math.max(0, i - SEARCH_RADIUS);
          const end = Math.min(lines.length, i + SEARCH_RADIUS + 1);
          const nearbyCode = lines.slice(start, end).join("\n");
          if (!CODE_CHALLENGE_PATTERN.test(nearbyCode)) {
            evidence.push({
              file: filePath,
              line: i + 1,
              snippet: line.trim(),
              detail: "OAuth authorization URL constructed without PKCE code_challenge parameter"
            });
          }
        }
        if (PLAIN_CHALLENGE_PATTERN.test(line)) {
          evidence.push({
            file: filePath,
            line: i + 1,
            snippet: line.trim(),
            detail: 'PKCE code_challenge_method set to "plain" \u2014 must use "S256" for security'
          });
        }
        if (TOKEN_EXCHANGE_PATTERN.test(line) && /grant_type.*authorization_code|authorization_code.*grant_type/.test(line)) {
          const start = Math.max(0, i - SEARCH_RADIUS);
          const end = Math.min(lines.length, i + SEARCH_RADIUS + 1);
          const nearbyCode = lines.slice(start, end).join("\n");
          if (!CODE_VERIFIER_PATTERN.test(nearbyCode)) {
            evidence.push({
              file: filePath,
              line: i + 1,
              snippet: line.trim(),
              detail: "Token exchange with authorization_code grant but no code_verifier \u2014 PKCE not enforced"
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "OAuth flows properly implement PKCE",
      failed: (n) => `Found ${n} OAuth flow(s) without PKCE protection`,
      fixable: false,
      fixDescription: "Add PKCE with S256 code_challenge_method to all OAuth authorization flows"
    });
  }
});

// src/checks/mcp/mcp-014-insecure-token-storage.ts
var INSECURE_TOKEN_PATTERNS = [
  { pattern: /console\.log\s*\(.*(?:token|access_token|refresh_token|bearer)/i, detail: "OAuth token logged to console" },
  { pattern: /localStorage\.setItem\s*\(.*(?:token|oauth|bearer)/i, detail: "OAuth token stored in localStorage (vulnerable to XSS)" },
  { pattern: /sessionStorage\.setItem\s*\(.*(?:token|oauth|bearer)/i, detail: "OAuth token stored in sessionStorage (vulnerable to XSS)" },
  { pattern: /writeFile(?:Sync)?\s*\(.*(?:token|oauth|bearer)/i, detail: "OAuth token written to file without encryption" },
  { pattern: /(?:access_token|bearer|refresh_token|token).*[?&].*=/, detail: "OAuth token passed in URL query parameter" },
  { pattern: /[?&](?:access_token|token|bearer)=/, detail: "OAuth token in URL query parameter" },
  { pattern: /url\s*[\+\`].*(?:token|access_token)/, detail: "OAuth token interpolated into URL" },
  { pattern: /(?:token|access_token|bearer)\s*\+\s*['"`]/, detail: "OAuth token concatenated into string (potential URL leak)" }
];
var mcp014 = defineCheck({
  id: "MCP-014",
  name: "Insecure Token Storage",
  category: "mcp",
  severity: "critical",
  description: "Detect OAuth tokens written to files, localStorage, console.log, or passed in query parameters",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpServerSources = ctx.mcpServerSources ?? [];
    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const lines = source.sourceCode.split("\n");
      const filePath = source.localPath ?? source.serverName;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim().startsWith("//") || line.trim().startsWith("*")) continue;
        for (const { pattern, detail } of INSECURE_TOKEN_PATTERNS) {
          if (pattern.test(line)) {
            evidence.push({
              file: filePath,
              line: i + 1,
              snippet: line.trim(),
              detail
            });
            break;
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No insecure token storage patterns found",
      failed: (n) => `Found ${n} insecure token storage pattern(s)`,
      fixable: false,
      fixDescription: "Store tokens securely (encrypted at rest, never in logs/URLs/localStorage)"
    });
  }
});

// src/checks/mcp/mcp-015-token-passthrough.ts
var TOKEN_PASSTHROUGH_PATTERNS = [
  { pattern: /req(?:uest)?\.headers\.authorization.*(?:fetch|http\.request|axios|got|request\()/i, detail: "Inbound authorization header forwarded to outbound request" },
  { pattern: /(?:fetch|http\.request|axios|got|request)\s*\(.*req(?:uest)?\.headers\.authorization/i, detail: "Inbound authorization header passed to outbound request" },
  { pattern: /(?:context|ctx)\.token.*(?:fetch|http\.request|axios|got)/i, detail: "Context token forwarded to downstream API call" },
  { pattern: /(?:fetch|http\.request|axios|got).*(?:context|ctx)\.token/i, detail: "Context token passed to downstream API" },
  { pattern: /headers\s*:\s*\{[^}]*authorization\s*:\s*req(?:uest)?\.headers/i, detail: "Authorization header copied from inbound to outbound request" },
  { pattern: /headers\s*:\s*\{[^}]*[Bb]earer\s*.*req(?:uest)?\.headers/i, detail: "Bearer token extracted from request and forwarded downstream" },
  { pattern: /authorization\s*:\s*[`'"]\s*Bearer\s*\$\{.*(?:req|request|ctx|context).*token/i, detail: "Token from request context interpolated into outbound Authorization header" }
];
var mcp015 = defineCheck({
  id: "MCP-015",
  name: "Token Passthrough",
  category: "mcp",
  severity: "critical",
  description: "Detect MCP servers forwarding received auth tokens to downstream APIs (confused deputy risk)",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpServerSources = ctx.mcpServerSources ?? [];
    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const lines = source.sourceCode.split("\n");
      const filePath = source.localPath ?? source.serverName;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim().startsWith("//") || line.trim().startsWith("*")) continue;
        for (const { pattern, detail } of TOKEN_PASSTHROUGH_PATTERNS) {
          if (pattern.test(line)) {
            evidence.push({
              file: filePath,
              line: i + 1,
              snippet: line.trim(),
              detail
            });
            break;
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No token passthrough patterns detected",
      failed: (n) => `Found ${n} token passthrough pattern(s) \u2014 tokens may be forwarded to downstream services`
    });
  }
});

// src/checks/mcp/mcp-016-insecure-redirect-uri.ts
var LOCALHOST_EXCEPTIONS2 = ["localhost", "127.0.0.1", "[::1]"];
function isLocalhostUrl2(url) {
  return LOCALHOST_EXCEPTIONS2.some((host) => url.includes(host));
}
var SOURCE_REDIRECT_PATTERNS = [
  { pattern: /redirect_uri['":\s]*['"]?http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/, detail: "HTTP redirect_uri (must use HTTPS for OAuth 2.1)" },
  { pattern: /redirect_uri['":\s]*['"]?\*/, detail: "Wildcard redirect_uri pattern \u2014 allows open redirect attacks" },
  { pattern: /redirect_uri['":\s]*['"]?.*\.\./, detail: "Path traversal in redirect_uri" },
  { pattern: /redirect.*(?:req\.query|req\.params|request\.query|params\.)/, detail: "User-controlled redirect target \u2014 potential open redirect" },
  { pattern: /callback.*(?:req\.query|req\.params|request\.query|params\.).*redirect/, detail: "User-controlled redirect in callback handler" }
];
var mcp016 = defineCheck({
  id: "MCP-016",
  name: "Insecure Redirect URI",
  category: "mcp",
  severity: "warning",
  description: "Detect HTTP redirect URIs, wildcard patterns, and user-controlled redirect targets in OAuth flows",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    const mcpServerSources = ctx.mcpServerSources ?? [];
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.env) continue;
        for (const [key, value] of Object.entries(server.env)) {
          if (/redirect|callback/i.test(key) && value.startsWith("http://") && !isLocalhostUrl2(value)) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${key}=${value}`,
              detail: "HTTP redirect/callback URI in env block \u2014 must use HTTPS"
            });
          }
        }
      }
    }
    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const lines = source.sourceCode.split("\n");
      const filePath = source.localPath ?? source.serverName;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim().startsWith("//") || line.trim().startsWith("*")) continue;
        for (const { pattern, detail } of SOURCE_REDIRECT_PATTERNS) {
          if (pattern.test(line)) {
            evidence.push({
              file: filePath,
              line: i + 1,
              snippet: line.trim(),
              detail
            });
            break;
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All OAuth redirect URIs are properly secured",
      failed: (n) => `Found ${n} insecure redirect URI pattern(s)`,
      fixable: evidence.length > 0,
      fixDescription: "Use HTTPS redirect URIs with exact-match validation; never allow user-controlled redirects"
    });
  }
});

// src/checks/mcp/mcp-017-overly-broad-scopes.ts
var DANGEROUS_SCOPE_PATTERNS = [
  { pattern: /scope['":\s]*['"]?\*['"]?/i, detail: "Wildcard scope \u2014 grants unrestricted access" },
  { pattern: /scope['":\s]*['"]?[^'"]*\ball\b/i, detail: 'Scope includes "all" \u2014 grants full access' },
  { pattern: /scope['":\s]*['"]?[^'"]*\badmin\b/i, detail: 'Scope includes "admin" \u2014 grants administrative access' },
  { pattern: /scope['":\s]*['"]?[^'"]*\broot\b/i, detail: 'Scope includes "root" \u2014 grants root-level access' },
  { pattern: /scope['":\s]*['"]?[^'"]*\bfull[_-]?access\b/i, detail: "Scope includes full-access pattern" }
];
var MAX_SCOPE_COUNT = 10;
var mcp017 = defineCheck({
  id: "MCP-017",
  name: "Overly Broad OAuth Scopes",
  category: "mcp",
  severity: "warning",
  description: "Detect wildcard scopes, excessive scope lists, and full-access patterns in OAuth configurations",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    const mcpServerSources = ctx.mcpServerSources ?? [];
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.env) continue;
        for (const [key, value] of Object.entries(server.env)) {
          if (!/scope/i.test(key)) continue;
          if (/^\*$|^all$|admin|root|full[_-]?access/i.test(value)) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${key}=${value}`,
              detail: "Overly broad OAuth scope in env block"
            });
          }
          const scopes = value.split(/[\s,]+/).filter(Boolean);
          if (scopes.length > MAX_SCOPE_COUNT) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${key}= (${scopes.length} scopes)`,
              detail: `Excessive scope count (${scopes.length}) \u2014 apply principle of least privilege`
            });
          }
        }
      }
    }
    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const lines = source.sourceCode.split("\n");
      const filePath = source.localPath ?? source.serverName;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim().startsWith("//") || line.trim().startsWith("*")) continue;
        for (const { pattern, detail } of DANGEROUS_SCOPE_PATTERNS) {
          if (pattern.test(line)) {
            evidence.push({
              file: filePath,
              line: i + 1,
              snippet: line.trim(),
              detail
            });
            break;
          }
        }
        const scopeMatch = line.match(/scope['":\s]*['"]([\w\s:,./\-]+)['"]/i);
        if (scopeMatch) {
          const scopes = scopeMatch[1].split(/[\s,]+/).filter(Boolean);
          if (scopes.length > MAX_SCOPE_COUNT) {
            const alreadyCaught = evidence.some((e) => e.file === filePath && e.line === i + 1);
            if (!alreadyCaught) {
              evidence.push({
                file: filePath,
                line: i + 1,
                snippet: line.trim(),
                detail: `Excessive scope count (${scopes.length}) \u2014 apply principle of least privilege`
              });
            }
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "OAuth scopes follow principle of least privilege",
      failed: (n) => `Found ${n} overly broad OAuth scope pattern(s)`,
      fixable: false,
      fixDescription: "Request only the minimum scopes needed; avoid wildcards and admin scopes"
    });
  }
});

// src/checks/mcp/mcp-018-missing-state-parameter.ts
var AUTHORIZE_URL_PATTERN2 = /\/authorize|\/authorization/;
var STATE_PARAM_PATTERN = /state/;
var STATIC_STATE_PATTERN = /state\s*[:=]\s*['"][^'"]*['"]/;
var DYNAMIC_STATE_PATTERNS = [
  /crypto\.random/,
  /uuid/i,
  /Math\.random/,
  /randomBytes/,
  /generateState/i,
  /nonce/i
];
var CALLBACK_HANDLER_PATTERN = /(?:function\s+\w*[Cc]allback|handle.*[Cc]allback|\.(?:get|post|all)\s*\(\s*['"].*callback)/;
var STATE_VERIFY_PATTERN = /state.*(?:===|!==|==|!=|verify|check|match|compare)|(?:verify|check|match|compare).*state/i;
var URL_CONSTRUCTION_PATTERN = /[?&]|URLSearchParams|\.search|\.href|redirect\s*\(|fetch\s*\(|window\.location|\+\s*['"`]|`[^`]*\$\{/;
var SEARCH_RADIUS2 = 15;
var mcp018 = defineCheck({
  id: "MCP-018",
  name: "Missing State Parameter",
  category: "mcp",
  severity: "warning",
  description: "Detect OAuth authorization flows without state/CSRF protection or with static state values",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpServerSources = ctx.mcpServerSources ?? [];
    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const lines = source.sourceCode.split("\n");
      const filePath = source.localPath ?? source.serverName;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim().startsWith("//") || line.trim().startsWith("*")) continue;
        if (AUTHORIZE_URL_PATTERN2.test(line)) {
          const isUrlConstruction = URL_CONSTRUCTION_PATTERN.test(line);
          const isConfigConstant = /^\s*\w+\s*[:=]\s*['"]https?:\/\//.test(line) && !isUrlConstruction;
          if (!isConfigConstant) {
            const start = Math.max(0, i - SEARCH_RADIUS2);
            const end = Math.min(lines.length, i + SEARCH_RADIUS2 + 1);
            const nearbyCode = lines.slice(start, end).join("\n");
            if (!STATE_PARAM_PATTERN.test(nearbyCode)) {
              evidence.push({
                file: filePath,
                line: i + 1,
                snippet: line.trim(),
                detail: "OAuth authorization URL constructed without state parameter \u2014 vulnerable to CSRF"
              });
            }
          }
        }
        if (STATIC_STATE_PATTERN.test(line) && /state/.test(line)) {
          const start = Math.max(0, i - 5);
          const end = Math.min(lines.length, i + 5 + 1);
          const nearbyCode = lines.slice(start, end).join("\n");
          const isDynamic = DYNAMIC_STATE_PATTERNS.some((p) => p.test(nearbyCode));
          if (!isDynamic) {
            evidence.push({
              file: filePath,
              line: i + 1,
              snippet: line.trim(),
              detail: "Static/hardcoded state value \u2014 state must be a unique random value per request"
            });
          }
        }
        if (CALLBACK_HANDLER_PATTERN.test(line)) {
          const start = i;
          const end = Math.min(lines.length, i + SEARCH_RADIUS2 + 1);
          const nearbyCode = lines.slice(start, end).join("\n");
          if (STATE_PARAM_PATTERN.test(nearbyCode) === false || STATE_PARAM_PATTERN.test(nearbyCode) && !STATE_VERIFY_PATTERN.test(nearbyCode)) {
            if (/code|authorization_code|grant/.test(nearbyCode)) {
              evidence.push({
                file: filePath,
                line: i + 1,
                snippet: line.trim(),
                detail: "OAuth callback handler does not verify state parameter \u2014 vulnerable to CSRF"
              });
            }
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "OAuth flows properly implement state/CSRF protection",
      failed: (n) => `Found ${n} OAuth flow(s) without proper state/CSRF protection`
    });
  }
});

// src/checks/mcp/mcp-019-toxic-tool-flow.ts
var SOURCE_PATTERNS = [
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
  /credentials/i
];
var SINK_PATTERNS = [
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
  /blob\.upload/i
];
function classifyToolHandler(handlerCode) {
  const sourceCapabilities = [];
  const sinkCapabilities = [];
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
    sinkCapabilities
  };
}
var TOOL_REGISTRATION_PATTERNS = [
  /\.tool\(\s*['"]([^'"]+)['"]/g,
  /addTool\(\s*\{[^}]*name:\s*['"]([^'"]+)['"]/g,
  /register[_]?[Tt]ool\(\s*['"]([^'"]+)['"]/g,
  /\{\s*name:\s*['"]([^'"]+)['"](?:\s*,\s*description:\s*['"][^'"]*?['"])?[^}]*handler\s*:/g
];
var MAX_HANDLER_WINDOW = 2e3;
function findToolRegistrationSites(sourceCode) {
  const sites = [];
  const seen = /* @__PURE__ */ new Set();
  for (const pattern of TOOL_REGISTRATION_PATTERNS) {
    pattern.lastIndex = 0;
    let match;
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
function extractToolHandlers(sourceCode) {
  const handlers = /* @__PURE__ */ new Map();
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
var mcp019 = defineCheck({
  id: "MCP-019",
  name: "Toxic Tool Flow",
  category: "mcp",
  severity: "critical",
  description: "Detect dangerous source\u2192sink tool combinations that enable data exfiltration via chained tool calls",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const sources = ctx.mcpServerSources ?? [];
    for (const source of sources) {
      if (!source.sourceCode) continue;
      const handlers = extractToolHandlers(source.sourceCode);
      const classifications = [];
      if (handlers.size > 0) {
        for (const [name, body] of handlers) {
          const result = classifyToolHandler(body);
          classifications.push({ name, ...result });
        }
      } else {
        continue;
      }
      const sourceTools = classifications.filter((c) => c.isSource);
      const sinkTools = classifications.filter((c) => c.isSink);
      if (sourceTools.length > 0 && sinkTools.length > 0) {
        const sourceNames = sourceTools.map((t) => `${t.name} (${t.sourceCapabilities.join(", ")})`);
        const sinkNames = sinkTools.map((t) => `${t.name} (${t.sinkCapabilities.join(", ")})`);
        evidence.push({
          file: source.localPath ?? source.serverName,
          detail: `Toxic flow: server "${source.serverName}" has source tools [${sourceNames.join("; ")}] and sink tools [${sinkNames.join("; ")}]. An agent could be prompt-injected to chain these for data exfiltration.`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No toxic source\u2192sink tool combinations found in MCP servers",
      failed: (n) => `Found ${n} MCP server(s) with toxic tool flow (source + sink tools coexist)`
    });
  }
});

// src/checks/mcp/mcp-020-tool-definition-rug-pull.ts
init_tool_baseline();
var mcp020 = defineCheck({
  id: "MCP-020",
  name: "Tool Definition Rug Pull",
  category: "mcp",
  severity: "warning",
  description: "Detect silent changes to MCP tool definitions between scans",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const sources = ctx.mcpServerSources ?? [];
    const store = ctx.mcpToolBaselineStore ?? defaultBaselineStore();
    const hostname = ctx.fs.hostname();
    let anyFirstScan = false;
    let totalChanges = 0;
    for (const source of sources) {
      const tools = source.tools ?? (source.sourceCode ? extractToolDefinitions(source.sourceCode) : []);
      if (tools.length === 0) continue;
      const { diff, isFirstScan } = await diffToolBaseline(store, source, tools, hostname);
      if (isFirstScan) {
        anyFirstScan = true;
        continue;
      }
      for (const changed of diff.changed) {
        totalChanges++;
        evidence.push({
          file: source.localPath ?? source.serverName,
          detail: `Tool "${changed.name}" definition changed in server "${source.serverName}" (hash ${changed.oldHash.slice(0, 8)}\u2192${changed.newHash.slice(0, 8)})`
        });
      }
      for (const added of diff.added) {
        totalChanges++;
        evidence.push({
          file: source.localPath ?? source.serverName,
          detail: `New tool "${added}" appeared in server "${source.serverName}" since last scan`
        });
      }
      for (const removed of diff.removed) {
        totalChanges++;
        evidence.push({
          file: source.localPath ?? source.serverName,
          detail: `Tool "${removed}" was removed from server "${source.serverName}" since last scan`
        });
      }
    }
    if (anyFirstScan && evidence.length === 0) {
      return h.result({
        passed: true,
        message: "MCP tool definition baseline established \u2014 changes will be detected on subsequent scans",
        severity: "info"
      });
    }
    return h.fromEvidence(evidence, {
      passed: "MCP tool definitions unchanged since last scan",
      failed: () => `Found ${totalChanges} tool definition change(s) across MCP servers \u2014 possible rug pull`
    });
  }
});

// src/checks/mcp/mcp-021-stdio-shell-invocation.ts
var SHELL_BINS = /* @__PURE__ */ new Set(["sh", "bash", "zsh", "fish", "dash", "ksh"]);
var SHELL_EXEC_FLAGS = /* @__PURE__ */ new Set(["-c", "-cu", "-uc"]);
function basename8(p) {
  const idx = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
  return idx >= 0 ? p.slice(idx + 1) : p;
}
var mcp021 = defineCheck({
  id: "MCP-021",
  name: "Stdio Server Shell Invocation",
  category: "mcp",
  severity: "warning",
  description: "Detect stdio MCP servers launched through sh -c / bash -c, which turns any env var or arg into shell input",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.command || !server.args) continue;
        const base = basename8(server.command);
        if (!SHELL_BINS.has(base)) continue;
        if (!server.args.some((a) => SHELL_EXEC_FLAGS.has(a))) continue;
        evidence.push({
          file: config.filePath,
          snippet: `Server "${server.name}": ${server.command} ${server.args.join(" ")}`,
          detail: `MCP server launched via ${base} -c \u2014 any value in env or args is parsed as shell, opening the door to injection`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No MCP servers are launched through a shell -c invocation",
      failed: (n) => `Found ${n} MCP server(s) launched via shell -c \u2014 injection-prone`,
      fixDescription: 'Invoke the server binary directly with argv (command: "/path/to/server", args: [...]); avoid shell -c wrappers'
    });
  }
});

// src/checks/mcp/mcp-022-world-writable-command.ts
var WORLD_WRITABLE_PREFIXES = ["/tmp/", "/var/tmp/", "/private/tmp/"];
var INTERPRETERS = /* @__PURE__ */ new Set([
  "python",
  "python2",
  "python3",
  "node",
  "nodejs",
  "ruby",
  "perl",
  "php",
  "sh",
  "bash",
  "zsh",
  "fish",
  "dash",
  "ksh",
  "deno",
  "bun"
]);
function basename9(p) {
  const idx = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
  return idx >= 0 ? p.slice(idx + 1) : p;
}
function inWorldWritable(path) {
  for (const prefix of WORLD_WRITABLE_PREFIXES) {
    if (path.startsWith(prefix)) return prefix.replace(/\/$/, "");
  }
  return void 0;
}
var mcp022 = defineCheck({
  id: "MCP-022",
  name: "Server Command in World-Writable Path",
  category: "mcp",
  severity: "critical",
  description: "Detect MCP servers whose command (or interpreter script) lives in /tmp, /var/tmp, or /private/tmp \u2014 replaceable by any local user",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.command) continue;
        const cmdDir = inWorldWritable(server.command);
        if (cmdDir) {
          evidence.push({
            file: config.filePath,
            snippet: `Server "${server.name}": ${server.command}`,
            detail: `Server binary lives under ${cmdDir} \u2014 any local user can replace it before the next MCP launch`
          });
          continue;
        }
        const base = basename9(server.command);
        if (INTERPRETERS.has(base) && server.args && server.args.length > 0) {
          const scriptArg = server.args.find((a) => !a.startsWith("-"));
          if (scriptArg) {
            const argDir = inWorldWritable(scriptArg);
            if (argDir) {
              evidence.push({
                file: config.filePath,
                snippet: `Server "${server.name}": ${server.command} ${scriptArg}`,
                detail: `Interpreter runs script under ${argDir} \u2014 any local user can swap the script payload`
              });
            }
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No MCP servers run from world-writable paths",
      failed: (n) => `Found ${n} MCP server(s) running from world-writable paths`,
      fixDescription: "Move the server binary or script to a user-owned directory (e.g. ~/.local/bin or a project venv); never run from /tmp"
    });
  }
});

// src/checks/mcp/mcp-023-streamable-http-origin-pinning.ts
var LOCALHOST_HOSTS = /* @__PURE__ */ new Set(["localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"]);
var ORIGIN_FLAG_PATTERNS = [
  /--allowed?-origins?/i,
  /--cors-?origins?/i,
  /--origin-allow-?list/i,
  /--trusted-?origins?/i,
  /--host=?(127\.0\.0\.1|localhost|::1)/i
];
function extractHostname(url) {
  try {
    const u = new URL(url);
    return u.hostname.toLowerCase();
  } catch {
    return void 0;
  }
}
function hasOriginPinning(args) {
  const joined = args.join(" ");
  return ORIGIN_FLAG_PATTERNS.some((p) => p.test(joined));
}
var mcp023 = defineCheck({
  id: "MCP-023",
  name: "Streamable-HTTP Server Without Origin Pinning",
  category: "mcp",
  severity: "warning",
  description: "Detect streamable-HTTP MCP servers reachable on a non-localhost URL with no apparent Origin/host allowlist \u2014 DNS-rebinding hardening required by the 2025 MCP spec",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (server.transport !== "streamable-http") continue;
        if (!server.url) continue;
        const host = extractHostname(server.url);
        if (!host || LOCALHOST_HOSTS.has(host)) continue;
        if (hasOriginPinning(server.args ?? [])) continue;
        evidence.push({
          file: config.filePath,
          snippet: `Server "${server.name}" (${server.transport}): ${server.url}`,
          detail: `Streamable-HTTP server reachable at "${host}" with no --allowed-origins / --host pin in args. The 2025 MCP spec requires Origin validation and localhost binding to prevent DNS rebinding attacks against local servers; remote servers must validate Origin per spec \xA76.2`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Streamable-HTTP MCP servers are localhost-bound or carry an explicit origin allowlist",
      failed: (n) => `Found ${n} streamable-HTTP MCP server(s) without visible Origin/host pinning`,
      fixDescription: "For local servers, pin the URL to 127.0.0.1/localhost. For remote servers, configure an allowed-origins allowlist and enforce Origin validation server-side."
    });
  }
});

// src/checks/mcp/mcp-024-tool-description-injection.ts
init_tool_baseline();

// src/mcp/injection-directives.ts
var DIRECTIVE_PATTERNS = [
  { re: /\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\b/i, label: 'instruction-override ("ignore previous")' },
  { re: /\bdisregard\s+(?:all\s+)?(?:previous|prior|above|earlier|the)\b/i, label: 'instruction-override ("disregard\u2026")' },
  { re: /\b(?:always|must)\s+(?:prefer|use|call|choose|select)\s+this\b/i, label: 'tool-priority directive ("always use this")' },
  { re: /\bprefer(?:red)?\s+(?:to\s+)?(?:use\s+)?this\s+tool\b/i, label: 'tool-priority directive ("prefer this tool")' },
  { re: /\bthis\s+tool\s+should\s+be\s+(?:prioriti[sz]ed|preferred|used\s+first)\b/i, label: 'tool-priority directive ("should be prioritized")' },
  { re: /\buse\s+this\s+tool\s+first\b/i, label: 'tool-priority directive ("use this tool first")' },
  { re: /\b(?:instead\s+of|rather\s+than)\s+(?:any\s+)?other\s+tools?\b/i, label: 'tool-priority directive ("instead of other tools")' },
  { re: /\bdo\s+not\s+(?:mention|tell|inform|reveal|disclose|notify)\b/i, label: 'concealment directive ("do not mention")' },
  { re: /\bdon'?t\s+(?:mention|tell|inform|reveal|disclose|notify)\b/i, label: `concealment directive ("don't tell")` },
  { re: /\bwithout\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?user\b/i, label: 'concealment directive ("without telling the user")' },
  { re: /(?:^|[.!?]\s+|\n)\s*(?:system|assistant|developer)\s*:/i, label: 'role-spoofing prefix ("system:" / "assistant:")' },
  { re: /\[\s*(?:system|admin|important|developer)\s+(?:instruction|prompt|note|message)\b/i, label: 'injected-instruction marker ("[SYSTEM INSTRUCTION\u2026]")' },
  // Role + instruction-noun lead-in ("Assistant instruction", "developer directive") — the
  // role-spoofing prefix above only fires when the role word is immediately followed by a
  // colon, so "Assistant instruction: …" slips past it. Restricted to assistant/developer +
  // instruction/directive: these collocations are essentially never benign, whereas
  // "system command" / "system message" / "model prompt" routinely are.
  { re: /\b(?:assistant|developer)\s+(?:instructions?|directives?)\b/i, label: 'injected-instruction lead-in ("assistant instruction\u2026")' },
  // Bare "Instruction: <Capitalised directive>" prefix. The trailing "\s+[A-Z][a-z]" keeps
  // this off JS/JSON property keys (`instruction: "value"` → colon is followed by a quote,
  // not a capitalised word), so it only matches an imperative directive sentence.
  { re: /\b[Ii]nstructions?\s*:\s+[A-Z][a-z]/, label: 'directive prefix ("Instruction: \u2026")' },
  { re: /<\/?(?:important|system|instructions?|secret|hidden)\b[^>]*>/i, label: "hidden-instruction tag (<important>/<system>)" },
  { re: /\byou\s+must\s+(?:always|first|immediately|secretly)\b/i, label: 'coercive directive ("you must always\u2026")' }
];
var INVISIBLE_RANGES = [
  [173, 173],
  [6158, 6158],
  [8203, 8207],
  [8234, 8238],
  [8288, 8292],
  [8294, 8297],
  [65279, 65279],
  [917504, 917631]
];
function isInvisibleCodePoint(cp) {
  return INVISIBLE_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi);
}
function describeChar(cp) {
  return `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}
function analyzeText(text, opts = {}) {
  const reasons = [];
  for (const { re, label } of DIRECTIVE_PATTERNS) {
    if (re.test(text)) reasons.push(label);
  }
  if (opts.checkInvisible) {
    const invisible = /* @__PURE__ */ new Set();
    for (const ch of text) {
      const cp = ch.codePointAt(0) ?? 0;
      if (isInvisibleCodePoint(cp)) invisible.add(describeChar(cp));
    }
    if (invisible.size > 0) {
      reasons.push(`invisible/bidi characters (${[...invisible].join(", ")})`);
    }
  }
  return reasons;
}

// src/checks/mcp/mcp-024-tool-description-injection.ts
var analyzeDescription = (description) => analyzeText(description, { checkInvisible: true });
var mcp024 = defineCheck({
  id: "MCP-024",
  name: "Tool Description Injection",
  category: "mcp",
  severity: "critical",
  description: "Detect prompt-injection / toolflow-hijacking directives and hidden Unicode embedded in MCP tool descriptions",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const sources = ctx.mcpServerSources ?? [];
    for (const source of sources) {
      const tools = source.tools ?? (source.sourceCode ? extractToolDefinitions(source.sourceCode) : []);
      if (tools.length === 0) continue;
      for (const tool of tools) {
        if (!tool.description) continue;
        const reasons = analyzeDescription(tool.description);
        if (reasons.length === 0) continue;
        evidence.push({
          file: source.localPath ?? source.packageName ?? source.serverName,
          snippet: `Tool "${tool.name}" in server "${source.serverName}"`,
          detail: `Tool description contains ${reasons.join("; ")} \u2014 the client LLM reads this verbatim when selecting tools, so it can be steered or kept silent without the user's knowledge`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No MCP tool descriptions contain injection directives or hidden characters",
      failed: (n) => `Found ${n} MCP tool description(s) with injection directives or hidden Unicode \u2014 toolflow-hijacking risk`,
      fixDescription: "Remove imperative/priority directives and any invisible characters from tool descriptions; descriptions should neutrally state what the tool does, not how the model must behave"
    });
  }
});

// src/checks/mcp/mcp-025-tool-name-collision.ts
init_tool_baseline();
var MIN_LEN_FOR_NEAR_DUP = 4;
var NEAR_DUP_MAX_DISTANCE = 1;
var mcp025 = defineCheck({
  id: "MCP-025",
  name: "Cross-Server Tool-Name Collision",
  category: "mcp",
  severity: "warning",
  description: "Detect identical or near-identical tool names exposed by different MCP servers, enabling tool shadowing",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const sources = ctx.mcpServerSources ?? [];
    const evidence = [];
    const refs = [];
    for (const source of sources) {
      const tools = source.tools ?? (source.sourceCode ? extractToolDefinitions(source.sourceCode) : []);
      for (const tool of tools) {
        refs.push({ server: source.serverName, tool: tool.name });
      }
    }
    const byName = /* @__PURE__ */ new Map();
    for (const { server, tool } of refs) {
      if (!byName.has(tool)) byName.set(tool, /* @__PURE__ */ new Set());
      byName.get(tool).add(server);
    }
    const reportedNames = /* @__PURE__ */ new Set();
    for (const [tool, servers] of byName) {
      if (servers.size >= 2) {
        reportedNames.add(tool);
        evidence.push({
          file: [...servers].join(", "),
          snippet: `Tool "${tool}"`,
          detail: `Tool name "${tool}" is exposed by ${servers.size} servers (${[...servers].join(", ")}) \u2014 tool routing is ambiguous and one server can shadow another`
        });
      }
    }
    const uniqueRefs = dedupeByServerTool(refs);
    const seenPairs = /* @__PURE__ */ new Set();
    for (let i = 0; i < uniqueRefs.length; i++) {
      for (let j = i + 1; j < uniqueRefs.length; j++) {
        const a = uniqueRefs[i];
        const b = uniqueRefs[j];
        if (a.server === b.server) continue;
        if (a.tool === b.tool) continue;
        if (reportedNames.has(a.tool) || reportedNames.has(b.tool)) continue;
        if (a.tool.length < MIN_LEN_FOR_NEAR_DUP || b.tool.length < MIN_LEN_FOR_NEAR_DUP) continue;
        if (Math.abs(a.tool.length - b.tool.length) > NEAR_DUP_MAX_DISTANCE) continue;
        if (levenshteinDistance(a.tool, b.tool) > NEAR_DUP_MAX_DISTANCE) continue;
        const pairKey = [`${a.server}:${a.tool}`, `${b.server}:${b.tool}`].sort().join("|");
        if (seenPairs.has(pairKey)) continue;
        seenPairs.add(pairKey);
        evidence.push({
          file: `${a.server}, ${b.server}`,
          snippet: `"${a.tool}" vs "${b.tool}"`,
          detail: `Tool "${a.tool}" (server "${a.server}") and "${b.tool}" (server "${b.server}") differ by one character \u2014 likely tool-shadowing / impersonation`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No tool-name collisions across MCP servers",
      failed: (n) => `Found ${n} tool-name collision(s)/near-collision(s) across MCP servers \u2014 shadowing risk`,
      fixDescription: "Namespace tools per server (e.g. prefix with the server name) so identical tool names cannot collide, and remove servers exposing impersonating tool names"
    });
  }
});
function dedupeByServerTool(refs) {
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  for (const ref of refs) {
    const key = `${ref.server}\0${ref.tool}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(ref);
  }
  return out;
}

// src/checks/mcp/mcp-026-slash-command-overlap.ts
init_tool_baseline();
var mcp026 = defineCheck({
  id: "MCP-026",
  name: "Slash-Command / Prompt Overlap",
  category: "mcp",
  severity: "info",
  description: "Detect identical prompt/slash-command names registered by different MCP servers",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const byName = /* @__PURE__ */ new Map();
    for (const source of ctx.mcpServerSources ?? []) {
      if (!source.sourceCode) continue;
      for (const prompt of extractPromptNames(source.sourceCode)) {
        if (!byName.has(prompt)) byName.set(prompt, /* @__PURE__ */ new Set());
        byName.get(prompt).add(source.serverName);
      }
    }
    const evidence = [];
    for (const [prompt, servers] of byName) {
      if (servers.size < 2) continue;
      evidence.push({
        file: [...servers].join(", "),
        snippet: `Prompt/command "${prompt}"`,
        detail: `Slash-command "${prompt}" is registered by ${servers.size} servers (${[...servers].join(", ")}) \u2014 command routing is ambiguous and one server can shadow another's command`
      });
    }
    return h.fromEvidence(evidence, {
      passed: "No prompt/slash-command name collisions across MCP servers",
      failed: (n) => `Found ${n} prompt/slash-command collision(s) across MCP servers`,
      fixDescription: "Namespace prompts per server (e.g. prefix with the server name) so slash-command names cannot collide across servers"
    });
  }
});

// src/checks/mcp/mcp-027-vulnerable-version.ts
init_database2();

// src/core/semver.ts
var SEMVER_RE3 = /^v?(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.]+))?/;
function parseSemVer(version) {
  const m = SEMVER_RE3.exec(version.trim());
  if (!m) return null;
  return {
    major: parseInt(m[1], 10),
    minor: parseInt(m[2], 10),
    patch: parseInt(m[3], 10),
    prerelease: m[4] ?? void 0,
    raw: version.trim()
  };
}
function compareSemVer(a, b) {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  if (!a.prerelease && b.prerelease) return 1;
  if (a.prerelease && !b.prerelease) return -1;
  if (a.prerelease && b.prerelease) {
    const aParts = a.prerelease.split(".");
    const bParts = b.prerelease.split(".");
    const len = Math.max(aParts.length, bParts.length);
    for (let i = 0; i < len; i++) {
      if (i >= aParts.length) return -1;
      if (i >= bParts.length) return 1;
      const aNum = parseInt(aParts[i], 10);
      const bNum = parseInt(bParts[i], 10);
      const aIsNum = !isNaN(aNum);
      const bIsNum = !isNaN(bNum);
      if (aIsNum && bIsNum) {
        if (aNum !== bNum) return aNum < bNum ? -1 : 1;
      } else if (aIsNum) {
        return -1;
      } else if (bIsNum) {
        return 1;
      } else {
        if (aParts[i] < bParts[i]) return -1;
        if (aParts[i] > bParts[i]) return 1;
      }
    }
  }
  return 0;
}
function parseComparator(token) {
  const m = /^([<>]=?|=)?(.+)$/.exec(token.trim());
  if (!m) return null;
  const op = m[1] || "=";
  const ver = parseSemVer(m[2]);
  if (!ver) return null;
  return { op, ver };
}
function matchComparator(version, comp) {
  const cmp = compareSemVer(version, comp.ver);
  switch (comp.op) {
    case "=":
      return cmp === 0;
    case "<":
      return cmp === -1;
    case "<=":
      return cmp <= 0;
    case ">":
      return cmp === 1;
    case ">=":
      return cmp >= 0;
  }
}
function satisfies(version, constraint) {
  const ver = parseSemVer(version);
  if (!ver) return false;
  const tokens = constraint.trim().split(/\s+/);
  for (const token of tokens) {
    const comp = parseComparator(token);
    if (!comp) return false;
    if (!matchComparator(ver, comp)) return false;
  }
  return true;
}

// src/mcp/mcp-state-store.ts
import { mkdir as mkdir5, readFile as readFile6, writeFile as writeFile6 } from "fs/promises";
import { join as join42 } from "path";
import { homedir as homedir4 } from "os";
var FileMcpStateStore = class {
  constructor(baseDir) {
    this.baseDir = baseDir;
  }
  async load(key) {
    try {
      return JSON.parse(await readFile6(join42(this.baseDir, `${sanitizeKey(key)}.json`), "utf-8"));
    } catch {
      return null;
    }
  }
  async save(key, value) {
    await mkdir5(this.baseDir, { recursive: true });
    await writeFile6(join42(this.baseDir, `${sanitizeKey(key)}.json`), JSON.stringify(value, null, 2), "utf-8");
  }
};
function defaultMcpStateStore() {
  return new FileMcpStateStore(join42(homedir4(), ".vaso", "mcp-state"));
}
function sanitizeKey(key) {
  return key.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 120) || "state";
}

// src/checks/mcp/mcp-027-vulnerable-version.ts
var NPM_RUNNERS = /* @__PURE__ */ new Set(["npx", "npx.cmd"]);
var SKIP_ARGS = /* @__PURE__ */ new Set(["-y", "--yes"]);
function parsePackageSpec(spec) {
  const at = spec.lastIndexOf("@");
  if (at > 0) return { name: spec.slice(0, at), version: spec.slice(at + 1) };
  return { name: spec };
}
function npmInstallSpec(server) {
  const cmd = server.command ? basename10(server.command) : void 0;
  if (!cmd || !NPM_RUNNERS.has(cmd)) return void 0;
  for (const arg of server.args ?? []) {
    if (arg.startsWith("-") || SKIP_ARGS.has(arg)) continue;
    return arg;
  }
  return void 0;
}
var mcp027 = defineCheck({
  id: "MCP-027",
  name: "Vulnerable / Rolled-Back MCP Version",
  category: "mcp",
  severity: "warning",
  description: "Detect MCP server packages pinned to a known-vulnerable version or rolled back below a previously-seen version",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    let maxSeverity = "warning";
    const db = getAdvisoryDatabase();
    const depAdvisories = db.advisories.filter((a) => a.affectedDependency);
    const store = ctx.mcpStateStore ?? defaultMcpStateStore();
    for (const config of ctx.mcpConfigs ?? []) {
      for (const server of config.servers) {
        const spec = npmInstallSpec(server);
        if (!spec) continue;
        const { name, version } = parsePackageSpec(spec);
        if (!version) continue;
        const parsed = parseSemVer(version);
        for (const adv of depAdvisories) {
          const dep = adv.affectedDependency;
          if (dep.name !== name) continue;
          if (!satisfies(version, dep.versionConstraint)) continue;
          if (adv.severity === "critical") maxSeverity = "critical";
          evidence.push({
            file: config.filePath,
            snippet: `Server "${server.name}": ${name}@${version}`,
            detail: `${adv.id}: ${name}@${version} is affected by "${adv.title}" (severity: ${adv.severity}${adv.fixedVersion ? `, fix: ${adv.fixedVersion}` : ""})`
          });
        }
        if (parsed) {
          const key = `version-${name}`;
          const prev = await store.load(key);
          const prevParsed = prev?.highest ? parseSemVer(prev.highest) : null;
          if (prevParsed && compareSemVer(parsed, prevParsed) < 0) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${name}@${version}`,
              detail: `${name} was rolled back from ${prev.highest} to ${version} \u2014 a downgrade can silently re-introduce a fixed vulnerability`
            });
          }
          const highest = prevParsed && compareSemVer(prevParsed, parsed) >= 0 ? prev.highest : version;
          await store.save(key, { highest });
        }
      }
    }
    return h.result({
      passed: evidence.length === 0,
      severity: maxSeverity,
      message: evidence.length === 0 ? "No MCP server packages are on a known-vulnerable or rolled-back version" : `Found ${evidence.length} MCP server version issue(s) \u2014 known-vulnerable or rolled-back package(s)`,
      evidence,
      fixDescription: "Pin MCP servers to a current, non-vulnerable release; never roll a server back below a version that carried a security fix"
    });
  }
});
function basename10(p) {
  const idx = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
  return idx >= 0 ? p.slice(idx + 1) : p;
}

// src/checks/mcp/mcp-028-config-drift.ts
var DRIFT_KEY = "config-drift";
var PACKAGE_RUNNERS = /* @__PURE__ */ new Set(["npx", "npx.cmd", "pnpm", "bunx", "uvx", "uv", "pipx"]);
var AUTH_ENV_RE = /(authorization|auth[_-]?token|access[_-]?token|api[_-]?key|apikey|bearer|oauth|client[_-]?secret|secret|token|password|credential)/i;
function basename11(p) {
  const idx = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
  return idx >= 0 ? p.slice(idx + 1) : p;
}
function isPinned(server) {
  const cmd = server.command ? basename11(server.command) : void 0;
  if (!cmd || !PACKAGE_RUNNERS.has(cmd)) return true;
  for (const arg of server.args ?? []) {
    if (arg.startsWith("-") || arg === "run" || arg === "tool") continue;
    return arg.lastIndexOf("@") > 0;
  }
  return true;
}
function schemeOf(url) {
  if (!url) return "none";
  if (/^https:\/\//i.test(url)) return "https";
  if (/^http:\/\//i.test(url)) return "http";
  return "none";
}
function hasAuth(server) {
  for (const [key, value] of Object.entries(server.env ?? {})) {
    if (AUTH_ENV_RE.test(key) && String(value).trim().length > 0) return true;
  }
  if (server.url && /\/\/[^/@]+:[^/@]+@/.test(server.url)) return true;
  if (server.url && /[?&](access_token|token|api_key|apikey|auth)=/i.test(server.url)) return true;
  return false;
}
function fingerprint(server) {
  return {
    transport: server.transport,
    pinned: isPinned(server),
    scheme: schemeOf(server.url),
    hasAuth: hasAuth(server)
  };
}
function buildSnapshot(ctxConfigs) {
  const snap = {};
  for (const config of ctxConfigs) {
    for (const server of config.servers) {
      snap[`${config.source}::${server.name}`] = fingerprint(server);
    }
  }
  return snap;
}
var mcp028 = defineCheck({
  id: "MCP-028",
  name: "MCP Configuration Drift",
  category: "mcp",
  severity: "warning",
  description: "Detect security regressions in MCP config since the last scan (new server, lost version pin, https\u2192http, removed auth)",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const configs = ctx.mcpConfigs ?? [];
    const store = ctx.mcpStateStore ?? defaultMcpStateStore();
    const current = buildSnapshot(configs);
    const baseline = await store.load(DRIFT_KEY);
    await store.save(DRIFT_KEY, current);
    if (!baseline) {
      return h.result({
        passed: true,
        severity: "info",
        message: "MCP configuration baseline established \u2014 drift will be detected on subsequent scans"
      });
    }
    const evidence = [];
    for (const [key, now] of Object.entries(current)) {
      const before = baseline[key];
      if (!before) {
        evidence.push({ file: key, detail: `New MCP server "${key}" appeared since the last scan` });
        continue;
      }
      if (before.pinned && !now.pinned) {
        evidence.push({ file: key, detail: `MCP server "${key}" lost its version pin since the last scan` });
      }
      if (before.scheme === "https" && now.scheme === "http") {
        evidence.push({ file: key, detail: `MCP server "${key}" was downgraded from https to http since the last scan` });
      }
      if (before.hasAuth && !now.hasAuth) {
        evidence.push({ file: key, detail: `MCP server "${key}" had its authentication removed since the last scan` });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No security regressions in MCP configuration since the last scan",
      failed: (n) => `Found ${n} security regression(s) in MCP configuration since the last scan`
    });
  }
});

// src/checks/mcp/mcp-029-remote-server-no-auth.ts
var AUTH_ENV_RE2 = /(authorization|auth[_-]?token|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|apikey|bearer|oauth|client[_-]?secret|secret|token|password|passwd|credential)/i;
var AUTH_ARG_RE = /^(--header|--auth|--authorization|--token|--bearer|--api-?key|-H)$/i;
var QUERY_TOKEN_KEYS = /* @__PURE__ */ new Set([
  "token",
  "access_token",
  "api_key",
  "apikey",
  "key",
  "auth",
  "authorization"
]);
function parseUrl(url) {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}
function isLoopbackHost(host) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  return h === "localhost" || h === "127.0.0.1" || h === "::1" || h.endsWith(".localhost");
}
function hasAuthSignal(server, parsed) {
  for (const [key, value] of Object.entries(server.env ?? {})) {
    if (AUTH_ENV_RE2.test(key) && String(value).trim().length > 0) return true;
  }
  for (const [key, value] of Object.entries(server.headers ?? {})) {
    if (AUTH_ENV_RE2.test(key) && String(value).trim().length > 0) return true;
    if (/bearer\s+\S/i.test(String(value))) return true;
  }
  if (parsed) {
    if (parsed.username || parsed.password) return true;
    for (const k of parsed.searchParams.keys()) {
      if (QUERY_TOKEN_KEYS.has(k.toLowerCase())) return true;
    }
  }
  if (server.args?.some((a) => AUTH_ARG_RE.test(a))) return true;
  if (server.args?.some((a) => /authorization\s*:/i.test(a) || /bearer\s+/i.test(a))) return true;
  return false;
}
var mcp029 = defineCheck({
  id: "MCP-029",
  name: "Remote Server Without Authentication",
  category: "mcp",
  severity: "critical",
  description: "Detect remotely-reachable MCP servers (SSE / streamable-HTTP / http(s)) configured with no authentication credentials",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.mcpConfigs ?? []) {
      for (const server of config.servers) {
        const isRemoteTransport = server.transport === "sse" || server.transport === "streamable-http";
        const parsed = server.url ? parseUrl(server.url) : null;
        const isHttpUrl = parsed?.protocol === "http:" || parsed?.protocol === "https:";
        if (!isRemoteTransport && !isHttpUrl) continue;
        if (!parsed) continue;
        if (isLoopbackHost(parsed.hostname)) continue;
        if (hasAuthSignal(server, parsed)) continue;
        evidence.push({
          file: config.filePath,
          snippet: `Server "${server.name}": ${server.transport} ${parsed.origin}`,
          detail: `Remote MCP server "${server.name}" (${parsed.host}) is configured with no authentication \u2014 any party that can reach this endpoint can invoke its tools, and a MITM can impersonate it`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All remotely-reachable MCP servers carry authentication credentials",
      failed: (n) => `Found ${n} remote MCP server(s) configured without authentication`,
      fixDescription: "Require authentication on the server and supply credentials in the client config (Authorization header or OAuth token); never expose an unauthenticated MCP endpoint off-host"
    });
  }
});

// src/checks/mcp/mcp-030-untrusted-installer-source.ts
var PACKAGE_RUNNERS2 = /* @__PURE__ */ new Set([
  "npx",
  "npx.cmd",
  "pnpm",
  "pnpm.cmd",
  "bunx",
  "yarn",
  "uvx",
  "uv",
  "pipx",
  "pip",
  "pip3",
  "deno"
]);
var SKIP_ARGS2 = /* @__PURE__ */ new Set(["-y", "--yes", "run", "tool", "dlx", "add", "install", "exec", "--"]);
function classifyUntrustedSource(spec) {
  if (/^git(\+|:)/i.test(spec) || /\.git(#.*)?$/i.test(spec)) {
    return { label: "git source" };
  }
  if (/^(github|gitlab|bitbucket|gist):/i.test(spec)) {
    return { label: "VCS shorthand source" };
  }
  if (/^https?:\/\//i.test(spec)) {
    return { label: "remote URL / tarball source" };
  }
  if (/^file:/i.test(spec) || /^(\/|\.\/|\.\.\/|~\/)/.test(spec)) {
    return { label: "local path source" };
  }
  return null;
}
function firstInstallSpec(server) {
  for (const arg of server.args ?? []) {
    if (arg.startsWith("-")) continue;
    if (SKIP_ARGS2.has(arg)) continue;
    return arg;
  }
  return void 0;
}
var mcp030 = defineCheck({
  id: "MCP-030",
  name: "Untrusted Installer Source",
  category: "mcp",
  severity: "warning",
  description: "Detect MCP servers installed via a package runner from a non-registry source (git URL, remote tarball, or local path)",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.mcpConfigs ?? []) {
      for (const server of config.servers) {
        const cmd = server.command ? basename12(server.command) : void 0;
        if (!cmd || !PACKAGE_RUNNERS2.has(cmd)) continue;
        const spec = firstInstallSpec(server);
        if (!spec) continue;
        const classified = classifyUntrustedSource(spec);
        if (!classified) continue;
        evidence.push({
          file: config.filePath,
          snippet: `Server "${server.name}": ${cmd} \u2026 ${spec}`,
          detail: `MCP server "${server.name}" is installed from a ${classified.label} (${spec}) rather than a registry package \u2014 the code is fetched outside registry provenance and escapes version/advisory checks`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All package-runner MCP servers install from registry packages",
      failed: (n) => `Found ${n} MCP server(s) installed from an untrusted (non-registry) source`,
      fixDescription: "Install MCP servers from a pinned registry package (e.g. npx pkg@1.2.3); avoid git URLs, remote tarballs, and local paths as the install source"
    });
  }
});
function basename12(p) {
  const idx = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
  return idx >= 0 ? p.slice(idx + 1) : p;
}

// src/checks/mcp/mcp-031-filesystem-sensitive-path.ts
var mcp031 = defineCheck({
  id: "MCP-031",
  name: "Filesystem Server Sensitive-Path Scope",
  category: "mcp",
  severity: "critical",
  description: "Detect MCP servers granted access to credential stores or shell startup files (~/.ssh, ~/.aws, ~/.bashrc, /etc)",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.mcpConfigs ?? []) {
      for (const server of config.servers) {
        const candidates = [];
        if (server.command) candidates.push(server.command);
        if (server.args) candidates.push(...server.args);
        const hits = /* @__PURE__ */ new Map();
        for (const arg of candidates) {
          for (const label of classifySensitivePath(arg)) {
            if (!hits.has(label)) hits.set(label, /* @__PURE__ */ new Set());
            hits.get(label).add(arg);
          }
        }
        for (const [label, args] of hits) {
          evidence.push({
            file: config.filePath,
            snippet: `Server "${server.name}": ${[...args].join(", ")}`,
            detail: `MCP server "${server.name}" is scoped to ${label} \u2014 a poisoned tool or injected instruction can use this to gain persistence, exfiltrate credentials, or achieve code execution`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No MCP servers are scoped to credential stores or shell startup files",
      failed: (n) => `Found ${n} MCP server path grant(s) reaching credential stores or shell startup files`,
      fixDescription: "Restrict the server to a dedicated project/workspace directory; never grant an MCP server access to ~/.ssh, ~/.aws, ~/.gnupg, shell rc files, or /etc"
    });
  }
});

// src/checks/mcp/mcp-032-env-dump-tool.ts
var DUMP_PATTERNS = [
  // Whole `process.env` object referenced (not `process.env.SPECIFIC` / `[...]`).
  { re: /process\.env(?!\s*\.\s*[A-Za-z_$])(?!\s*\[)/, label: "returns/serializes the whole process.env" },
  // Python servers (source may be resolved locally).
  { re: /\bos\.environ(?!\s*\.\s*get)(?!\s*\[)/, label: "returns the whole os.environ" },
  { re: /\bdict\(\s*os\.environ\s*\)/, label: "serializes os.environ" },
  // Shell environment dump.
  { re: /\b(printenv|\/usr\/bin\/env|\benv\b\s*\|)/, label: "runs a shell environment dump (printenv/env)" }
];
var mcp032 = defineCheck({
  id: "MCP-032",
  name: "Environment-Dump Tool",
  category: "mcp",
  severity: "warning",
  description: "Detect MCP server tools that return the entire process environment (printEnv-style credential exposure)",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    for (const source of ctx.mcpServerSources ?? []) {
      if (!source.sourceCode) continue;
      const reasons = /* @__PURE__ */ new Set();
      for (const { re, label } of DUMP_PATTERNS) {
        if (re.test(source.sourceCode)) reasons.add(label);
      }
      if (reasons.size === 0) continue;
      evidence.push({
        file: source.localPath ?? source.packageName ?? source.serverName,
        snippet: `Server "${source.serverName}"`,
        detail: `MCP server source ${[...reasons].join("; ")} \u2014 exposing the full environment leaks every secret the agent holds to the model and tool-result consumers`
      });
    }
    return h.fromEvidence(evidence, {
      passed: "No MCP server tools dump the full process environment",
      failed: (n) => `Found ${n} MCP server(s) exposing the full process environment`,
      fixDescription: "Return only the specific environment values a tool needs (e.g. process.env.API_BASE), never the whole environment object"
    });
  }
});

// src/checks/mcp/mcp-033-long-lived-token.ts
var TOKEN_ENV_RE = /(access[_-]?token|bearer[_-]?token|^token$|_token$|^bearer$|api[_-]?token)/i;
var REFRESH_OR_EXPIRY_RE = /(refresh[_-]?token|expires|expiry|_exp$|_ttl$|token[_-]?lifetime)/i;
var PLACEHOLDER_RE = /^\$\{?[A-Z0-9_]+\}?$/;
var ONE_YEAR_SECONDS = 365 * 24 * 60 * 60;
function decodeJwtExp(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return { isJwt: false };
  try {
    const json = Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf-8");
    const payload = JSON.parse(json);
    return { isJwt: true, exp: typeof payload.exp === "number" ? payload.exp : void 0 };
  } catch {
    return { isJwt: false };
  }
}
function analyzeServer(server, nowSeconds) {
  const env = server.env ?? {};
  const keys = Object.keys(env);
  const hasRefreshOrExpiry = keys.some((k) => REFRESH_OR_EXPIRY_RE.test(k));
  const evidence = [];
  for (const [key, rawValue] of Object.entries(env)) {
    if (!TOKEN_ENV_RE.test(key)) continue;
    const value = String(rawValue).trim();
    if (value.length === 0 || PLACEHOLDER_RE.test(value)) continue;
    const { isJwt, exp } = decodeJwtExp(value);
    if (isJwt) {
      if (exp === void 0) {
        evidence.push({ snippet: `${key}`, file: server.name, detail: `JWT token in ${key} has no expiry (exp) claim \u2014 it never expires` });
      } else if (exp - nowSeconds > ONE_YEAR_SECONDS) {
        const when = new Date(exp * 1e3).toISOString().slice(0, 10);
        evidence.push({ snippet: `${key}`, file: server.name, detail: `JWT token in ${key} is long-lived (expires ${when}, >1 year out)` });
      }
    } else if (!hasRefreshOrExpiry) {
      evidence.push({ snippet: `${key}`, file: server.name, detail: `Static token in ${key} with no refresh-token or expiry configured \u2014 likely a non-rotating long-lived credential` });
    }
  }
  return evidence;
}
var mcp033 = defineCheck({
  id: "MCP-033",
  name: "Long-Lived / Non-Expiring Token",
  category: "mcp",
  severity: "warning",
  description: "Detect MCP server credentials that never expire (JWT without exp / far-future exp, or static tokens with no refresh)",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const nowSeconds = Math.floor(Date.now() / 1e3);
    const evidence = [];
    for (const config of ctx.mcpConfigs ?? []) {
      for (const server of config.servers) {
        for (const ev of analyzeServer(server, nowSeconds)) {
          evidence.push({ ...ev, file: config.filePath, snippet: `Server "${server.name}": ${ev.snippet}` });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No long-lived or non-expiring MCP server tokens detected",
      failed: (n) => `Found ${n} long-lived / non-expiring MCP server token(s)`,
      fixDescription: "Use short-lived tokens with a refresh mechanism (or OAuth with expiry); avoid embedding non-expiring credentials in MCP config"
    });
  }
});

// src/checks/mcp/mcp-034-output-injection.ts
init_tool_baseline();
var mcp034 = defineCheck({
  id: "MCP-034",
  name: "Prompt-Injection Directive in Tool Output",
  category: "mcp",
  severity: "critical",
  description: "Detect prompt-injection / toolflow-hijacking directives hardcoded into the content an MCP server returns as tool results",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    const sources = ctx.mcpServerSources ?? [];
    for (const source of sources) {
      if (!source.sourceCode) continue;
      const tools = source.tools ?? extractToolDefinitions(source.sourceCode);
      const descriptions = tools.map((t) => t.description).filter((d) => !!d);
      const lines = source.sourceCode.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue;
        const reasons = analyzeText(line, { checkInvisible: true });
        if (reasons.length === 0) continue;
        if (descriptions.some((d) => trimmed.includes(d) || d.includes(trimmed))) continue;
        evidence.push({
          file: source.localPath ?? source.packageName ?? source.serverName,
          line: i + 1,
          snippet: trimmed.slice(0, 120),
          detail: `Hardcoded ${reasons.join("; ")} in server "${source.serverName}" \u2014 directives embedded in returned tool content steer the client LLM at call time (indirect prompt injection)`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No hardcoded prompt-injection directives found in MCP tool output",
      failed: (n) => `Found ${n} hardcoded prompt-injection directive(s) in MCP server output \u2014 toolflow-hijacking / indirect-injection risk`,
      fixDescription: 'Remove instruction-like directives ("ignore previous instructions", "do not reveal\u2026", role-spoofing prefixes) from content the server returns; tool results should carry data, not instructions to the model'
    });
  }
});

// src/checks/mcp/mcp-035-obfuscated-source.ts
var mcp035 = defineCheck({
  id: "MCP-035",
  name: "Obfuscated / Encoded Server Source",
  category: "mcp",
  severity: "warning",
  description: "Detect MCP server source that hides its real strings (URLs, secrets, commands) behind runtime-decoded base64/hex string-tables, evading static review",
  supportedAgents: ["mcp"],
  async run(ctx, h) {
    const evidence = [];
    let sawStringTable = false;
    for (const source of ctx.mcpServerSources ?? []) {
      if (!source.sourceCode) continue;
      const report = analyzeObfuscation(source.sourceCode);
      if (report.tier === "none") continue;
      const file = source.localPath ?? source.packageName ?? source.serverName;
      if (report.tier === "string-table") {
        sawStringTable = true;
        evidence.push({
          file,
          snippet: `Server "${source.serverName}"`,
          detail: `Encoded string-table obfuscation: ${report.decoderLabels.join(", ")} decodes ${report.encodedLiteralCount} encoded literal(s) at runtime \u2014 hides the strings the server actually uses (URLs, secrets, commands) from static review`
        });
        for (const hit of report.hits.slice(0, 5)) {
          evidence.push({ file, line: hit.line, snippet: hit.snippet, detail: hit.label });
        }
      } else {
        for (const hit of report.hits.slice(0, 5)) {
          evidence.push({
            file,
            line: hit.line,
            snippet: hit.snippet,
            detail: `${hit.label} (no runtime decoder found \u2014 unconfirmed obfuscation)`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No obfuscated/encoded MCP server source detected",
      failed: (n) => `Found ${n} obfuscation indicator(s) in MCP server source`,
      severity: sawStringTable ? "warning" : "info",
      fixDescription: "Ship MCP server source in clear text; do not decode tables of base64/hex literals at runtime \u2014 encoding hides the server\u2019s real behavior (endpoints, secrets, commands) from review"
    });
  }
});

// src/checks/mcp/index.ts
init_owasp_mcp();
var mcpChecks = [
  mcp001,
  mcp002,
  mcp003,
  mcp004,
  mcp005,
  mcp006,
  mcp007,
  mcp008,
  mcp009,
  mcp010,
  mcp011,
  mcp012,
  mcp013,
  mcp014,
  mcp015,
  mcp016,
  mcp017,
  mcp018,
  mcp019,
  mcp020,
  mcp021,
  mcp022,
  mcp023,
  mcp024,
  mcp025,
  mcp026,
  mcp027,
  mcp028,
  mcp029,
  mcp030,
  mcp031,
  mcp032,
  mcp033,
  mcp034,
  mcp035
];
applyOwaspTags(mcpChecks);

// src/checks/openclaw/posture.ts
init_utils();
function mergeConfigData(configs) {
  let merged = {};
  for (const c of configs) {
    merged = deepMerge(merged, c.data);
  }
  return merged;
}
function asRecord(v) {
  return v && typeof v === "object" && !Array.isArray(v) ? v : void 0;
}
function asBool(v) {
  if (typeof v === "boolean") return v;
  if (typeof v === "string") {
    const lower = v.toLowerCase();
    if (lower === "true" || lower === "1") return true;
    if (lower === "false" || lower === "0") return false;
  }
  return void 0;
}
function extractPosture(merged) {
  const gw = asRecord(merged.gateway);
  const auth = gw ? asRecord(gw.auth) : void 0;
  const sandbox = asRecord(merged.sandbox);
  const policy = asRecord(merged.policy);
  return {
    tls: gw ? asBool(gw.tls) : void 0,
    authMode: auth?.mode,
    gatewayHost: gw?.host,
    gatewayPort: gw?.port,
    sandboxEnabled: sandbox ? asBool(sandbox.enabled) : void 0,
    approvalRequired: policy ? asBool(policy.require_approval ?? policy.requireApproval) : void 0
  };
}
var PUBLIC_HOSTS = /* @__PURE__ */ new Set(["0.0.0.0", "::", "*"]);
function isPublic(host) {
  return host !== void 0 && PUBLIC_HOSTS.has(host);
}
function isLoopback(host) {
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
}
var AUTH_RANK = {
  none: 0,
  basic: 1,
  apikey: 2,
  api_key: 2,
  jwt: 3,
  oauth: 4,
  oauth2: 4,
  mtls: 5
};
function authRank(mode) {
  if (!mode) return void 0;
  return AUTH_RANK[mode.toLowerCase()];
}
function findDowngrades(base, override) {
  const issues = [];
  if (base.tls === true && override.tls === false) {
    issues.push("TLS disabled (base had TLS enabled)");
  }
  if (isLoopback(base.gatewayHost) && isPublic(override.gatewayHost)) {
    issues.push(`Gateway re-bound from ${base.gatewayHost} to ${override.gatewayHost} (publicly exposed)`);
  }
  if (base.sandboxEnabled === true && override.sandboxEnabled === false) {
    issues.push("Sandbox disabled (base had sandbox enabled)");
  }
  if (base.approvalRequired === true && override.approvalRequired === false) {
    issues.push("Tool approval no longer required (base required approval)");
  }
  const baseAuth = authRank(base.authMode);
  const overrideAuth = authRank(override.authMode);
  if (baseAuth !== void 0 && overrideAuth !== void 0 && overrideAuth < baseAuth) {
    issues.push(`Auth mode downgraded from ${base.authMode} to ${override.authMode}`);
  }
  return issues;
}

// src/checks/openclaw/oc-001-subagent-config-downgrade.ts
var oc001 = defineCheck({
  id: "OC-001",
  name: "Sub-Agent Config Security Downgrade",
  category: "openclaw",
  severity: "critical",
  description: "Detect when an OpenClaw sub-agent (agents/<name>/agent.{yaml,json,env}) overrides the global config to weaken security: disable TLS or sandbox, re-bind the gateway publicly, drop tool approval, or downgrade auth.",
  supportedAgents: ["openclaw"],
  async run(ctx, h) {
    const installation = ctx.installation;
    if (!installation.agentName) {
      return h.passed("Not a sub-agent installation; OC-001 does not apply");
    }
    const subAgentDir = installation.installDir;
    const globalConfigs = [];
    const subAgentConfigs = [];
    for (const c of ctx.configs) {
      if (c.filePath.startsWith(subAgentDir + "/") || c.filePath.startsWith(subAgentDir + "\\")) {
        subAgentConfigs.push(c);
      } else {
        globalConfigs.push(c);
      }
    }
    if (subAgentConfigs.length === 0 || globalConfigs.length === 0) {
      return h.passed("No sub-agent override configs to compare against global");
    }
    const basePosture = extractPosture(mergeConfigData(globalConfigs));
    const overridePosture = extractPosture(mergeConfigData([...globalConfigs, ...subAgentConfigs]));
    const issues = findDowngrades(basePosture, overridePosture);
    const evidence = issues.map((detail) => ({
      file: subAgentConfigs[0].filePath,
      detail: `Sub-agent "${installation.agentName}": ${detail}`
    }));
    return h.fromEvidence(evidence, {
      passed: `Sub-agent "${installation.agentName}" config does not weaken global security posture`,
      failed: (n) => `Sub-agent "${installation.agentName}" weakens ${n} global security setting${n === 1 ? "" : "s"}`
    });
  }
});

// src/checks/openclaw/oc-003-legacy-bot-dirs.ts
import { basename as basename13, dirname as dirname4, join as join43 } from "path";
var LEGACY_DIR_NAMES = /* @__PURE__ */ new Set([".clawdbot", ".moltbot"]);
var oc003 = defineCheck({
  id: "OC-003",
  name: "Legacy Bot Config Directory",
  category: "openclaw",
  severity: "warning",
  description: "Detect legacy `.clawdbot` / `.moltbot` config directories. The OpenClaw adapter still loads these alongside `.openclaw`, so stale or weaker configs left over from migrations remain active.",
  supportedAgents: ["openclaw"],
  async run(ctx, h) {
    const installation = ctx.installation;
    if (installation.agentName) {
      return h.passed("Sub-agent installation; OC-003 only runs at top-level");
    }
    const installDir = installation.installDir;
    const dirName = basename13(installDir);
    if (!LEGACY_DIR_NAMES.has(dirName)) {
      return h.passed("Not a legacy bot directory");
    }
    const parent = dirname4(installDir);
    const openclawDir = join43(parent, ".openclaw");
    const openclawExists = await ctx.fs.access(openclawDir);
    const detail = openclawExists ? `Legacy ${dirName} directory exists alongside .openclaw \u2014 config is still loaded by the adapter (sibling/migration leftover)` : `Legacy ${dirName} directory in use without a current .openclaw counterpart \u2014 verify intended`;
    const evidence = [{
      file: installDir,
      detail
    }];
    return h.fromEvidence(evidence, {
      passed: "No legacy bot directories detected",
      failed: () => `Legacy bot directory ${dirName} loaded by adapter`
    });
  }
});

// src/checks/openclaw/oc-004-openclaw-home-redirect.ts
var WORLD_WRITABLE_PREFIXES2 = ["/tmp/", "/var/tmp/", "/private/tmp/", "/dev/shm/"];
var oc004 = defineCheck({
  id: "OC-004",
  name: "OPENCLAW_HOME Redirects Config Loading",
  category: "openclaw",
  severity: "warning",
  description: "Detect when the OPENCLAW_HOME environment variable redirects config loading away from the user home directory, especially into world-writable locations (/tmp, /var/tmp, /dev/shm) where an attacker could plant a shadow config.",
  supportedAgents: ["openclaw"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    if (ctx.installation.agentName) {
      return h.passed("Sub-agent installation; OC-004 only runs at top-level");
    }
    const envHome = ctx.fs.getEnv("OPENCLAW_HOME");
    if (!envHome) {
      return h.passed("OPENCLAW_HOME not set");
    }
    if (ctx.installation.installDir !== envHome) {
      return h.passed("Installation not driven by OPENCLAW_HOME");
    }
    const userHome = ctx.fs.homedir();
    const insideHome = envHome.startsWith(userHome + "/");
    const worldWritable = WORLD_WRITABLE_PREFIXES2.some((p) => envHome.startsWith(p));
    if (insideHome && !worldWritable) {
      return h.passed(`OPENCLAW_HOME points inside the user home (${envHome})`);
    }
    const detail = worldWritable ? `OPENCLAW_HOME=${envHome} points to a world-writable location \u2014 any local user can plant a shadow config` : `OPENCLAW_HOME=${envHome} points outside the user home (${userHome}) \u2014 review whether the redirect is intended`;
    const evidence = [{
      file: envHome,
      detail
    }];
    return h.fromEvidence(evidence, {
      passed: "OPENCLAW_HOME not set to a risky location",
      failed: () => worldWritable ? "OPENCLAW_HOME redirects config loading into a world-writable directory" : "OPENCLAW_HOME redirects config loading outside the user home",
      severity: worldWritable ? "critical" : "warning"
    });
  }
});

// src/checks/openclaw/oc-005-profile-weaker-than-default.ts
import { basename as basename14, dirname as dirname5, join as join44 } from "path";
init_config_loader();
var CONFIG_FILENAMES6 = [
  "openclaw.json",
  "config.yaml",
  "config.json",
  "gateway.yaml",
  ".env"
];
var oc005 = defineCheck({
  id: "OC-005",
  name: "Profile Config Weaker Than Default",
  category: "openclaw",
  severity: "warning",
  description: "Detect when an `.openclaw-${profile}` config relaxes the security posture relative to the default `.openclaw` config (TLS off, gateway re-bound publicly, sandbox off, auth weakened, approval skipped).",
  supportedAgents: ["openclaw"],
  async run(ctx, h) {
    const installation = ctx.installation;
    if (installation.agentName) {
      return h.passed("Sub-agent installation; OC-005 only runs at top-level");
    }
    if (!installation.profile) {
      return h.passed("No OpenClaw profile in use");
    }
    const profileDir = installation.installDir;
    const profileDirName = basename14(profileDir);
    const expectedSuffix = `.openclaw-${installation.profile}`;
    if (profileDirName !== expectedSuffix) {
      return h.passed("Installation directory does not match the active profile");
    }
    const defaultDir = join44(dirname5(profileDir), ".openclaw");
    if (!await ctx.fs.access(defaultDir)) {
      return h.passed("No default .openclaw directory to compare against");
    }
    const defaultConfigs = [];
    for (const filename of CONFIG_FILENAMES6) {
      const filePath = join44(defaultDir, filename);
      try {
        defaultConfigs.push(await loadConfig(filePath, ctx.fs));
      } catch {
      }
    }
    if (defaultConfigs.length === 0) {
      return h.passed("Default .openclaw directory has no readable configs");
    }
    const basePosture = extractPosture(mergeConfigData(defaultConfigs));
    const overridePosture = extractPosture(mergeConfigData(ctx.configs));
    const issues = findDowngrades(basePosture, overridePosture);
    const evidence = issues.map((detail) => ({
      file: profileDir,
      detail: `Profile "${installation.profile}": ${detail}`
    }));
    return h.fromEvidence(evidence, {
      passed: `Profile "${installation.profile}" matches default security posture`,
      failed: (n) => `Profile "${installation.profile}" weakens ${n} default security setting${n === 1 ? "" : "s"}`
    });
  }
});

// src/checks/openclaw/oc-006-memory-file-permissions.ts
import { join as join45 } from "path";
init_config_writer();
var MEMORY_FILES = ["memory.json", "conversations.db"];
var oc006 = defineCheck({
  id: "OC-006",
  name: "Memory File Permissions",
  category: "openclaw",
  severity: "warning",
  description: "Verify memory.json and conversations.db are not group/world-readable. These files contain conversation history with potential PII and embedded secrets.",
  supportedAgents: ["openclaw"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    if (ctx.installation.agentName) {
      return h.passed("Sub-agent installation; OC-006 only runs at top-level");
    }
    const evidence = [];
    for (const name of MEMORY_FILES) {
      const filePath = join45(ctx.installation.installDir, name);
      if (!await ctx.fs.access(filePath)) continue;
      try {
        const stats = await ctx.fs.stat(filePath);
        const mode = stats.mode & 511;
        if (mode & 63) {
          evidence.push({
            file: filePath,
            detail: `Permissions: ${mode.toString(8)} \u2014 should be 600 (owner-only)`
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Memory files are owner-only (or absent)",
      failed: (n) => `${n} memory file${n === 1 ? "" : "s"} readable by group/other`,
      fixable: true,
      fixDescription: "chmod 600 memory.json conversations.db"
    });
  },
  async fix(ctx) {
    let fixed = 0;
    for (const name of MEMORY_FILES) {
      const filePath = join45(ctx.installation.installDir, name);
      try {
        await chmodFile(filePath, 384);
        fixed++;
      } catch {
      }
    }
    return {
      checkId: "OC-006",
      applied: fixed > 0,
      message: fixed > 0 ? `Set 0600 on ${fixed} memory file${fixed === 1 ? "" : "s"}` : "No memory files to fix"
    };
  }
});

// src/checks/openclaw/oc-007-etc-openclaw-writable.ts
import { join as join46 } from "path";
var SYSTEM_DIR = "/etc/openclaw";
var CONFIG_FILENAMES7 = [
  "openclaw.json",
  "config.yaml",
  "config.json",
  "gateway.yaml",
  ".env"
];
var oc007 = defineCheck({
  id: "OC-007",
  name: "/etc/openclaw Writable by Non-Root",
  category: "openclaw",
  severity: "critical",
  description: "Verify the system-wide /etc/openclaw directory and its config files are not group- or world-writable. A writable system config lets any local user hijack the agent.",
  supportedAgents: ["openclaw"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    if (ctx.installation.agentName) {
      return h.passed("Sub-agent installation; OC-007 only runs at top-level");
    }
    if (!await ctx.fs.access(SYSTEM_DIR)) {
      return h.passed("/etc/openclaw not present");
    }
    const evidence = [];
    try {
      const dirStats = await ctx.fs.stat(SYSTEM_DIR);
      const dirMode = dirStats.mode & 511;
      if (dirMode & 18) {
        evidence.push({
          file: SYSTEM_DIR,
          detail: `Directory permissions ${dirMode.toString(8)} \u2014 group or world writable (should be 755 or tighter)`
        });
      }
    } catch {
    }
    for (const name of CONFIG_FILENAMES7) {
      const filePath = join46(SYSTEM_DIR, name);
      if (!await ctx.fs.access(filePath)) continue;
      try {
        const stats = await ctx.fs.stat(filePath);
        const mode = stats.mode & 511;
        if (mode & 18) {
          evidence.push({
            file: filePath,
            detail: `File permissions ${mode.toString(8)} \u2014 group or world writable`
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "/etc/openclaw and its configs are not group/world writable",
      failed: (n) => `${n} entry under /etc/openclaw ${n === 1 ? "is" : "are"} writable by non-root users`
    });
  }
});

// src/checks/openclaw/index.ts
var openclawChecks = [
  oc001,
  oc003,
  oc004,
  oc005,
  oc006,
  oc007
];

// src/checks/nanoclaw/nc-001-overbroad-mount-allowlist.ts
var SENSITIVE_LITERALS = /* @__PURE__ */ new Set([
  "/",
  "/etc",
  "/etc/",
  "/root",
  "/root/",
  "/var",
  "/var/log",
  "/usr",
  "/boot",
  "/proc",
  "/sys"
]);
var SENSITIVE_HOME_SUFFIXES = [
  ".ssh",
  ".aws",
  ".gnupg",
  ".config",
  ".kube",
  ".docker",
  ".npmrc",
  ".netrc",
  ".git-credentials"
];
var ROOT_GLOBS = /* @__PURE__ */ new Set(["/*", "/**", "*", "**"]);
function expandHome(p, home) {
  if (p === "~") return home;
  if (p.startsWith("~/")) return home + p.slice(1);
  return p;
}
function classify(rawPath, home) {
  const expanded = expandHome(rawPath, home);
  const trimmed = expanded.replace(/\/+$/, "");
  if (ROOT_GLOBS.has(rawPath)) return `Root glob "${rawPath}" grants the entire filesystem`;
  if (SENSITIVE_LITERALS.has(rawPath) || SENSITIVE_LITERALS.has(rawPath + "/")) {
    return `Path "${rawPath}" exposes a sensitive system directory`;
  }
  if (trimmed === home) return `Path "${rawPath}" exposes the entire user home directory`;
  for (const suffix of SENSITIVE_HOME_SUFFIXES) {
    if (trimmed === `${home}/${suffix}` || trimmed === `/home/${suffix}` || rawPath === `~/${suffix}`) {
      return `Path "${rawPath}" exposes credentials directory ~/${suffix}`;
    }
  }
  return null;
}
var nc001 = defineCheck({
  id: "NC-001",
  name: "Overbroad Mount Allowlist",
  category: "nanoclaw",
  severity: "critical",
  description: "Detect mount-allowlist.json entries that grant the agent access to the entire filesystem, system directories (/etc, /root), or credential locations (~/.ssh, ~/.aws, ~/.gnupg).",
  supportedAgents: ["nanoclaw"],
  async run(ctx, h) {
    const evidence = [];
    const home = ctx.fs.homedir();
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith("mount-allowlist.json")) continue;
      const data = config.data;
      const candidates = [
        data.allowedPaths,
        data.allowed_paths,
        data.mounts,
        data.paths
      ].find((v) => Array.isArray(v));
      if (!candidates) continue;
      for (const entry of candidates) {
        const path = typeof entry === "string" ? entry : entry && typeof entry === "object" && "path" in entry ? entry.path : void 0;
        if (!path) continue;
        const issue = classify(path, home);
        if (issue) {
          evidence.push({ file: config.filePath, detail: issue });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Mount allowlist contains no overbroad or sensitive paths",
      failed: (n) => `Mount allowlist grants ${n} overbroad / sensitive path${n === 1 ? "" : "s"}`
    });
  }
});

// src/checks/nanoclaw/nc-002-allowlist-writable.ts
init_config_writer();
var nc002 = defineCheck({
  id: "NC-002",
  name: "Mount Allowlist File Writable",
  category: "nanoclaw",
  severity: "critical",
  description: "Verify mount-allowlist.json is not group/world-writable. A writable allowlist lets any local user grant the agent additional filesystem scope.",
  supportedAgents: ["nanoclaw"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith("mount-allowlist.json")) continue;
      try {
        const stats = await ctx.fs.stat(config.filePath);
        const mode = stats.mode & 511;
        if (mode & 18) {
          evidence.push({
            file: config.filePath,
            detail: `Permissions ${mode.toString(8)} \u2014 group or world writable (should be 600)`
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "mount-allowlist.json is not group/world writable",
      failed: () => "mount-allowlist.json is writable by other users",
      fixable: true,
      fixDescription: "chmod 600 mount-allowlist.json"
    });
  },
  async fix(ctx) {
    let fixed = 0;
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith("mount-allowlist.json")) continue;
      try {
        await chmodFile(config.filePath, 384);
        fixed++;
      } catch {
      }
    }
    return {
      checkId: "NC-002",
      applied: fixed > 0,
      message: fixed > 0 ? `Set 0600 on mount-allowlist.json` : "No allowlist file to fix"
    };
  }
});

// src/checks/nanoclaw/nc-003-nanoclaw-home-redirect.ts
var WORLD_WRITABLE_PREFIXES3 = ["/tmp/", "/var/tmp/", "/private/tmp/", "/dev/shm/"];
function isWorldWritable(path) {
  return WORLD_WRITABLE_PREFIXES3.some((p) => path.startsWith(p)) || path === "/tmp" || path === "/var/tmp";
}
var nc003 = defineCheck({
  id: "NC-003",
  name: "NANOCLAW_HOME Redirected to Risky Location",
  category: "nanoclaw",
  severity: "warning",
  description: "Detect when NANOCLAW_HOME (in `.nanoclaw.env` or the process environment) points the agent's runtime directory outside the user home, especially into world-writable locations where any local user can tamper with state and skills.",
  supportedAgents: ["nanoclaw"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    const userHome = ctx.fs.homedir();
    const sources = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith(".nanoclaw.env")) continue;
      const v = config.data.NANOCLAW_HOME;
      if (typeof v === "string" && v.trim()) {
        sources.push({ value: v.trim(), file: config.filePath });
      }
    }
    const envValue = ctx.fs.getEnv("NANOCLAW_HOME");
    if (envValue) {
      sources.push({ value: envValue, file: "<process env>" });
    }
    let highest = "warning";
    for (const { value, file } of sources) {
      const insideHome = value.startsWith(userHome + "/") || value === userHome;
      const worldWritable = isWorldWritable(value);
      if (insideHome && !worldWritable) continue;
      if (worldWritable) {
        highest = "critical";
        evidence.push({
          file,
          detail: `NANOCLAW_HOME=${value} \u2014 world-writable directory; any local user can tamper with agent state`
        });
      } else {
        evidence.push({
          file,
          detail: `NANOCLAW_HOME=${value} \u2014 outside user home (${userHome}); review whether the redirect is intended`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "NANOCLAW_HOME is unset or points inside the user home",
      failed: () => "NANOCLAW_HOME redirects the agent runtime to a risky location",
      severity: highest
    });
  }
});

// src/checks/nanoclaw/nc-004-nanoclaw-port-public-bind.ts
init_config_writer();
var PUBLIC_HOSTS2 = /* @__PURE__ */ new Set(["0.0.0.0", "::", "*"]);
var nc004 = defineCheck({
  id: "NC-004",
  name: "NANOCLAW_PORT Bound Publicly",
  category: "nanoclaw",
  severity: "warning",
  description: "Detect when NANOCLAW_HOST in `.nanoclaw.env` is set to 0.0.0.0 (or absent while NANOCLAW_PORT is set), exposing the agent listener on all network interfaces.",
  supportedAgents: ["nanoclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith(".nanoclaw.env")) continue;
      const port = config.data.NANOCLAW_PORT;
      const host = config.data.NANOCLAW_HOST;
      if (!port) continue;
      if (typeof host === "string" && PUBLIC_HOSTS2.has(host)) {
        evidence.push({
          file: config.filePath,
          detail: `NANOCLAW_HOST=${host} with NANOCLAW_PORT=${port} \u2014 listener exposed on all interfaces`
        });
      } else if (host === void 0 || typeof host === "string" && host === "") {
        evidence.push({
          file: config.filePath,
          detail: `NANOCLAW_PORT=${port} set without NANOCLAW_HOST \u2014 defaults are framework-dependent; pin NANOCLAW_HOST=127.0.0.1 explicitly`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "NANOCLAW listener is loopback-bound or not configured",
      failed: () => "NANOCLAW listener is publicly bound or unspecified",
      fixable: true,
      fixDescription: "Set NANOCLAW_HOST=127.0.0.1 in .nanoclaw.env"
    });
  },
  async fix(ctx) {
    let fixed = 0;
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith(".nanoclaw.env")) continue;
      try {
        await updateEnvFile(config.filePath, "NANOCLAW_HOST", "127.0.0.1");
        fixed++;
      } catch {
      }
    }
    return {
      checkId: "NC-004",
      applied: fixed > 0,
      message: fixed > 0 ? "Set NANOCLAW_HOST=127.0.0.1" : "No .nanoclaw.env to update"
    };
  }
});

// src/checks/nanoclaw/nc-005-skills-dir-writable.ts
import { join as join47 } from "path";
var nc005 = defineCheck({
  id: "NC-005",
  name: "Skills Directory World-Writable",
  category: "nanoclaw",
  severity: "warning",
  description: "Verify the NanoClaw skills directory is not group/world-writable. A writable skills directory lets any local user drop a malicious skill that runs in the agent context.",
  supportedAgents: ["nanoclaw"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir ?? join47(ctx.installation.installDir, "skills");
    if (!await ctx.fs.access(skillsDir)) {
      return h.passed("Skills directory not present");
    }
    const evidence = [];
    try {
      const stats = await ctx.fs.stat(skillsDir);
      const mode = stats.mode & 511;
      if (mode & 18) {
        evidence.push({
          file: skillsDir,
          detail: `Permissions ${mode.toString(8)} \u2014 directory writable by group or world; arbitrary skills can be planted`
        });
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "Skills directory has restrictive permissions",
      failed: () => "Skills directory writable by other users"
    });
  }
});

// src/checks/nanoclaw/index.ts
var nanoclawChecks = [
  nc001,
  nc002,
  nc003,
  nc004,
  nc005
];

// src/checks/ironclaw/ic-001-webhook-binding.ts
init_config_writer();
var ic001 = defineCheck({
  id: "IC-001",
  name: "HTTP Webhook Public Bind",
  category: "ironclaw",
  severity: "critical",
  description: "Check if HTTP webhook listener is bound to 0.0.0.0 (default on port 8080)",
  supportedAgents: ["ironclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const host = config.data.HTTP_HOST;
      const port = config.data.HTTP_PORT;
      if (host === "0.0.0.0" || !host && config.raw.includes("HTTP_PORT")) {
        evidence.push({
          file: config.filePath,
          detail: `HTTP webhook bound to ${host ?? "0.0.0.0 (default)"}:${port ?? "8080"} \u2014 publicly accessible`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "HTTP webhook is not publicly bound",
      failed: () => "HTTP webhook is bound to 0.0.0.0 \u2014 accessible from all network interfaces",
      fixable: true,
      fixDescription: "Set HTTP_HOST=127.0.0.1 in .env"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "IC-001",
      env: "HTTP_HOST",
      path: "http.host",
      value: "127.0.0.1",
      message: "Set HTTP_HOST=127.0.0.1"
    });
  }
});

// src/checks/ironclaw/ic-002-no-tls.ts
init_utils();
var TLS_LISTENERS = [
  { envKey: "GATEWAY_TLS_CERT", tomlPath: "gateway.tls", label: "Gateway" },
  { envKey: "HTTP_TLS_CERT", tomlPath: "http.tls", label: "HTTP Webhook" },
  { envKey: "ORCHESTRATOR_TLS_CERT", tomlPath: "orchestrator.tls", label: "Orchestrator" }
];
var ic002 = defineCheck({
  id: "IC-002",
  name: "No TLS on Listeners",
  category: "ironclaw",
  severity: "critical",
  description: "Check all 3 listeners (gateway, webhook, orchestrator) for TLS configuration",
  supportedAgents: ["ironclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      for (const listener of TLS_LISTENERS) {
        const envCert = config.data[listener.envKey];
        const tomlTls = getNestedValue(config.data, listener.tomlPath);
        const tomlCert = getNestedValue(config.data, `${listener.tomlPath}.cert`);
        const hasTls = !!(envCert || tomlTls || tomlCert);
        if (!hasTls) {
          const listenerPrefix = listener.envKey.replace("_TLS_CERT", "");
          const listenerActive = config.raw.includes(listenerPrefix) || getNestedValue(config.data, listener.tomlPath.replace(".tls", ""));
          if (listenerActive) {
            evidence.push({
              file: config.filePath,
              detail: `${listener.label} listener has no TLS certificate configured (${listener.envKey} / ${listener.tomlPath})`
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All active listeners have TLS configured",
      failed: (n) => `Found ${n} listener(s) without TLS \u2014 traffic is unencrypted`,
      fixDescription: "Configure TLS certificates for each active listener (GATEWAY_TLS_CERT, HTTP_TLS_CERT, ORCHESTRATOR_TLS_CERT)"
    });
  }
});

// src/checks/ironclaw/ic-003-orchestrator-binding.ts
init_config_writer();
init_utils();
var ic003 = defineCheck({
  id: "IC-003",
  name: "Orchestrator Public Bind",
  category: "ironclaw",
  severity: "critical",
  description: "Check if gRPC orchestrator is bound to 0.0.0.0 (port 50051)",
  supportedAgents: ["ironclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const host = config.data.ORCHESTRATOR_HOST ?? getNestedValue(config.data, "orchestrator.host");
      const port = config.data.ORCHESTRATOR_PORT ?? getNestedValue(config.data, "orchestrator.port");
      const WILDCARD_BINDS = ["0.0.0.0", "[::]", "::"];
      if (typeof host === "string" && WILDCARD_BINDS.includes(host)) {
        evidence.push({
          file: config.filePath,
          detail: `Orchestrator gRPC bound to ${host}:${port ?? "50051"} \u2014 publicly accessible`
        });
      }
      if (!host && (config.data.ORCHESTRATOR_PORT || getNestedValue(config.data, "orchestrator.port"))) {
        if (ctx.platform === "linux") {
          evidence.push({
            file: config.filePath,
            detail: `Orchestrator gRPC on port ${port ?? "50051"} with no explicit host \u2014 defaults to 0.0.0.0 on Linux`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Orchestrator gRPC is not publicly bound",
      failed: () => "Orchestrator gRPC is bound to 0.0.0.0 \u2014 accessible from all network interfaces",
      fixable: true,
      fixDescription: "Set ORCHESTRATOR_HOST=127.0.0.1 in .env or orchestrator.host in config.toml"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "IC-003",
      env: "ORCHESTRATOR_HOST",
      path: "orchestrator.host",
      value: "127.0.0.1",
      message: "Set ORCHESTRATOR_HOST=127.0.0.1"
    });
  }
});

// src/checks/ironclaw/ic-004-gateway-auth-token.ts
import { randomBytes } from "crypto";
init_config_writer();
init_utils();
var ic004 = defineCheck({
  id: "IC-004",
  name: "Gateway Auth Token Missing",
  category: "ironclaw",
  severity: "warning",
  description: "Check if GATEWAY_AUTH_TOKEN is set \u2014 ephemeral random tokens are not persistent across restarts",
  supportedAgents: ["ironclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const token = config.data.GATEWAY_AUTH_TOKEN ?? getNestedValue(config.data, "gateway.auth_token") ?? getNestedValue(config.data, "gateway.authToken");
      if (!token || token.trim() === "") {
        evidence.push({
          file: config.filePath,
          detail: "GATEWAY_AUTH_TOKEN is not set or empty \u2014 gateway uses ephemeral random tokens that are not persistent"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Gateway auth token is explicitly configured",
      failed: () => "Gateway auth token is not set \u2014 ephemeral tokens reset on restart",
      fixable: true,
      fixDescription: "Set a persistent GATEWAY_AUTH_TOKEN in .env or gateway.auth_token in config.toml"
    });
  },
  async fix(ctx) {
    const token = randomBytes(32).toString("hex");
    return fixFirstConfig(ctx.configs, {
      checkId: "IC-004",
      env: "GATEWAY_AUTH_TOKEN",
      path: "gateway.auth_token",
      value: token,
      message: "Generated and set persistent GATEWAY_AUTH_TOKEN"
    });
  }
});

// src/checks/ironclaw/ic-005-sandbox-disabled.ts
init_config_writer();
init_utils();
var ic005 = defineCheck({
  id: "IC-005",
  name: "Sandbox Disabled",
  category: "ironclaw",
  severity: "critical",
  description: "Check if sandbox isolation is explicitly disabled",
  supportedAgents: ["ironclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const sandboxEnabled = config.data.SANDBOX_ENABLED ?? getNestedValue(config.data, "sandbox.enabled");
      if (sandboxEnabled === false || sandboxEnabled === "false") {
        evidence.push({
          file: config.filePath,
          detail: "SANDBOX_ENABLED=false \u2014 all tools execute without isolation"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Sandbox is not explicitly disabled",
      failed: () => "Sandbox is disabled \u2014 tools execute without isolation",
      fixable: true,
      fixDescription: "Set SANDBOX_ENABLED=true in .env or sandbox.enabled=true in config.toml"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "IC-005",
      env: "SANDBOX_ENABLED",
      path: "sandbox.enabled",
      value: true,
      message: "Set SANDBOX_ENABLED=true"
    });
  }
});

// src/checks/ironclaw/ic-006-sandbox-full-access.ts
init_config_writer();
init_utils();
var ic006 = defineCheck({
  id: "IC-006",
  name: "Sandbox Full Access Policy",
  category: "ironclaw",
  severity: "critical",
  description: "Check if sandbox policy is set to full_access, granting unrestricted system access",
  supportedAgents: ["ironclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const policy = config.data.SANDBOX_POLICY ?? getNestedValue(config.data, "sandbox.policy");
      if (typeof policy === "string" && policy.toLowerCase() === "full_access") {
        evidence.push({
          file: config.filePath,
          detail: `SANDBOX_POLICY=${policy} \u2014 tools have unrestricted system access`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Sandbox policy is not set to full_access",
      failed: () => "Sandbox policy is full_access \u2014 tools have unrestricted system access",
      fixable: true,
      fixDescription: "Set SANDBOX_POLICY=restricted or SANDBOX_POLICY=minimal in .env or sandbox.policy in config.toml"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "IC-006",
      env: "SANDBOX_POLICY",
      path: "sandbox.policy",
      value: "restricted",
      message: "Set SANDBOX_POLICY=restricted"
    });
  }
});

// src/checks/ironclaw/ic-007-auto-approve-tools.ts
init_config_writer();
init_utils();
var ic007 = defineCheck({
  id: "IC-007",
  name: "Auto-Approve Tools Enabled",
  category: "ironclaw",
  severity: "critical",
  description: "Check if AGENT_AUTO_APPROVE_TOOLS is enabled, bypassing all tool approval prompts",
  supportedAgents: ["ironclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const autoApprove = config.data.AGENT_AUTO_APPROVE_TOOLS ?? getNestedValue(config.data, "agent.auto_approve_tools") ?? getNestedValue(config.data, "agent.autoApproveTools");
      if (autoApprove === true || autoApprove === "true") {
        evidence.push({
          file: config.filePath,
          detail: "AGENT_AUTO_APPROVE_TOOLS=true \u2014 all tool executions bypass approval prompts"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Tool auto-approval is not enabled",
      failed: () => "Tool auto-approval is enabled \u2014 all tool executions bypass user confirmation",
      fixable: true,
      fixDescription: "Set AGENT_AUTO_APPROVE_TOOLS=false in .env or agent.auto_approve_tools=false in config.toml"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "IC-007",
      env: "AGENT_AUTO_APPROVE_TOOLS",
      path: "agent.auto_approve_tools",
      value: false,
      message: "Set AGENT_AUTO_APPROVE_TOOLS=false"
    });
  }
});

// src/checks/ironclaw/ic-008-local-tools-bypass.ts
init_config_writer();
init_utils();
var ic008 = defineCheck({
  id: "IC-008",
  name: "Local Tools Bypass",
  category: "ironclaw",
  severity: "warning",
  description: "Check if ALLOW_LOCAL_TOOLS is enabled, allowing tools to execute outside the sandbox",
  supportedAgents: ["ironclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const allowLocal = config.data.ALLOW_LOCAL_TOOLS ?? getNestedValue(config.data, "tools.allow_local") ?? getNestedValue(config.data, "tools.allowLocal");
      if (allowLocal === true || allowLocal === "true") {
        evidence.push({
          file: config.filePath,
          detail: "ALLOW_LOCAL_TOOLS=true \u2014 tools can execute outside the sandbox boundary"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Local tools bypass is not enabled",
      failed: () => "Local tools bypass is enabled \u2014 tools can execute outside the sandbox",
      fixable: true,
      fixDescription: "Set ALLOW_LOCAL_TOOLS=false in .env or tools.allow_local=false in config.toml"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "IC-008",
      env: "ALLOW_LOCAL_TOOLS",
      path: "tools.allow_local",
      value: false,
      message: "Set ALLOW_LOCAL_TOOLS=false"
    });
  }
});

// src/checks/ironclaw/ic-009-secrets-key-env.ts
init_utils();
var ic009 = defineCheck({
  id: "IC-009",
  name: "Secrets Master Key in .env",
  category: "ironclaw",
  severity: "critical",
  description: "Check if SECRETS_MASTER_KEY is stored in a .env file instead of a keychain or vault",
  supportedAgents: ["ironclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const masterKey = config.data.SECRETS_MASTER_KEY ?? getNestedValue(config.data, "secrets.master_key") ?? getNestedValue(config.data, "secrets.masterKey");
      if (masterKey && masterKey.trim() !== "") {
        const isPlaceholder = /^\$\{?[A-Z_]+\}?$/.test(masterKey.trim());
        if (!isPlaceholder) {
          evidence.push({
            file: config.filePath,
            detail: `SECRETS_MASTER_KEY found in config file \u2014 should use system keychain or vault instead`
          });
        }
      }
      if (config.format === "env" && config.raw.includes("SECRETS_MASTER_KEY")) {
        const lines = config.raw.split("\n");
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          if (line.startsWith("SECRETS_MASTER_KEY") && line.includes("=")) {
            const value = line.split("=").slice(1).join("=").trim().replace(/^["']|["']$/g, "");
            if (value && !/^\$\{?[A-Z_]+\}?$/.test(value)) {
              const alreadyCaught = evidence.some((e) => e.file === config.filePath);
              if (!alreadyCaught) {
                evidence.push({
                  file: config.filePath,
                  line: i + 1,
                  snippet: `SECRETS_MASTER_KEY=${value.slice(0, 4)}${"*".repeat(Math.max(0, value.length - 4))}`,
                  detail: "Plaintext secrets master key in .env file"
                });
              }
            }
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No plaintext secrets master key found in config files",
      failed: () => "SECRETS_MASTER_KEY found in config file \u2014 should use keychain/vault",
      fixDescription: "Remove SECRETS_MASTER_KEY from .env and store it in the system keychain or a secrets vault"
    });
  }
});

// src/checks/ironclaw/ic-010-telegram-no-owner.ts
init_utils();
var ic010 = defineCheck({
  id: "IC-010",
  name: "Telegram Without Owner ID",
  category: "ironclaw",
  severity: "warning",
  description: "Check if Telegram integration is enabled but TELEGRAM_OWNER_ID is not set",
  supportedAgents: ["ironclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const telegramToken = config.data.TELEGRAM_TOKEN ?? getNestedValue(config.data, "telegram.token");
      const telegramOwnerId = config.data.TELEGRAM_OWNER_ID ?? getNestedValue(config.data, "telegram.owner_id") ?? getNestedValue(config.data, "telegram.ownerId");
      if (telegramToken && telegramToken.trim() !== "") {
        if (!telegramOwnerId || telegramOwnerId.trim() === "") {
          evidence.push({
            file: config.filePath,
            detail: "Telegram is enabled (TELEGRAM_TOKEN set) but TELEGRAM_OWNER_ID is empty \u2014 any Telegram user can interact with the bot"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Telegram owner ID is properly configured or Telegram is not enabled",
      failed: () => "Telegram is enabled without an owner ID \u2014 bot is accessible to any user",
      fixDescription: "Set TELEGRAM_OWNER_ID to your Telegram user ID in .env or telegram.owner_id in config.toml"
    });
  }
});

// src/checks/ironclaw/ic-011-broad-sandbox-domains.ts
init_utils();
var ic011 = defineCheck({
  id: "IC-011",
  name: "Broad Sandbox Domain Allowlist",
  category: "ironclaw",
  severity: "warning",
  description: "Check if SANDBOX_EXTRA_DOMAINS contains wildcard patterns that weaken network isolation",
  supportedAgents: ["ironclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const extraDomains = config.data.SANDBOX_EXTRA_DOMAINS ?? getNestedValue(config.data, "sandbox.extra_domains") ?? getNestedValue(config.data, "sandbox.extraDomains");
      if (!extraDomains) continue;
      const domainList = Array.isArray(extraDomains) ? extraDomains : extraDomains.split(",").map((d) => d.trim());
      const wildcards = domainList.filter((d) => {
        if (d === "*") return true;
        if (d.startsWith("*.")) return true;
        if (d.includes("*")) return true;
        return false;
      });
      if (wildcards.length > 0) {
        evidence.push({
          file: config.filePath,
          detail: `SANDBOX_EXTRA_DOMAINS contains wildcard patterns: ${wildcards.join(", ")} \u2014 weakens network isolation`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No wildcard patterns in sandbox domain allowlist",
      failed: () => "Sandbox domain allowlist contains wildcard patterns \u2014 network isolation is weakened",
      fixDescription: "Replace wildcard domain patterns with specific fully-qualified domain names in SANDBOX_EXTRA_DOMAINS"
    });
  }
});

// src/checks/ironclaw/ic-012-docker-auto-pull.ts
init_config_writer();
init_utils();
var ic012 = defineCheck({
  id: "IC-012",
  name: "Docker Auto-Pull Without Digest Pin",
  category: "ironclaw",
  severity: "warning",
  description: "Check if SANDBOX_AUTO_PULL is enabled without a sha256 digest pin on the Docker image",
  supportedAgents: ["ironclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const autoPull = config.data.SANDBOX_AUTO_PULL ?? getNestedValue(config.data, "sandbox.auto_pull") ?? getNestedValue(config.data, "sandbox.autoPull");
      const dockerImage = config.data.SANDBOX_DOCKER_IMAGE ?? getNestedValue(config.data, "sandbox.docker_image") ?? getNestedValue(config.data, "sandbox.dockerImage");
      if (autoPull === true || autoPull === "true") {
        const hasDigestPin = typeof dockerImage === "string" && dockerImage.includes("@sha256:");
        if (!hasDigestPin) {
          evidence.push({
            file: config.filePath,
            detail: `SANDBOX_AUTO_PULL=true with image "${dockerImage ?? "(not set)"}" \u2014 no @sha256: digest pin, vulnerable to tag mutation attacks`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Docker auto-pull is either disabled or uses a pinned image digest",
      failed: () => "Docker auto-pull is enabled without a sha256 digest pin \u2014 vulnerable to tag mutation",
      fixable: true,
      fixDescription: "Pin SANDBOX_DOCKER_IMAGE to a sha256 digest (e.g., myimage@sha256:abc123...) or disable SANDBOX_AUTO_PULL"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "IC-012",
      env: "SANDBOX_AUTO_PULL",
      path: "sandbox.auto_pull",
      value: false,
      message: "Disabled SANDBOX_AUTO_PULL"
    });
  }
});

// src/checks/ironclaw/index.ts
var ironclawChecks = [
  ic001,
  ic002,
  ic003,
  ic004,
  ic005,
  ic006,
  ic007,
  ic008,
  ic009,
  ic010,
  ic011,
  ic012
];

// src/checks/nanobot/nb-001-channel-allow-from.ts
var nb001 = defineCheck({
  id: "NB-001",
  name: "Empty Channel allowFrom",
  category: "nanobot",
  severity: "critical",
  description: "Check if any channel has an empty allowFrom list (no access control)",
  supportedAgents: ["nanobot"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const channels = config.data.channels;
      if (!channels || typeof channels !== "object") continue;
      for (const [name, ch] of Object.entries(channels)) {
        if (Array.isArray(ch.allowFrom) && ch.allowFrom.length === 0) {
          evidence.push({
            file: config.filePath,
            detail: `Channel "${name}" has empty allowFrom \u2014 anyone can send messages`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All channels have allowFrom configured",
      failed: () => "Channels with empty allowFrom detected \u2014 no access control",
      fixDescription: "Add allowed user IDs to channel allowFrom arrays"
    });
  }
});

// src/checks/nanobot/nb-002-plaintext-secrets.ts
var PLACEHOLDER_HINTS = ["your-", "xxx", "placeholder", "changeme", "TODO", "REPLACE", "<", "example"];
function looksLikePlaceholder(value) {
  const lower = value.toLowerCase();
  return PLACEHOLDER_HINTS.some((hint) => lower.includes(hint.toLowerCase()));
}
var nb002 = defineCheck({
  id: "NB-002",
  name: "Plaintext Secrets in Config",
  category: "nanobot",
  severity: "critical",
  description: "Scan config files for plaintext API keys, tokens, and passwords",
  supportedAgents: ["nanobot"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const raw = config.raw;
      if (!raw) continue;
      for (const { pattern, name } of API_KEY_PATTERNS) {
        const matches = raw.match(new RegExp(pattern.source, "g"));
        if (!matches) continue;
        for (const match of matches) {
          if (looksLikePlaceholder(match)) continue;
          evidence.push({
            file: config.filePath,
            snippet: `${match.slice(0, 8)}${"*".repeat(Math.max(0, match.length - 8))}`,
            detail: `Plaintext ${name} found in config`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No plaintext secrets found in nanobot configs",
      failed: (n) => `Found ${n} plaintext secret(s) in nanobot configs`,
      fixDescription: "Move secrets to environment variables or a secrets manager"
    });
  }
});

// src/checks/nanobot/nb-003-restrict-workspace.ts
init_utils();
init_config_writer();
var nb003 = defineCheck({
  id: "NB-003",
  name: "Workspace Restriction Disabled",
  category: "nanobot",
  severity: "warning",
  description: "Check if restrictToWorkspace is false, allowing file access outside the workspace",
  supportedAgents: ["nanobot"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const restrict = getNestedValue(config.data, "restrictToWorkspace") ?? getNestedValue(config.data, "security.restrictToWorkspace");
      if (restrict === false) {
        evidence.push({
          file: config.filePath,
          detail: "restrictToWorkspace is explicitly set to false \u2014 agent can access files outside workspace"
        });
      } else if (restrict === void 0) {
        evidence.push({
          file: config.filePath,
          detail: "restrictToWorkspace is not configured (defaults to false) \u2014 agent can access files outside workspace"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Workspace restriction is enabled",
      failed: () => "Workspace restriction is disabled \u2014 agent can access files outside its workspace",
      fixable: true,
      fixDescription: 'Set "restrictToWorkspace": true in config'
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "NB-003",
      path: "restrictToWorkspace",
      value: true,
      message: "Set restrictToWorkspace=true",
      noConfigMessage: "No JSON config file found"
    });
  }
});

// src/checks/nanobot/nb-004-exec-tool-filter.ts
init_utils();
init_config_writer();
var MIN_DENYLIST_LENGTH = 5;
var nb004 = defineCheck({
  id: "NB-004",
  name: "Weak ExecTool Denylist",
  category: "nanobot",
  severity: "critical",
  description: "Check if the ExecTool command denylist is missing, empty, or too short to be effective",
  supportedAgents: ["nanobot"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const execTool = getNestedValue(config.data, "tools.exec") ?? getNestedValue(config.data, "execTool");
      if (!execTool || typeof execTool !== "object") continue;
      const toolConfig = execTool;
      const denylist = toolConfig.denyList ?? toolConfig.denylist ?? toolConfig.blockedCommands ?? toolConfig.deny;
      if (!denylist) {
        evidence.push({
          file: config.filePath,
          detail: "ExecTool has no command denylist \u2014 all commands are allowed"
        });
      } else if (Array.isArray(denylist) && denylist.length === 0) {
        evidence.push({
          file: config.filePath,
          detail: "ExecTool denylist is empty \u2014 all commands are allowed"
        });
      } else if (Array.isArray(denylist) && denylist.length < MIN_DENYLIST_LENGTH) {
        evidence.push({
          file: config.filePath,
          detail: `ExecTool denylist has only ${denylist.length} entries (minimum ${MIN_DENYLIST_LENGTH}) \u2014 easily bypassed with path tricks like /usr/bin/rm vs rm`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "ExecTool denylist is adequately configured",
      failed: () => "ExecTool has a missing or weak command denylist",
      fixable: true,
      fixDescription: "Add a comprehensive command denylist to ExecTool config (rm, curl, wget, chmod, chown, etc.)"
    });
  },
  async fix(ctx) {
    const denyList = ["rm", "rmdir", "mkfs", "dd", "curl", "wget", "nc", "chmod", "chown", "kill", "shutdown", "reboot", "passwd"];
    return fixFirstConfig(ctx.configs, {
      checkId: "NB-004",
      path: "tools.exec.denyList",
      value: denyList,
      message: "Added comprehensive ExecTool denyList",
      noConfigMessage: "No JSON config file found"
    });
  }
});

// src/checks/nanobot/nb-005-ssrf-webfetch.ts
init_utils();
init_config_writer();
var nb005 = defineCheck({
  id: "NB-005",
  name: "WebFetchTool SSRF Risk",
  category: "nanobot",
  severity: "warning",
  description: "Check if WebFetchTool allows requests to localhost or private IPs (SSRF risk)",
  supportedAgents: ["nanobot"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const webFetch = getNestedValue(config.data, "tools.webFetch") ?? getNestedValue(config.data, "webFetchTool");
      if (!webFetch || typeof webFetch !== "object") continue;
      const toolConfig = webFetch;
      const blockedHosts = toolConfig.blockedHosts;
      const allowedHosts = toolConfig.allowedHosts;
      if (!blockedHosts && !allowedHosts) {
        evidence.push({
          file: config.filePath,
          detail: "WebFetchTool has no blockedHosts or allowedHosts \u2014 SSRF to localhost/internal IPs is possible"
        });
      } else if (Array.isArray(blockedHosts) && blockedHosts.length === 0) {
        evidence.push({
          file: config.filePath,
          detail: "WebFetchTool blockedHosts is empty \u2014 no host restrictions enforced"
        });
      } else if (Array.isArray(allowedHosts) && allowedHosts.length === 0) {
        evidence.push({
          file: config.filePath,
          detail: "WebFetchTool allowedHosts is empty \u2014 no requests will succeed but config may be misconfigured"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "WebFetchTool has host restrictions configured",
      failed: () => "WebFetchTool lacks host restrictions \u2014 SSRF risk to localhost/private IPs",
      fixable: true,
      fixDescription: "Add blockedHosts with localhost, 127.0.0.1, 169.254.169.254, and private IP ranges to WebFetchTool config"
    });
  },
  async fix(ctx) {
    const blockedHosts = ["localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254", "10.*", "172.16.*", "192.168.*"];
    return fixFirstConfig(ctx.configs, {
      checkId: "NB-005",
      path: "tools.webFetch.blockedHosts",
      value: blockedHosts,
      message: "Added SSRF-blocking host list to WebFetchTool",
      noConfigMessage: "No JSON config file found"
    });
  }
});

// src/checks/nanobot/nb-006-heartbeat-injection.ts
import { join as join48 } from "path";
var nb006 = defineCheck({
  id: "NB-006",
  name: "HEARTBEAT.md Injection Risk",
  category: "nanobot",
  severity: "warning",
  description: "Check if HEARTBEAT.md exists in workspace and is potentially writable/injectable",
  supportedAgents: ["nanobot"],
  async run(ctx, h) {
    const evidence = [];
    const installDir = ctx.installation.installDir;
    const heartbeatPath = join48(installDir, "workspace", "HEARTBEAT.md");
    if (await ctx.fs.access(heartbeatPath)) {
      try {
        const info = await ctx.fs.stat(heartbeatPath);
        const worldWritable = (info.mode & 2) !== 0;
        const groupWritable = (info.mode & 16) !== 0;
        if (worldWritable) {
          evidence.push({
            file: heartbeatPath,
            detail: "HEARTBEAT.md is world-writable \u2014 any process can inject content"
          });
        } else if (groupWritable) {
          evidence.push({
            file: heartbeatPath,
            detail: "HEARTBEAT.md is group-writable \u2014 other group members can inject content"
          });
        } else {
          evidence.push({
            file: heartbeatPath,
            detail: "HEARTBEAT.md exists in workspace \u2014 content may be loaded by the agent and could be a prompt injection vector"
          });
        }
      } catch {
        evidence.push({
          file: heartbeatPath,
          detail: "HEARTBEAT.md exists but permissions could not be checked"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No HEARTBEAT.md found in workspace",
      failed: () => "HEARTBEAT.md present in workspace \u2014 potential injection vector",
      fixable: false,
      fixDescription: "Review HEARTBEAT.md content and set restrictive file permissions (chmod 600)"
    });
  }
});

// src/checks/nanobot/nb-007-memory-injection.ts
import { join as join49 } from "path";
init_utils();
var nb007 = defineCheck({
  id: "NB-007",
  name: "MEMORY.md Prompt Injection",
  category: "nanobot",
  severity: "critical",
  description: "Check if MEMORY.md is loaded into the system prompt \u2014 persistent prompt injection vector",
  supportedAgents: ["nanobot"],
  async run(ctx, h) {
    const evidence = [];
    const installDir = ctx.installation.installDir;
    const memoryPath = join49(installDir, "workspace", "memory", "MEMORY.md");
    const memoryExists = await ctx.fs.access(memoryPath);
    let memoryEnabled = false;
    for (const config of ctx.configs) {
      const memoryConfig = getNestedValue(config.data, "memory") ?? getNestedValue(config.data, "systemPrompt.memory") ?? getNestedValue(config.data, "agent.memory");
      if (memoryConfig !== void 0 && memoryConfig !== false) {
        memoryEnabled = true;
      }
      const raw = config.raw;
      if (raw.includes("MEMORY.md") || raw.includes("memory.md")) {
        memoryEnabled = true;
      }
    }
    if (memoryExists && memoryEnabled) {
      try {
        const info = await ctx.fs.stat(memoryPath);
        const worldWritable = (info.mode & 2) !== 0;
        evidence.push({
          file: memoryPath,
          detail: worldWritable ? "MEMORY.md is world-writable AND loaded into system prompt \u2014 critical prompt injection risk" : "MEMORY.md is loaded into system prompt \u2014 content becomes part of agent instructions and can persistently alter behavior"
        });
      } catch {
        evidence.push({
          file: memoryPath,
          detail: "MEMORY.md exists and memory is enabled \u2014 persistent prompt injection vector"
        });
      }
    } else if (memoryExists) {
      evidence.push({
        file: memoryPath,
        detail: "MEMORY.md exists in workspace \u2014 verify it is not loaded into system prompt"
      });
    }
    return h.fromEvidence(evidence, {
      passed: "No MEMORY.md prompt injection risk detected",
      failed: () => "MEMORY.md may be injected into system prompt \u2014 persistent prompt injection vector",
      fixable: false,
      fixDescription: "Restrict write access to MEMORY.md (chmod 400) and audit its contents regularly"
    });
  }
});

// src/checks/nanobot/nb-008-bridge-token.ts
var nb008 = defineCheck({
  id: "NB-008",
  name: "Empty Bridge Token",
  category: "nanobot",
  severity: "warning",
  description: "Check if WhatsApp bridge is enabled but bridge_token is empty or unset",
  supportedAgents: ["nanobot"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const channels = config.data.channels;
      if (!channels || typeof channels !== "object") continue;
      for (const [name, ch] of Object.entries(channels)) {
        const type = ch.type;
        const isBridge = type === "whatsapp" || type === "whatsapp-bridge" || type === "bridge" || ch.bridge === true || name === "whatsapp" || name === "whatsapp-bridge";
        if (!isBridge) continue;
        const token = ch.bridge_token ?? ch.bridgeToken ?? ch.token;
        if (!token || typeof token === "string" && token.trim() === "") {
          evidence.push({
            file: config.filePath,
            detail: `Channel "${name}" has WhatsApp bridge enabled but bridge_token is empty or unset \u2014 unauthenticated bridge access`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All bridge channels have tokens configured",
      failed: () => "Bridge channel(s) found with empty or missing bridge_token",
      fixDescription: "Set a strong bridge_token for each WhatsApp bridge channel"
    });
  }
});

// src/checks/nanobot/nb-009-session-unencrypted.ts
import { join as join50 } from "path";
init_utils();
init_config_writer();
var nb009 = defineCheck({
  id: "NB-009",
  name: "Unencrypted Session Files",
  category: "nanobot",
  severity: "warning",
  description: "Check if session files (JSONL) exist without encryption configured",
  supportedAgents: ["nanobot"],
  async run(ctx, h) {
    const evidence = [];
    const installDir = ctx.installation.installDir;
    let encryptionEnabled = false;
    for (const config of ctx.configs) {
      const encryption = getNestedValue(config.data, "sessions.encryption") ?? getNestedValue(config.data, "session.encryption") ?? getNestedValue(config.data, "encryption");
      if (encryption === true || typeof encryption === "object" && encryption !== null) {
        encryptionEnabled = true;
        break;
      }
    }
    const sessionDirs = [
      join50(installDir, "workspace", "sessions"),
      join50(installDir, "sessions"),
      join50(installDir, ".sessions"),
      join50(installDir, "data", "sessions")
    ];
    let sessionFilesFound = false;
    for (const dir of sessionDirs) {
      try {
        const entries = await ctx.fs.readdir(dir);
        const jsonlFiles = entries.filter((f) => f.endsWith(".jsonl") || f.endsWith(".session"));
        if (jsonlFiles.length > 0) {
          sessionFilesFound = true;
          if (!encryptionEnabled) {
            evidence.push({
              file: dir,
              detail: `Found ${jsonlFiles.length} session file(s) in ${dir} without encryption \u2014 conversation history is stored in plaintext`
            });
          }
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: sessionFilesFound ? "Session files found with encryption enabled" : "No session files found",
      failed: () => "Session files found without encryption \u2014 plaintext conversation history",
      fixable: true,
      fixDescription: 'Enable session encryption in config: "sessions": { "encryption": true }'
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "NB-009",
      path: "sessions.encryption",
      value: true,
      message: "Enabled session encryption",
      noConfigMessage: "No JSON config file found"
    });
  }
});

// src/checks/nanobot/nb-010-cron-channels.ts
var nb010 = defineCheck({
  id: "NB-010",
  name: "Unrestricted Cron Channels",
  category: "nanobot",
  severity: "warning",
  description: "Check if cron jobs can target any channel or recipient without restrictions",
  supportedAgents: ["nanobot"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const cron = config.data.cron ?? config.data.cronJobs ?? config.data.scheduledTasks;
      if (!cron || typeof cron !== "object") continue;
      const jobs = Array.isArray(cron) ? cron : Object.entries(cron).map(([name, job]) => ({ name, ...job }));
      for (const job of jobs) {
        const j = job;
        const name = j.name ?? j.id ?? "unnamed";
        const targetChannel = j.channel ?? j.targetChannel;
        const allowedRecipients = j.allowedRecipients ?? j.recipients;
        if (!targetChannel && !allowedRecipients) {
          evidence.push({
            file: config.filePath,
            detail: `Cron job "${name}" has no channel or recipient restriction \u2014 can target any channel`
          });
        } else if (targetChannel === "*" || targetChannel === "all") {
          evidence.push({
            file: config.filePath,
            detail: `Cron job "${name}" targets all channels ("${targetChannel}") \u2014 unrestricted broadcast`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All cron jobs have channel/recipient restrictions",
      failed: () => "Cron job(s) found that can target any channel without restrictions",
      fixDescription: "Set explicit channel and recipient restrictions for each cron job"
    });
  }
});

// src/checks/nanobot/nb-011-no-rate-limit.ts
init_utils();
init_config_writer();
var nb011 = defineCheck({
  id: "NB-011",
  name: "No Rate Limiting",
  category: "nanobot",
  severity: "warning",
  description: "Check if no rate limiting is configured on any channel",
  supportedAgents: ["nanobot"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const globalRateLimit = getNestedValue(config.data, "rateLimit") ?? getNestedValue(config.data, "rateLimiting") ?? getNestedValue(config.data, "security.rateLimit");
      const channels = config.data.channels;
      if (!channels || typeof channels !== "object") {
        if (!globalRateLimit) {
          evidence.push({
            file: config.filePath,
            detail: "No global rate limiting configured"
          });
        }
        continue;
      }
      for (const [name, ch] of Object.entries(channels)) {
        const channelRateLimit = ch.rateLimit ?? ch.rateLimiting ?? ch.maxMessagesPerMinute;
        if (!channelRateLimit && !globalRateLimit) {
          evidence.push({
            file: config.filePath,
            detail: `Channel "${name}" has no rate limiting (no channel-level or global rate limit) \u2014 vulnerable to abuse/DoS`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Rate limiting is configured",
      failed: () => "Channel(s) found without rate limiting \u2014 vulnerable to abuse",
      fixable: true,
      fixDescription: "Add rate limiting to channels or set a global rateLimit in config"
    });
  },
  async fix(ctx) {
    const rateLimit = { maxPerMinute: 30, maxPerHour: 500 };
    return fixFirstConfig(ctx.configs, {
      checkId: "NB-011",
      path: "rateLimit",
      value: rateLimit,
      message: "Added global rate limit (30/min, 500/hr)",
      noConfigMessage: "No JSON config file found"
    });
  }
});

// src/checks/nanobot/nb-012-clawhub-npx.ts
init_utils();
var nb012 = defineCheck({
  id: "NB-012",
  name: "npx Skill Installation",
  category: "nanobot",
  severity: "warning",
  description: "Check if skills are installed via npx (supply chain risk from unverified packages)",
  supportedAgents: ["nanobot"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const skillSource = getNestedValue(config.data, "skillSource") ?? getNestedValue(config.data, "skills.source") ?? getNestedValue(config.data, "skills.installMethod");
      if (typeof skillSource === "string" && skillSource.toLowerCase().includes("npx")) {
        evidence.push({
          file: config.filePath,
          detail: `skillSource is set to "${skillSource}" \u2014 skills installed via npx without version pinning`
        });
      }
      const raw = config.raw;
      const npxPattern = /\bnpx\s+[@a-zA-Z0-9\-_/]+/g;
      const matches = raw.match(npxPattern);
      if (matches) {
        for (const match of matches) {
          evidence.push({
            file: config.filePath,
            snippet: match,
            detail: `npx invocation found: "${match}" \u2014 runs unverified remote code on every execution`
          });
        }
      }
      const skills = config.data.skills;
      if (skills && typeof skills === "object") {
        const skillEntries = Array.isArray(skills) ? skills : Object.entries(skills).map(([name, val]) => ({ name, ...typeof val === "object" && val !== null ? val : {} }));
        for (const skill of skillEntries) {
          const s = skill;
          const cmd = s.command ?? s.cmd ?? s.run;
          if (typeof cmd === "string" && cmd.includes("npx")) {
            evidence.push({
              file: config.filePath,
              snippet: String(cmd).slice(0, 120),
              detail: `Skill "${s.name ?? "unnamed"}" uses npx \u2014 supply chain risk from unverified package execution`
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No npx-based skill installations found",
      failed: (n) => `Found ${n} npx-based skill reference(s) \u2014 supply chain risk`,
      fixDescription: "Install skills locally with pinned versions instead of using npx for remote execution"
    });
  }
});

// src/checks/nanobot/index.ts
var nanobotChecks = [
  nb001,
  nb002,
  nb003,
  nb004,
  nb005,
  nb006,
  nb007,
  nb008,
  nb009,
  nb010,
  nb011,
  nb012
];

// src/checks/zeroclaw/zc-001-plaintext-api-keys.ts
init_utils();
init_config_writer();
var zc001 = defineCheck({
  id: "ZC-001",
  name: "Plaintext API Keys",
  category: "zeroclaw",
  severity: "critical",
  description: "Detect secrets.encrypt=false with API keys present in config",
  supportedAgents: ["zeroclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const encrypt = getNestedValue(config.data, "secrets.encrypt");
      if (encrypt === false || encrypt === "false") {
        for (const { pattern, name } of API_KEY_PATTERNS) {
          const matches = config.raw.match(pattern);
          if (matches) {
            evidence.push({
              file: config.filePath,
              detail: `secrets.encrypt=false and ${name} found in config`
            });
          }
        }
        if (!evidence.some((e) => e.file === config.filePath)) {
          evidence.push({
            file: config.filePath,
            detail: "secrets.encrypt=false \u2014 API keys stored in plaintext"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Secret encryption is enabled or no API keys found",
      failed: (n) => `Found ${n} config(s) with plaintext API keys`,
      fixable: true,
      fixDescription: "Set secrets.encrypt=true and re-encrypt API keys using zeroclaw secrets encrypt"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "ZC-001",
      path: "secrets.encrypt",
      value: true,
      message: 'Set secrets.encrypt=true \u2014 run "zeroclaw secrets encrypt" to encrypt existing keys',
      noConfigMessage: "No TOML config file found"
    });
  }
});

// src/checks/zeroclaw/zc-002-xor-encryption.ts
var XOR_CIPHER_PATTERN = /\benc:[A-Za-z0-9+\/=]+/g;
var zc002 = defineCheck({
  id: "ZC-002",
  name: "XOR Encryption",
  category: "zeroclaw",
  severity: "critical",
  description: "Detect values using legacy XOR cipher (enc: prefix), which is trivially reversible",
  supportedAgents: ["zeroclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const lines = config.raw.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].match(XOR_CIPHER_PATTERN);
        if (matches) {
          for (const match of matches) {
            evidence.push({
              file: config.filePath,
              line: i + 1,
              snippet: lines[i].trim().slice(0, 120),
              detail: `Legacy XOR-encrypted value found: ${match.slice(0, 20)}... \u2014 trivially reversible`
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No legacy XOR-encrypted values found",
      failed: (n) => `Found ${n} value(s) using trivially reversible XOR cipher`,
      fixDescription: "Re-encrypt secrets using zeroclaw secrets encrypt with AES-256"
    });
  }
});

// src/checks/zeroclaw/zc-003-public-bind-no-tunnel.ts
init_utils();
init_config_writer();
var zc003 = defineCheck({
  id: "ZC-003",
  name: "Public Bind Without Tunnel",
  category: "zeroclaw",
  severity: "critical",
  description: "Detect allow_public_bind=true combined with no tunnel provider configured",
  supportedAgents: ["zeroclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const publicBind = getNestedValue(config.data, "security.allow_public_bind") ?? getNestedValue(config.data, "allow_public_bind");
      const tunnelProvider = getNestedValue(config.data, "tunnel.provider");
      if (publicBind === true || publicBind === "true") {
        if (!tunnelProvider || tunnelProvider === "none") {
          evidence.push({
            file: config.filePath,
            detail: `allow_public_bind=true with tunnel.provider=${tunnelProvider ?? "not set"} \u2014 server is directly exposed to the internet`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Public bind is disabled or a tunnel provider is configured",
      failed: () => "Server is directly exposed \u2014 public bind enabled without tunnel",
      fixable: true,
      fixDescription: "Set tunnel.provider to a supported provider (e.g., cloudflare, ngrok) or disable allow_public_bind"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "ZC-003",
      path: "security.allow_public_bind",
      value: false,
      message: "Set security.allow_public_bind=false",
      noConfigMessage: "No TOML config file found"
    });
  }
});

// src/checks/zeroclaw/zc-004-pairing-disabled.ts
init_utils();
init_config_writer();
var zc004 = defineCheck({
  id: "ZC-004",
  name: "Pairing Disabled",
  category: "zeroclaw",
  severity: "warning",
  description: "Detect require_pairing=false which allows unauthenticated device connections",
  supportedAgents: ["zeroclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const requirePairing = getNestedValue(config.data, "security.require_pairing") ?? getNestedValue(config.data, "require_pairing") ?? config.data.REQUIRE_PAIRING;
      if (requirePairing === false || requirePairing === "false") {
        evidence.push({
          file: config.filePath,
          detail: "require_pairing=false \u2014 any device can connect without authentication"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Device pairing is required",
      failed: () => "Device pairing is disabled \u2014 unauthenticated connections allowed",
      fixable: true,
      fixDescription: "Set require_pairing=true to enforce device authentication"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "ZC-004",
      path: "require_pairing",
      value: true,
      message: "Set require_pairing=true",
      noConfigMessage: "No TOML config file found"
    });
  }
});

// src/checks/zeroclaw/zc-005-full-autonomy.ts
init_utils();
init_config_writer();
var zc005 = defineCheck({
  id: "ZC-005",
  name: "Full Autonomy Mode",
  category: "zeroclaw",
  severity: "critical",
  description: "Detect autonomy.level=full which bypasses all approval gates for tool execution",
  supportedAgents: ["zeroclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const autonomyLevel = getNestedValue(config.data, "autonomy.level");
      if (autonomyLevel === "full") {
        evidence.push({
          file: config.filePath,
          detail: "autonomy.level=full \u2014 all tool executions bypass approval gates"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Autonomy level is not set to full",
      failed: () => "Full autonomy mode enabled \u2014 all approval gates bypassed",
      fixable: true,
      fixDescription: 'Set autonomy.level to "supervised" or "restricted" to require approval for tool execution'
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "ZC-005",
      path: "autonomy.level",
      value: "supervised",
      message: "Set autonomy.level=supervised",
      noConfigMessage: "No TOML config file found"
    });
  }
});

// src/checks/zeroclaw/zc-006-workspace-unrestricted.ts
init_utils();
init_config_writer();
var zc006 = defineCheck({
  id: "ZC-006",
  name: "Workspace Unrestricted",
  category: "zeroclaw",
  severity: "warning",
  description: "Detect workspace_only=false which allows filesystem access beyond workspace",
  supportedAgents: ["zeroclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const workspaceOnly = getNestedValue(config.data, "workspace.workspace_only") ?? getNestedValue(config.data, "workspace_only") ?? config.data.WORKSPACE_ONLY;
      if (workspaceOnly === false || workspaceOnly === "false") {
        evidence.push({
          file: config.filePath,
          detail: "workspace_only=false \u2014 agent can access files outside the workspace directory"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Filesystem access is restricted to workspace",
      failed: () => "Filesystem access is unrestricted \u2014 agent can access files outside workspace",
      fixable: true,
      fixDescription: "Set workspace_only=true to restrict filesystem access to the workspace directory"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "ZC-006",
      path: "workspace_only",
      value: true,
      message: "Set workspace_only=true",
      noConfigMessage: "No TOML config file found"
    });
  }
});

// src/checks/zeroclaw/zc-007-channel-wildcard.ts
init_utils();
var zc007 = defineCheck({
  id: "ZC-007",
  name: "Channel Wildcard Users",
  category: "zeroclaw",
  severity: "critical",
  description: 'Detect "*" in allowed_users for any channel, granting unrestricted access',
  supportedAgents: ["zeroclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const channels = getNestedValue(config.data, "channels");
      if (channels && typeof channels === "object") {
        for (const [channelName, channelConfig] of Object.entries(channels)) {
          if (!channelConfig || typeof channelConfig !== "object") continue;
          const allowedUsers = channelConfig.allowed_users;
          if (Array.isArray(allowedUsers) && allowedUsers.includes("*")) {
            evidence.push({
              file: config.filePath,
              detail: `Channel "${channelName}" has allowed_users=["*"] \u2014 any user can interact`
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No channels have wildcard allowed_users",
      failed: (n) => `Found ${n} channel(s) with wildcard allowed_users`,
      fixDescription: 'Replace "*" in allowed_users with explicit user identifiers'
    });
  }
});

// src/checks/zeroclaw/zc-008-open-skills.ts
init_utils();
init_config_writer();
var PUBLIC_URL_PATTERNS = [
  /https?:\/\/github\.com\//,
  /https?:\/\/gitlab\.com\//,
  /https?:\/\/bitbucket\.org\//,
  /git:\/\//,
  /https?:\/\/.*\.git$/
];
var zc008 = defineCheck({
  id: "ZC-008",
  name: "Open Skills",
  category: "zeroclaw",
  severity: "warning",
  description: "Detect open skills enabled \u2014 skills installed from public repos via git clone",
  supportedAgents: ["zeroclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const openInstall = getNestedValue(config.data, "skills.open_install");
      if (openInstall === true || openInstall === "true") {
        evidence.push({
          file: config.filePath,
          detail: "skills.open_install=true \u2014 skills can be installed from any public repository"
        });
      }
      const sources = getNestedValue(config.data, "skills.sources");
      if (Array.isArray(sources)) {
        for (const source of sources) {
          if (typeof source === "string") {
            for (const pattern of PUBLIC_URL_PATTERNS) {
              if (pattern.test(source)) {
                evidence.push({
                  file: config.filePath,
                  detail: `skills.sources contains public URL: ${source}`
                });
                break;
              }
            }
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Open skill installation is not enabled",
      failed: (n) => `Found ${n} open skill configuration(s) \u2014 unvetted code may be installed`,
      fixable: true,
      fixDescription: "Set skills.open_install=false and restrict skills.sources to trusted private repositories"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "ZC-008",
      path: "skills.open_install",
      value: false,
      message: "Set skills.open_install=false",
      noConfigMessage: "No TOML config file found"
    });
  }
});

// src/checks/zeroclaw/zc-009-whatsapp-no-secret.ts
init_utils();
var zc009 = defineCheck({
  id: "ZC-009",
  name: "WhatsApp No App Secret",
  category: "zeroclaw",
  severity: "warning",
  description: "Detect WhatsApp channel enabled without app_secret \u2014 webhooks accepted without HMAC verification",
  supportedAgents: ["zeroclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const whatsappChannel = getNestedValue(config.data, "channels.whatsapp");
      if (!whatsappChannel || typeof whatsappChannel !== "object") continue;
      const enabled = whatsappChannel.enabled;
      const appSecret = whatsappChannel.app_secret;
      if (enabled === true || enabled === "true" || enabled === void 0) {
        if (!appSecret || typeof appSecret === "string" && appSecret.trim() === "") {
          evidence.push({
            file: config.filePath,
            detail: "WhatsApp channel enabled without app_secret \u2014 webhook payloads are not HMAC-verified"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "WhatsApp channel has app_secret configured or is not enabled",
      failed: () => "WhatsApp channel lacks app_secret \u2014 webhooks accepted without signature verification",
      fixDescription: "Set channels.whatsapp.app_secret to your WhatsApp app secret for HMAC webhook verification"
    });
  }
});

// src/checks/zeroclaw/zc-010-composio-enabled.ts
init_utils();
var zc010 = defineCheck({
  id: "ZC-010",
  name: "Composio Integration Enabled",
  category: "zeroclaw",
  severity: "info",
  description: "Detect Composio integration enabled \u2014 grants access to 1000+ OAuth apps, large attack surface",
  supportedAgents: ["zeroclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const composioEnabled = getNestedValue(config.data, "integrations.composio.enabled");
      if (composioEnabled === true || composioEnabled === "true") {
        evidence.push({
          file: config.filePath,
          detail: "integrations.composio.enabled=true \u2014 access to 1000+ OAuth apps increases attack surface"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Composio integration is not enabled",
      failed: () => "Composio integration is enabled \u2014 large OAuth attack surface"
    });
  }
});

// src/checks/zeroclaw/zc-011-browser-no-allowlist.ts
init_utils();
var zc011 = defineCheck({
  id: "ZC-011",
  name: "Browser Tool No Allowlist",
  category: "zeroclaw",
  severity: "warning",
  description: "Detect browser tool enabled without allowed_domains restriction",
  supportedAgents: ["zeroclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const browserEnabled = getNestedValue(config.data, "tools.browser.enabled");
      const allowedDomains = getNestedValue(config.data, "tools.browser.allowed_domains");
      if (browserEnabled === true || browserEnabled === "true") {
        if (!allowedDomains || Array.isArray(allowedDomains) && allowedDomains.length === 0) {
          evidence.push({
            file: config.filePath,
            detail: "tools.browser.enabled=true without allowed_domains \u2014 agent can browse any website"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Browser tool has domain restrictions or is not enabled",
      failed: () => "Browser tool enabled without domain allowlist \u2014 unrestricted web access",
      fixDescription: "Set tools.browser.allowed_domains to a list of trusted domains"
    });
  }
});

// src/checks/zeroclaw/zc-012-http-no-allowlist.ts
init_utils();
var zc012 = defineCheck({
  id: "ZC-012",
  name: "HTTP Tool No Allowlist",
  category: "zeroclaw",
  severity: "warning",
  description: "Detect HTTP request tool enabled without domain restrictions",
  supportedAgents: ["zeroclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const httpEnabled = getNestedValue(config.data, "tools.http.enabled");
      const allowedDomains = getNestedValue(config.data, "tools.http.allowed_domains");
      if (httpEnabled === true || httpEnabled === "true") {
        if (!allowedDomains || Array.isArray(allowedDomains) && allowedDomains.length === 0) {
          evidence.push({
            file: config.filePath,
            detail: "tools.http.enabled=true without allowed_domains \u2014 agent can make requests to any domain"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "HTTP tool has domain restrictions or is not enabled",
      failed: () => "HTTP tool enabled without domain allowlist \u2014 unrestricted outbound requests",
      fixDescription: "Set tools.http.allowed_domains to a list of trusted domains"
    });
  }
});

// src/checks/zeroclaw/zc-013-secret-key-perms.ts
import { join as join51 } from "path";
init_config_writer();
var zc013 = defineCheck({
  id: "ZC-013",
  name: ".secret_key Permissions",
  category: "zeroclaw",
  severity: "critical",
  description: "Check if .secret_key file has overly permissive file permissions",
  supportedAgents: ["zeroclaw"],
  supportedPlatforms: ["linux", "darwin"],
  async run(ctx, h) {
    const evidence = [];
    const keyPath = join51(ctx.installation.installDir, ".secret_key");
    try {
      const stats = await ctx.fs.stat(keyPath);
      const mode = stats.mode & 511;
      if (mode !== 384) {
        evidence.push({
          file: keyPath,
          detail: `File permissions are ${mode.toString(8)} \u2014 should be 600`
        });
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: ".secret_key has appropriate permissions",
      failed: () => ".secret_key has overly permissive file permissions",
      fixable: true,
      fixDescription: "Run: chmod 600 ~/.zeroclaw/.secret_key"
    });
  },
  async fix(ctx) {
    const keyPath = join51(ctx.installation.installDir, ".secret_key");
    try {
      await chmodFile(keyPath, 384);
      return { checkId: "ZC-013", applied: true, message: "Set .secret_key permissions to 600" };
    } catch {
      return { checkId: "ZC-013", applied: false, message: "Failed to set permissions on .secret_key" };
    }
  }
});

// src/checks/zeroclaw/zc-014-no-os-sandbox.ts
init_utils();
init_config_writer();
var KNOWN_SANDBOXES = ["firejail", "bubblewrap", "bwrap", "landlock", "docker", "podman", "nsjail"];
var zc014 = defineCheck({
  id: "ZC-014",
  name: "No OS Sandbox",
  category: "zeroclaw",
  severity: "warning",
  description: "Detect runtime.kind=native without OS-level sandboxing (Firejail, Bubblewrap, Landlock)",
  supportedAgents: ["zeroclaw"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const runtimeKind = getNestedValue(config.data, "runtime.kind");
      const runtimeSandbox = getNestedValue(config.data, "runtime.sandbox");
      if (runtimeKind === "native") {
        const hasSandbox = typeof runtimeSandbox === "string" && KNOWN_SANDBOXES.includes(runtimeSandbox.toLowerCase());
        if (!hasSandbox) {
          evidence.push({
            file: config.filePath,
            detail: `runtime.kind=native with runtime.sandbox=${runtimeSandbox ?? "not set"} \u2014 no OS-level isolation`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Runtime has OS-level sandboxing or is not running in native mode",
      failed: () => "Native runtime without OS-level sandboxing \u2014 process isolation is missing",
      fixable: true,
      fixDescription: "Set runtime.sandbox to a supported sandbox (firejail, bubblewrap, landlock) or use runtime.kind=docker"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "ZC-014",
      path: "runtime.sandbox",
      value: "firejail",
      message: "Set runtime.sandbox=firejail",
      noConfigMessage: "No TOML config file found"
    });
  }
});

// src/checks/zeroclaw/index.ts
var zeroclawChecks = [
  zc001,
  zc002,
  zc003,
  zc004,
  zc005,
  zc006,
  zc007,
  zc008,
  zc009,
  zc010,
  zc011,
  zc012,
  zc013,
  zc014
];

// src/checks/lyrie/ly-001-shield-mode-passive.ts
init_config_writer();
var ly001 = defineCheck({
  id: "LY-001",
  name: "Lyrie Shield Mode Passive",
  category: "lyrie",
  severity: "critical",
  description: "Detect LYRIE_SHIELD_MODE=passive \u2014 Shield logs threats but does not block them, leaving Layer-1 enforcement effectively disabled.",
  supportedAgents: ["lyrie"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mode = config.data.LYRIE_SHIELD_MODE;
      if (mode === "passive") {
        evidence.push({
          file: config.filePath,
          detail: "LYRIE_SHIELD_MODE=passive \u2014 threats are logged but not blocked"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Shield mode is active or strict",
      failed: () => "Shield mode is passive \u2014 Layer-1 enforcement is disabled",
      fixable: true,
      fixDescription: "Set LYRIE_SHIELD_MODE=active in .env"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "LY-001",
      env: "LYRIE_SHIELD_MODE",
      value: "active",
      message: "Set LYRIE_SHIELD_MODE=active",
      noConfigMessage: "No .env file found"
    });
  }
});

// src/checks/lyrie/ly-002-shield-binary-missing.ts
var ly002 = defineCheck({
  id: "LY-002",
  name: "Lyrie Shield Binary Missing",
  category: "lyrie",
  severity: "warning",
  description: "Detect when the Rust lyrie-shield binary is not on PATH \u2014 Lyrie's TS engine still runs but Layer-1 enforcement is silently absent.",
  supportedAgents: ["lyrie"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    let resolved;
    try {
      resolved = ctx.fs.execSync("which", ["lyrie-shield"], { timeout: 3e3 }).trim();
    } catch {
      resolved = void 0;
    }
    if (!resolved) {
      evidence.push({
        file: ctx.installation.installDir,
        detail: "lyrie-shield is not on PATH \u2014 Layer-1 (Shield) is unavailable; build it via `cargo build --release` in packages/shield/"
      });
    } else {
      try {
        const out = ctx.fs.execSync(resolved, ["--version"], { timeout: 3e3 }).trim();
        if (!out) {
          evidence.push({
            file: resolved,
            detail: "lyrie-shield --version returned no output \u2014 binary may be broken"
          });
        }
      } catch {
        evidence.push({
          file: resolved,
          detail: "lyrie-shield exists on PATH but failed to execute \u2014 binary may be broken"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "lyrie-shield binary is present and runnable",
      failed: () => "lyrie-shield is missing or broken \u2014 Layer-1 enforcement is silently disabled",
      fixDescription: "Build the Rust Shield: `bun run shield:build` (or `cd packages/shield && cargo build --release`)"
    });
  }
});

// src/checks/lyrie/ly-003-dm-policy-open.ts
var CHANNELS = [
  { name: "telegram", tokenKeys: ["TELEGRAM_BOT_TOKEN", "LYRIE_TELEGRAM_TOKEN"], policyKey: "LYRIE_TELEGRAM_DM_POLICY" },
  { name: "whatsapp", tokenKeys: ["LYRIE_WHATSAPP_TOKEN", "LYRIE_WHATSAPP_PHONE_ID"], policyKey: "LYRIE_WHATSAPP_DM_POLICY" },
  { name: "discord", tokenKeys: ["DISCORD_BOT_TOKEN", "LYRIE_DISCORD_TOKEN"], policyKey: "LYRIE_DISCORD_DM_POLICY" },
  { name: "slack", tokenKeys: ["SLACK_BOT_TOKEN", "LYRIE_SLACK_TOKEN"], policyKey: "LYRIE_SLACK_DM_POLICY" },
  { name: "matrix", tokenKeys: ["LYRIE_MATRIX_TOKEN"], policyKey: "LYRIE_MATRIX_DM_POLICY" },
  { name: "mattermost", tokenKeys: ["LYRIE_MATTERMOST_TOKEN"], policyKey: "LYRIE_MATTERMOST_DM_POLICY" },
  { name: "irc", tokenKeys: ["LYRIE_IRC_SERVER", "LYRIE_IRC_NICK"], policyKey: "LYRIE_IRC_DM_POLICY" },
  { name: "feishu", tokenKeys: ["LYRIE_FEISHU_TOKEN", "LYRIE_FEISHU_APP_ID"], policyKey: "LYRIE_FEISHU_DM_POLICY" },
  { name: "rocketchat", tokenKeys: ["LYRIE_ROCKETCHAT_TOKEN"], policyKey: "LYRIE_ROCKETCHAT_DM_POLICY" },
  { name: "webchat", tokenKeys: ["LYRIE_WEBCHAT_PORT"], policyKey: "LYRIE_WEBCHAT_DM_POLICY" }
];
function isPresent(v) {
  return typeof v === "string" && v.trim() !== "" && !/^\$\{?[A-Z_]+\}?$/.test(v.trim());
}
var ly003 = defineCheck({
  id: "LY-003",
  name: "DM Pairing Policy Open on Live Channel",
  category: "lyrie",
  severity: "critical",
  description: `Detect channels with credentials configured but DM policy unset or "open" \u2014 Lyrie's legacy default lets any unknown sender DM the agent. Affects Telegram, WhatsApp, Discord, Slack, Matrix, Mattermost, IRC, Feishu, Rocket.Chat, WebChat.`,
  supportedAgents: ["lyrie"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      for (const ch of CHANNELS) {
        const enabled = ch.tokenKeys.some((k) => isPresent(config.data[k]));
        if (!enabled) continue;
        const policy = config.data[ch.policyKey]?.trim().toLowerCase();
        if (!policy || policy === "open") {
          evidence.push({
            file: config.filePath,
            detail: `Channel "${ch.name}" is enabled but ${ch.policyKey} is ${policy ? `"${policy}"` : "unset"} \u2014 unknown senders can DM the agent without operator approval`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All configured channels have a non-open DM policy",
      failed: (count) => `${count} configured channel(s) have DM policy "open" or unset`,
      fixDescription: "For each affected channel, set LYRIE_<CHAN>_DM_POLICY=pairing (recommended) or =closed in .env"
    });
  }
});

// src/checks/lyrie/ly-004-pairing-store-perms.ts
import { join as join52 } from "path";
var ly004 = defineCheck({
  id: "LY-004",
  name: "DM Pairing Store Over-Permissive",
  category: "lyrie",
  severity: "warning",
  description: `Verify ~/.lyrie/pairing.json mode is 0600 \u2014 Lyrie writes it that way at creation, but operators may chmod it later. Wider perms let other local users see who's paired and add fake "approved" entries.`,
  supportedAgents: ["lyrie"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const path = join52(ctx.installation.installDir, "pairing.json");
    if (!await ctx.fs.access(path)) return h.passed("pairing.json not present");
    const evidence = [];
    try {
      const stat4 = await ctx.fs.stat(path);
      const perms = stat4.mode & 511;
      if ((perms & 63) !== 0) {
        evidence.push({
          file: path,
          snippet: `mode 0${perms.toString(8)}`,
          detail: "pairing.json is over-permissive \u2014 other local users can read or modify the DM allowlist"
        });
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "pairing.json has restrictive permissions",
      failed: () => "pairing.json is over-permissive",
      fixDescription: "Run `chmod 600 ~/.lyrie/pairing.json`"
    });
  }
});

// src/checks/lyrie/ly-005-stale-pending-pairings.ts
import { join as join53 } from "path";
var STALE_DAYS = 7;
var ly005 = defineCheck({
  id: "LY-005",
  name: "Stale Pending DM Pairings",
  category: "lyrie",
  severity: "warning",
  description: "Detect pending DM-pairing requests older than 7 days \u2014 abandoned approvals accumulate and obscure new requests, weakening the human-in-the-loop signal.",
  supportedAgents: ["lyrie"],
  async run(ctx, h) {
    const path = join53(ctx.installation.installDir, "pairing.json");
    if (!await ctx.fs.access(path)) return h.passed("pairing.json not present");
    const evidence = [];
    try {
      const raw = await ctx.fs.readFile(path);
      const data = JSON.parse(raw);
      const pending = Array.isArray(data.pending) ? data.pending : [];
      const cutoff = Date.now() - STALE_DAYS * 24 * 60 * 60 * 1e3;
      const stale = pending.filter((p) => {
        if (!p.requestedAt) return false;
        const ts = Date.parse(p.requestedAt);
        return Number.isFinite(ts) && ts < cutoff;
      });
      if (stale.length > 0) {
        evidence.push({
          file: path,
          detail: `${stale.length} pending pairing request(s) older than ${STALE_DAYS} days \u2014 review and prune`
        });
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "No stale pending pairings",
      failed: () => "Stale pending pairings detected",
      fixDescription: "Review pending requests with `lyrie pairing list` and either approve or remove them"
    });
  }
});

// src/checks/lyrie/ly-006-env-file-perms.ts
var SECRET_KEY_PATTERN = /(_API_KEY|_TOKEN|_SECRET|_TOKEN_ID|_TOKEN_SECRET)\s*=/;
var ly006 = defineCheck({
  id: "LY-006",
  name: "Plaintext Secrets in Over-Permissive .env",
  category: "lyrie",
  severity: "critical",
  description: "Detect .env files containing API keys / channel tokens with mode wider than 0600 \u2014 credentials are readable by other local users.",
  supportedAgents: ["lyrie"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (config.format !== "env") continue;
      if (!SECRET_KEY_PATTERN.test(config.raw)) continue;
      try {
        const stat4 = await ctx.fs.stat(config.filePath);
        const perms = stat4.mode & 511;
        if ((perms & 63) !== 0) {
          evidence.push({
            file: config.filePath,
            snippet: `mode 0${perms.toString(8)}`,
            detail: ".env contains secrets and is readable/writable by group or other users"
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Secret-bearing .env files have restricted permissions",
      failed: () => ".env contains secrets and is over-permissive \u2014 restrict to 0600",
      fixDescription: "Run `chmod 600 ~/.lyrie/.env` to restrict access to the owner"
    });
  }
});

// src/checks/lyrie/ly-007-unused-provider-keys.ts
var PROVIDER_KEYS = [
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "GOOGLE_API_KEY",
  "XAI_API_KEY",
  "MINIMAX_API_KEY"
];
var ly007 = defineCheck({
  id: "LY-007",
  name: "Unused Provider API Keys",
  category: "lyrie",
  severity: "warning",
  description: "Detect cloud-provider API keys configured while LYRIE_MODE=local \u2014 keys are unreachable but still present, expanding credential-theft surface for no functional reason.",
  supportedAgents: ["lyrie"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mode = config.data.LYRIE_MODE;
      if (mode !== "local") continue;
      for (const key of PROVIDER_KEYS) {
        const val = config.data[key];
        if (val && val.trim() !== "" && !/^\$\{?[A-Z_]+\}?$/.test(val.trim())) {
          evidence.push({
            file: config.filePath,
            detail: `${key} is set while LYRIE_MODE=local \u2014 credential is unused at runtime`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No unused provider keys detected",
      failed: () => "Cloud-provider keys configured while LYRIE_MODE=local",
      fixDescription: "Remove unused *_API_KEY entries from .env, or set LYRIE_MODE=hybrid/cloud if you intend to use them"
    });
  }
});

// src/checks/lyrie/ly-008-remote-backend-creds.ts
var ly008 = defineCheck({
  id: "LY-008",
  name: "Remote Backend Credentials in Plaintext .env",
  category: "lyrie",
  severity: "warning",
  description: "Detect LYRIE_BACKEND=daytona or modal with API credentials stored plaintext in .env \u2014 every Lyrie scan ships repo contents to the remote backend.",
  supportedAgents: ["lyrie"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const backend = config.data.LYRIE_BACKEND;
      if (backend !== "daytona" && backend !== "modal") continue;
      const isPlaceholder = (v) => /^\$\{?[A-Z_]+\}?$/.test(v.trim());
      if (backend === "daytona") {
        const key = config.data.DAYTONA_API_KEY;
        if (key && key.trim() !== "" && !isPlaceholder(key)) {
          evidence.push({
            file: config.filePath,
            detail: "LYRIE_BACKEND=daytona with plaintext DAYTONA_API_KEY \u2014 every scan exfiltrates repo contents to Daytona"
          });
        }
      }
      if (backend === "modal") {
        const tokenId = config.data.MODAL_TOKEN_ID;
        const tokenSecret = config.data.MODAL_TOKEN_SECRET;
        if (tokenId && tokenId.trim() !== "" && !isPlaceholder(tokenId) || tokenSecret && tokenSecret.trim() !== "" && !isPlaceholder(tokenSecret)) {
          evidence.push({
            file: config.filePath,
            detail: "LYRIE_BACKEND=modal with plaintext MODAL_TOKEN_* \u2014 every scan exfiltrates repo contents to Modal"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No remote-backend credentials in plaintext .env",
      failed: () => "Remote backend uses plaintext credentials and exfiltrates scan inputs",
      fixDescription: "Move DAYTONA_API_KEY / MODAL_TOKEN_* to a secrets manager and reference via $ENV_VAR substitution; or set LYRIE_BACKEND=local"
    });
  }
});

// src/checks/lyrie/ly-009-dry-run-enabled.ts
init_config_writer();
var ly009 = defineCheck({
  id: "LY-009",
  name: "Lyrie Local Dry-Run Enabled",
  category: "lyrie",
  severity: "warning",
  description: "Detect LYRIE_LOCAL_DRY_RUN=true \u2014 backend returns empty SARIF without running Lyrie. Operators may believe scans are running when they are not.",
  supportedAgents: ["lyrie"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const dryRun = config.data.LYRIE_LOCAL_DRY_RUN;
      if (dryRun === "true" || dryRun === "1") {
        evidence.push({
          file: config.filePath,
          detail: "LYRIE_LOCAL_DRY_RUN=true \u2014 Lyrie reports no findings without scanning"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Dry-run mode is not enabled",
      failed: () => "Dry-run mode is on \u2014 Lyrie returns empty SARIF without running",
      fixable: true,
      fixDescription: "Remove LYRIE_LOCAL_DRY_RUN from .env (or set it to false)"
    });
  },
  async fix(ctx) {
    for (const config of ctx.configs) {
      if (config.format === "env" && "LYRIE_LOCAL_DRY_RUN" in config.data) {
        await updateEnvFile(config.filePath, "LYRIE_LOCAL_DRY_RUN", "false");
        return { checkId: "LY-009", applied: true, message: "Set LYRIE_LOCAL_DRY_RUN=false" };
      }
    }
    return { checkId: "LY-009", applied: false, message: "No .env file found" };
  }
});

// src/checks/lyrie/ly-010-webchat-unauthed.ts
var PUBLIC_HOSTS3 = /* @__PURE__ */ new Set(["0.0.0.0", "::", "0:0:0:0:0:0:0:0"]);
var ly010 = defineCheck({
  id: "LY-010",
  name: "WebChat Unauthenticated and Non-Loopback",
  category: "lyrie",
  severity: "critical",
  description: "Detect WebChat enabled with no auth token and bound to a non-loopback host \u2014 anyone reachable on the network can talk to the agent.",
  supportedAgents: ["lyrie"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const port = config.data.LYRIE_WEBCHAT_PORT;
      if (!port) continue;
      const host = config.data.LYRIE_WEBCHAT_HOST ?? "127.0.0.1";
      const authToken = config.data.LYRIE_WEBCHAT_AUTH_TOKEN;
      const hasAuth2 = typeof authToken === "string" && authToken.trim() !== "" && !/^\$\{?[A-Z_]+\}?$/.test(authToken.trim());
      const isPublic2 = PUBLIC_HOSTS3.has(host) || !host.startsWith("127.") && host !== "localhost" && host !== "::1";
      if (isPublic2 && !hasAuth2) {
        evidence.push({
          file: config.filePath,
          detail: `WebChat bound to ${host}:${port} with no LYRIE_WEBCHAT_AUTH_TOKEN \u2014 agent is reachable unauthenticated`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "WebChat is loopback-only or has an auth token",
      failed: () => "WebChat is reachable on a public interface without authentication",
      fixDescription: "Set LYRIE_WEBCHAT_HOST=127.0.0.1, or set a strong LYRIE_WEBCHAT_AUTH_TOKEN and put TLS-terminating proxy in front"
    });
  }
});

// src/checks/lyrie/ly-011-webchat-cors-permissive.ts
init_config_writer();
var ly011 = defineCheck({
  id: "LY-011",
  name: "WebChat Permissive Origin Allowlist",
  category: "lyrie",
  severity: "warning",
  description: "Detect WebChat enabled with LYRIE_WEBCHAT_ORIGINS unset or wildcard \u2014 invites cross-origin requests from any browser context.",
  supportedAgents: ["lyrie"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const port = config.data.LYRIE_WEBCHAT_PORT;
      if (!port) continue;
      const origins = config.data.LYRIE_WEBCHAT_ORIGINS?.trim();
      if (!origins) {
        evidence.push({
          file: config.filePath,
          detail: "WebChat enabled but LYRIE_WEBCHAT_ORIGINS is unset \u2014 origin allowlist defaults to permissive"
        });
      } else if (origins === "*" || origins.split(",").map((s) => s.trim()).includes("*")) {
        evidence.push({
          file: config.filePath,
          detail: 'LYRIE_WEBCHAT_ORIGINS includes "*" \u2014 any origin can connect'
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "WebChat origin allowlist is restrictive or WebChat is disabled",
      failed: () => "WebChat origin allowlist is unset or wildcard",
      fixable: true,
      fixDescription: "Set LYRIE_WEBCHAT_ORIGINS to an explicit comma-separated list (e.g. https://your-app.example.com)"
    });
  },
  async fix(ctx) {
    for (const config of ctx.configs) {
      if (config.format === "env" && config.data.LYRIE_WEBCHAT_PORT) {
        await updateEnvFile(config.filePath, "LYRIE_WEBCHAT_ORIGINS", "http://127.0.0.1");
        return { checkId: "LY-011", applied: true, message: "Set LYRIE_WEBCHAT_ORIGINS=http://127.0.0.1 \u2014 adjust to your real frontend origin" };
      }
    }
    return { checkId: "LY-011", applied: false, message: "No .env file with WebChat configured found" };
  }
});

// src/checks/lyrie/ly-012-stale-edit-approvals.ts
import { join as join54 } from "path";
var STALE_HOURS = 24;
var ly012 = defineCheck({
  id: "LY-012",
  name: "Stale Pending Edit Approvals",
  category: "lyrie",
  severity: "warning",
  description: "Detect pending diff-view edits older than 24 hours \u2014 long queues mean operator inattention; old plans rebased against drifted file state apply with stale beforeHash failures or, worse, unintended changes.",
  supportedAgents: ["lyrie"],
  async run(ctx, h) {
    const path = join54(ctx.installation.installDir, "edits.json");
    if (!await ctx.fs.access(path)) return h.passed("edits.json not present");
    const evidence = [];
    try {
      const raw = await ctx.fs.readFile(path);
      const data = JSON.parse(raw);
      const pending = Array.isArray(data.pending) ? data.pending : [];
      const cutoff = Date.now() - STALE_HOURS * 60 * 60 * 1e3;
      const stale = pending.filter((p) => {
        const ts = Date.parse(p.createdAt ?? p.requestedAt ?? "");
        return Number.isFinite(ts) && ts < cutoff;
      });
      if (stale.length > 0) {
        evidence.push({
          file: path,
          detail: `${stale.length} pending edit plan(s) older than ${STALE_HOURS} hours \u2014 apply or discard before applying against drifted file state`
        });
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "No stale pending edit approvals",
      failed: () => "Stale pending edit approvals detected",
      fixDescription: "Review pending edits with `lyrie edits list` and approve or discard them"
    });
  }
});

// src/checks/lyrie/ly-013-edits-store-perms.ts
import { join as join55 } from "path";
var ly013 = defineCheck({
  id: "LY-013",
  name: "Edit Ledger Over-Permissive",
  category: "lyrie",
  severity: "warning",
  description: "Verify ~/.lyrie/edits.json mode is 0600 \u2014 wider perms enable a TOCTOU race where another local process swaps the unifiedDiff between operator approval and EditEngine apply.",
  supportedAgents: ["lyrie"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const path = join55(ctx.installation.installDir, "edits.json");
    if (!await ctx.fs.access(path)) return h.passed("edits.json not present");
    const evidence = [];
    try {
      const stat4 = await ctx.fs.stat(path);
      const perms = stat4.mode & 511;
      if ((perms & 63) !== 0) {
        evidence.push({
          file: path,
          snippet: `mode 0${perms.toString(8)}`,
          detail: "edits.json writable by group/other \u2014 TOCTOU race vector for diff swapping"
        });
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "edits.json has restrictive permissions",
      failed: () => "edits.json is over-permissive",
      fixDescription: "Run `chmod 600 ~/.lyrie/edits.json`"
    });
  }
});

// src/checks/lyrie/ly-014-executable-skill-files.ts
import { join as join56 } from "path";
var EXECUTABLE_EXTS = [".ts", ".js", ".mjs", ".py", ".sh"];
var ly014 = defineCheck({
  id: "LY-014",
  name: "Executable Skill Files Outside Shield Scope",
  category: "lyrie",
  severity: "warning",
  description: "Detect executable skill files (.ts/.js/.py/.sh) in the skills directory. Lyrie's SkillManager Shield filter applies to declarative SKILL.md content; executable code paths are run by the skill's own loader and may not pass through the Shield gate.",
  supportedAgents: ["lyrie"],
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir ?? join56(ctx.installation.installDir, "skills");
    if (!await ctx.fs.access(skillsDir)) return h.passed("Skills directory not present");
    const evidence = [];
    try {
      const entries = await ctx.fs.readdirEntries(skillsDir, { recursive: true });
      const executables = entries.filter((e) => {
        if (!e.isFile) return false;
        const lower = e.name.toLowerCase();
        return EXECUTABLE_EXTS.some((ext) => lower.endsWith(ext));
      });
      if (executables.length > 0) {
        evidence.push({
          file: skillsDir,
          detail: `${executables.length} executable skill file(s) found \u2014 confirm each is registered through SkillManager so Shield scans its output`
        });
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "No executable skill files found outside Shield scope",
      failed: () => "Executable skill files present \u2014 verify Shield coverage",
      fixDescription: "Audit each .ts/.js/.py skill: register it through Lyrie's SkillManager so its output passes through `SkillManager.shieldFilter`, or move it out of the skills directory"
    });
  }
});

// src/checks/lyrie/ly-015-skills-dir-writable.ts
import { join as join57 } from "path";
var ly015 = defineCheck({
  id: "LY-015",
  name: "Skills Directory Writable by Other Users",
  category: "lyrie",
  severity: "warning",
  description: "Verify ~/.lyrie/skills/ is not group/world-writable \u2014 a writable skills directory lets any local user drop a malicious skill that runs in the agent context.",
  supportedAgents: ["lyrie"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir ?? join57(ctx.installation.installDir, "skills");
    if (!await ctx.fs.access(skillsDir)) return h.passed("Skills directory not present");
    const evidence = [];
    try {
      const stats = await ctx.fs.stat(skillsDir);
      const mode = stats.mode & 511;
      if (mode & 18) {
        evidence.push({
          file: skillsDir,
          detail: `Permissions ${mode.toString(8)} \u2014 directory writable by group or world; arbitrary skills can be planted`
        });
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "Skills directory has restrictive permissions",
      failed: () => "Skills directory writable by other users",
      fixDescription: "Run `chmod 700 ~/.lyrie/skills`"
    });
  }
});

// src/checks/lyrie/ly-016-migration-import-detected.ts
import { join as join58 } from "path";
var ly016 = defineCheck({
  id: "LY-016",
  name: "Cross-Agent Migration Detected",
  category: "lyrie",
  severity: "info",
  description: "Surface ~/.lyrie/migrations/*.json manifests \u2014 Lyrie can import memory/skills/config from OpenClaw, Hermes, AutoGPT, NanoClaw, ZeroClaw, Nanobot, etc. The source agent's threat exposure (compromised memory, planted skills) carries over into Lyrie.",
  supportedAgents: ["lyrie"],
  async run(ctx, h) {
    const dir = join58(ctx.installation.installDir, "migrations");
    if (!await ctx.fs.access(dir)) return h.passed("No migrations recorded");
    const evidence = [];
    try {
      const entries = await ctx.fs.readdir(dir);
      const manifests = entries.filter((name) => name.endsWith(".json"));
      const platforms = /* @__PURE__ */ new Set();
      for (const name of manifests) {
        try {
          const raw = await ctx.fs.readFile(join58(dir, name));
          const data = JSON.parse(raw);
          if (data.platform) platforms.add(data.platform);
        } catch {
        }
      }
      if (platforms.size > 0) {
        evidence.push({
          file: dir,
          detail: `Memory imported from: ${[...platforms].sort().join(", ")} \u2014 review the source agent(s) for compromise; their threat exposure transfers to Lyrie`
        });
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "No cross-agent imports detected",
      failed: () => "Cross-agent imports present (informational)",
      fixDescription: "Scan the source agent(s) (e.g. `vaso scan -a openclaw`) \u2014 anything they were exposed to is now reachable from Lyrie's memory"
    });
  }
});

// src/checks/lyrie/ly-017-migration-errors.ts
import { join as join59 } from "path";
var ly017 = defineCheck({
  id: "LY-017",
  name: "Cross-Agent Migration Errors",
  category: "lyrie",
  severity: "warning",
  description: "Detect ~/.lyrie/migrations/*.json manifests with non-empty errors[] or success=false \u2014 a partially imported state may leave dangling references, corrupt memory, or skipped Shield-gating.",
  supportedAgents: ["lyrie"],
  async run(ctx, h) {
    const dir = join59(ctx.installation.installDir, "migrations");
    if (!await ctx.fs.access(dir)) return h.passed("No migrations recorded");
    const evidence = [];
    try {
      const entries = await ctx.fs.readdir(dir);
      for (const name of entries.filter((n) => n.endsWith(".json"))) {
        const path = join59(dir, name);
        try {
          const raw = await ctx.fs.readFile(path);
          const data = JSON.parse(raw);
          const failed = data.success === false;
          const hasErrors = Array.isArray(data.errors) && data.errors.length > 0;
          if (failed || hasErrors) {
            evidence.push({
              file: path,
              detail: `Migration from "${data.platform ?? "unknown"}" reported ${data.errors?.length ?? 0} error(s)${failed ? " and was marked unsuccessful" : ""}`
            });
          }
        } catch {
        }
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "All recorded migrations completed cleanly",
      failed: () => "One or more migrations completed with errors",
      fixDescription: "Re-run `lyrie migrate --from <platform>` for the affected import, or clear the partial state from ~/.lyrie/memory/lyrie-memory.db"
    });
  }
});

// src/checks/lyrie/ly-018-node-env-development.ts
init_config_writer();
var CHANNEL_TOKEN_KEYS = [
  "TELEGRAM_BOT_TOKEN",
  "LYRIE_TELEGRAM_TOKEN",
  "DISCORD_BOT_TOKEN",
  "LYRIE_DISCORD_TOKEN",
  "SLACK_BOT_TOKEN",
  "LYRIE_SLACK_TOKEN",
  "LYRIE_WHATSAPP_TOKEN",
  "LYRIE_MATRIX_TOKEN",
  "LYRIE_MATTERMOST_TOKEN",
  "LYRIE_FEISHU_TOKEN",
  "LYRIE_ROCKETCHAT_TOKEN"
];
function isPresent2(v) {
  return typeof v === "string" && v.trim() !== "" && !/^\$\{?[A-Z_]+\}?$/.test(v.trim());
}
var ly018 = defineCheck({
  id: "LY-018",
  name: "Development NODE_ENV with Production Channels",
  category: "lyrie",
  severity: "critical",
  description: "Detect NODE_ENV=development while one or more channel tokens are configured \u2014 verbose logging and dev-only paths are active alongside live channel bots, risking secret leakage in logs.",
  supportedAgents: ["lyrie"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const nodeEnv = config.data.NODE_ENV;
      if (nodeEnv && nodeEnv !== "development") continue;
      const liveChannels = CHANNEL_TOKEN_KEYS.filter((k) => isPresent2(config.data[k]));
      if (liveChannels.length === 0) continue;
      evidence.push({
        file: config.filePath,
        detail: `NODE_ENV=${nodeEnv ?? "development (default)"} with ${liveChannels.length} channel token(s) configured \u2014 debug logs may leak secrets and message content`
      });
    }
    return h.fromEvidence(evidence, {
      passed: "NODE_ENV is production or no channels are configured",
      failed: () => "NODE_ENV=development with live channel tokens configured",
      fixable: true,
      fixDescription: "Set NODE_ENV=production in .env when running Lyrie with real channel tokens"
    });
  },
  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: "LY-018",
      env: "NODE_ENV",
      value: "production",
      message: "Set NODE_ENV=production",
      noConfigMessage: "No .env file found"
    });
  }
});

// src/checks/lyrie/index.ts
var lyrieChecks = [
  ly001,
  ly002,
  ly003,
  ly004,
  ly005,
  ly006,
  ly007,
  ly008,
  ly009,
  ly010,
  ly011,
  ly012,
  ly013,
  ly014,
  ly015,
  ly016,
  ly017,
  ly018
];

// src/checks/hermes/hm-001-plaintext-api-keys.ts
var KEY_NAME_PATTERN = /(?:api[_-]?key|token|secret|password|credential|auth|bot[_-]?token)/i;
var KNOWN_PREFIXES = [
  /^sk-or-v1-[A-Za-z0-9]{32,}/,
  /^sk-ant-[A-Za-z0-9_-]{20,}/,
  /^sk-[A-Za-z0-9]{20,}/,
  /^ghp_[A-Za-z0-9]{20,}/,
  /^gho_[A-Za-z0-9]{20,}/,
  /^github_pat_[A-Za-z0-9_]{20,}/,
  /^xox[baprs]-[A-Za-z0-9-]{10,}/,
  /^AIza[0-9A-Za-z_-]{30,}/,
  /^xai-[A-Za-z0-9_-]{20,}/,
  /^\d{8,}:[A-Za-z0-9_-]{35}$/,
  // Telegram bot
  /^[MN][\w-]{23,28}\.[\w-]{6,7}\.[\w-]{27,38}$/
  // Discord bot
];
var ENV_REF = /^\$\{?[A-Z_][A-Z0-9_]*\}?$/;
var HIGH_ENTROPY = 4.5;
var MIN_LEN = 20;
function isSecret(value) {
  if (value.length < MIN_LEN) return false;
  if (ENV_REF.test(value)) return false;
  if (KNOWN_PREFIXES.some((p) => p.test(value))) return true;
  return shannonEntropy(value) > HIGH_ENTROPY;
}
function walk(obj, file, path, evidence) {
  if (!obj || typeof obj !== "object") return;
  for (const [key, value] of Object.entries(obj)) {
    const here = path ? `${path}.${key}` : key;
    if (typeof value === "string") {
      const looksSecret = KEY_NAME_PATTERN.test(key) || isSecret(value);
      if (looksSecret && isSecret(value)) {
        evidence.push({
          file,
          snippet: `${here} = ${value.slice(0, 8)}\u2026`,
          detail: "Plaintext credential in Hermes config \u2014 move to .env or use ${ENV_VAR} reference"
        });
      }
    } else if (value && typeof value === "object") {
      walk(value, file, here, evidence);
    }
  }
}
var hm001 = defineCheck({
  id: "HM-001",
  name: "Plaintext API Keys in Hermes Config",
  category: "hermes",
  severity: "critical",
  description: "Detect API keys, OAuth tokens, channel bot tokens, or other secrets stored in plaintext in ~/.hermes/cli-config.yaml (model.api_key, auxiliary.*.api_key, delegation.api_key, mcp_servers.<n>.env.*).",
  supportedAgents: ["hermes"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith("cli-config.yaml") && !config.filePath.endsWith("config.yaml")) continue;
      walk(config.data, config.filePath, "", evidence);
    }
    return h.fromEvidence(evidence, {
      passed: "No plaintext credentials in Hermes cli-config.yaml",
      failed: (n) => `Found ${n} plaintext credential(s) in Hermes config`,
      fixDescription: "Move secrets to ~/.hermes/.env (with mode 0600) and reference them via ${ENV_VAR} in cli-config.yaml"
    });
  }
});

// src/checks/hermes/hm-002-env-file-perms.ts
var SECRET_KEY_PATTERN2 = /(_API_KEY|_TOKEN|_SECRET|_KEY|BEARER|PASSWORD)\s*=/i;
var hm002 = defineCheck({
  id: "HM-002",
  name: "Hermes .env Over-Permissive Permissions",
  category: "hermes",
  severity: "critical",
  description: "Detect ~/.hermes/.env containing provider API keys / channel bot tokens with mode wider than 0600 \u2014 credentials readable by other local users.",
  supportedAgents: ["hermes"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (config.format !== "env") continue;
      if (!SECRET_KEY_PATTERN2.test(config.raw)) continue;
      try {
        const stat4 = await ctx.fs.stat(config.filePath);
        const perms = stat4.mode & 511;
        if ((perms & 63) !== 0) {
          evidence.push({
            file: config.filePath,
            snippet: `mode 0${perms.toString(8)}`,
            detail: ".env contains provider/channel secrets and is readable by group or other users"
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Secret-bearing Hermes .env files have restricted permissions",
      failed: () => "Hermes .env contains secrets and is over-permissive \u2014 restrict to 0600",
      fixDescription: "Run `chmod 600 ~/.hermes/.env`"
    });
  }
});

// src/checks/hermes/hm-003-credential-file-perms.ts
import { join as join60 } from "path";
var SENSITIVE_FILES = [
  "credentials.json",
  "auth.json"
];
var SENSITIVE_DIR_GLOBS = [
  "mcp-tokens"
];
var hm003 = defineCheck({
  id: "HM-003",
  name: "Hermes Credential File Over-Permissive Permissions",
  category: "hermes",
  severity: "critical",
  description: "Detect ~/.hermes/credentials.json, ~/.hermes/auth.json, and ~/.hermes/mcp-tokens/*.json with mode wider than 0600.",
  supportedAgents: ["hermes"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    const installDir = ctx.installation.installDir;
    const checkPerms = async (filePath) => {
      try {
        const stat4 = await ctx.fs.stat(filePath);
        if (!stat4.isFile()) return;
        const perms = stat4.mode & 511;
        if ((perms & 63) !== 0) {
          evidence.push({
            file: filePath,
            snippet: `mode 0${perms.toString(8)}`,
            detail: "Credential file readable by group or other users"
          });
        }
      } catch {
      }
    };
    for (const name of SENSITIVE_FILES) {
      await checkPerms(join60(installDir, name));
    }
    for (const dirName of SENSITIVE_DIR_GLOBS) {
      const dirPath = join60(installDir, dirName);
      try {
        const entries = await ctx.fs.readdirEntries(dirPath);
        for (const entry of entries) {
          if (!entry.isFile) continue;
          if (!entry.name.endsWith(".json")) continue;
          await checkPerms(join60(dirPath, entry.name));
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Hermes credential files have restricted permissions",
      failed: (n) => `Found ${n} Hermes credential file(s) with over-permissive mode`,
      fixDescription: "Run `chmod 600 ~/.hermes/credentials.json ~/.hermes/auth.json ~/.hermes/mcp-tokens/*.json` (whichever exist)"
    });
  }
});

// src/checks/hermes/hm-004-api-server-no-auth.ts
var LOOPBACK_HOSTS = /* @__PURE__ */ new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);
function readEnvKey(configs, key) {
  for (const c of configs) {
    if (c.format !== "env") continue;
    const v = c.data[key];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return void 0;
}
var hm004 = defineCheck({
  id: "HM-004",
  name: "Hermes API Server Non-Loopback Without Auth Key",
  category: "hermes",
  severity: "critical",
  description: "API_SERVER_HOST is non-loopback (e.g. 0.0.0.0) but API_SERVER_KEY is empty/unset \u2014 Hermes API server accepts unauthenticated requests with full access to the agent toolset (including terminal commands).",
  supportedAgents: ["hermes"],
  async run(ctx, h) {
    const evidence = [];
    const host = readEnvKey(ctx.configs, "API_SERVER_HOST");
    const key = readEnvKey(ctx.configs, "API_SERVER_KEY");
    if (host && !LOOPBACK_HOSTS.has(host) && !key) {
      const envFile = ctx.configs.find((c) => c.format === "env")?.filePath ?? "~/.hermes/.env";
      evidence.push({
        file: envFile,
        snippet: `API_SERVER_HOST=${host}, API_SERVER_KEY=<unset>`,
        detail: "API server bound to non-loopback address with no bearer token \u2014 anyone who can reach the host can run terminal commands"
      });
    }
    return h.fromEvidence(evidence, {
      passed: "API server bound to loopback or has an authentication key configured",
      failed: () => "Hermes API server is reachable without authentication",
      fixDescription: "Set API_SERVER_KEY=<long-random-token> in ~/.hermes/.env, or rebind API_SERVER_HOST=127.0.0.1 and use a reverse proxy with TLS"
    });
  }
});

// src/checks/hermes/hm-005-api-server-cors.ts
var LOOPBACK_HOSTS2 = /* @__PURE__ */ new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);
function readEnvKey2(configs, key) {
  for (const c of configs) {
    if (c.format !== "env") continue;
    const v = c.data[key];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return void 0;
}
var hm005 = defineCheck({
  id: "HM-005",
  name: "Hermes API Server Permissive CORS",
  category: "hermes",
  severity: "warning",
  description: 'API_SERVER_HOST is non-loopback and API_SERVER_CORS_ORIGINS is empty or "*" \u2014 any browser tab on any origin can call the Hermes API.',
  supportedAgents: ["hermes"],
  async run(ctx, h) {
    const evidence = [];
    const host = readEnvKey2(ctx.configs, "API_SERVER_HOST");
    if (!host || LOOPBACK_HOSTS2.has(host)) {
      return h.fromEvidence(evidence, {
        passed: "API server is loopback-only \u2014 CORS config not relevant",
        failed: () => "unreachable"
      });
    }
    const origins = readEnvKey2(ctx.configs, "API_SERVER_CORS_ORIGINS");
    const envFile = ctx.configs.find((c) => c.format === "env")?.filePath ?? "~/.hermes/.env";
    if (!origins) {
      evidence.push({
        file: envFile,
        detail: "API_SERVER_CORS_ORIGINS unset \u2014 Hermes accepts cross-origin requests with no origin allowlist"
      });
    } else if (origins === "*" || origins.split(",").map((s) => s.trim()).includes("*")) {
      evidence.push({
        file: envFile,
        snippet: `API_SERVER_CORS_ORIGINS=${origins}`,
        detail: 'API_SERVER_CORS_ORIGINS contains "*" \u2014 any browser origin can drive the Hermes API'
      });
    }
    return h.fromEvidence(evidence, {
      passed: "API server CORS allowlist is restrictive",
      failed: () => "API_SERVER_CORS_ORIGINS is unset or wildcard",
      fixDescription: "Set API_SERVER_CORS_ORIGINS to an explicit comma-separated list of frontend origins (e.g. https://your-app.example.com)"
    });
  }
});

// src/checks/hermes/hm-006-plaintext-http-endpoint.ts
var LOOPBACK_HTTP = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?\b/i;
function walk2(obj, path, found) {
  if (!obj || typeof obj !== "object") return;
  for (const [key, value] of Object.entries(obj)) {
    const here = path ? `${path}.${key}` : key;
    if (typeof value === "string") {
      if ((key === "base_url" || key === "url" || key === "http_url" || key === "sse_url") && value.startsWith("http://") && !LOOPBACK_HTTP.test(value)) {
        found.push({ path: here, url: value });
      }
    } else if (value && typeof value === "object") {
      walk2(value, here, found);
    }
  }
}
var hm006 = defineCheck({
  id: "HM-006",
  name: "Hermes Inference / MCP Endpoint Over Plaintext HTTP",
  category: "hermes",
  severity: "critical",
  description: "Detect non-loopback http:// URLs in model.base_url, auxiliary.*.base_url, delegation.base_url, or mcp_servers.<n>.url \u2014 prompts, tool calls, and bearer tokens traverse unencrypted.",
  supportedAgents: ["hermes"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith("cli-config.yaml") && !config.filePath.endsWith("config.yaml")) continue;
      const found = [];
      walk2(config.data, "", found);
      for (const f of found) {
        evidence.push({
          file: config.filePath,
          snippet: `${f.path} = ${f.url}`,
          detail: "Inference traffic over plaintext HTTP \u2014 credentials, tool args, and prompts traverse unencrypted"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All Hermes endpoints use HTTPS or loopback transports",
      failed: (n) => `Found ${n} Hermes endpoint(s) using plaintext HTTP`,
      fixDescription: "Switch to https:// or front the endpoint with a TLS-terminating proxy"
    });
  }
});

// src/checks/hermes/hm-007-untrusted-custom-endpoint.ts
var KNOWN_HOSTS = [
  /\bopenrouter\.ai$/i,
  /\banthropic\.com$/i,
  /\bopenai\.com$/i,
  /\b(?:azure|openai\.azure)\.com$/i,
  /\bgenerativelanguage\.googleapis\.com$/i,
  /\bbuild\.nvidia\.com$/i,
  /\bintegrate\.api\.nvidia\.com$/i,
  /\bapi\.nvidia\.com$/i,
  /\bollama\.com$/i,
  /\blmstudio\.ai$/i,
  /\bgroq\.com$/i,
  /\bmistral\.ai$/i,
  /\bcohere\.com$/i,
  /\bperplexity\.ai$/i,
  /\bdeepseek\.com$/i,
  /\bx\.ai$/i,
  /\bbedrock-runtime\.[\w.-]+\.amazonaws\.com$/i,
  /\bhuggingface\.co$/i,
  /\bnousresearch\.com$/i,
  /\bchatgpt\.com$/i
];
var LOOPBACK_HOSTS3 = /^(?:localhost|127\.0\.0\.1|\[?::1\]?)$/i;
var PRIVATE_RANGES = /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/;
function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return void 0;
  }
}
function walk3(obj, path, found) {
  if (!obj || typeof obj !== "object") return;
  for (const [key, value] of Object.entries(obj)) {
    const here = path ? `${path}.${key}` : key;
    if (typeof value === "string") {
      if ((key === "base_url" || key === "url" || key === "http_url" || key === "sse_url") && /^https?:\/\//i.test(value)) {
        const host = hostOf(value);
        if (host && !LOOPBACK_HOSTS3.test(host) && !PRIVATE_RANGES.test(host) && !KNOWN_HOSTS.some((p) => p.test(host))) {
          found.push({ path: here, url: value, host });
        }
      }
    } else if (value && typeof value === "object") {
      walk3(value, here, found);
    }
  }
}
var hm007 = defineCheck({
  id: "HM-007",
  name: "Hermes Custom Inference Endpoint Outside Known Providers",
  category: "hermes",
  severity: "warning",
  description: "Detect base_url / mcp_servers URLs pointing to hosts outside the known-provider allowlist \u2014 possible exfiltration endpoint harvesting prompts and bearer tokens.",
  supportedAgents: ["hermes"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith("cli-config.yaml") && !config.filePath.endsWith("config.yaml")) continue;
      const found = [];
      walk3(config.data, "", found);
      for (const f of found) {
        evidence.push({
          file: config.filePath,
          snippet: `${f.path} = ${f.url}`,
          detail: `Endpoint host "${f.host}" is not a known inference provider \u2014 verify it isn't an exfil destination`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Hermes endpoints all point to known inference providers",
      failed: (n) => `Found ${n} Hermes endpoint(s) on unknown hosts`,
      fixDescription: "Verify each unknown endpoint is intentional and trusted; consider TLS pinning or revert to a known provider"
    });
  }
});

// src/checks/hermes/hm-008-approvals-disabled.ts
init_utils();
var TRUTHY = /^(?:1|true|yes|on)$/i;
var hm008 = defineCheck({
  id: "HM-008",
  name: "Hermes Tool-Call Approvals Disabled",
  category: "hermes",
  severity: "critical",
  description: 'approvals.mode set to "off" in cli-config.yaml or HERMES_YOLO_MODE truthy in .env \u2014 tool calls (including terminal commands) execute without operator confirmation.',
  supportedAgents: ["hermes"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (config.filePath.endsWith("cli-config.yaml") || config.filePath.endsWith("config.yaml")) {
        const mode = getNestedValue(config.data, "approvals.mode");
        if (typeof mode === "string" && mode.toLowerCase() === "off") {
          evidence.push({
            file: config.filePath,
            snippet: `approvals.mode: ${mode}`,
            detail: "Tool-call approval prompts disabled \u2014 every action runs without confirmation"
          });
        }
      }
      if (config.format === "env") {
        const yolo = config.data.HERMES_YOLO_MODE;
        if (typeof yolo === "string" && TRUTHY.test(yolo.trim())) {
          evidence.push({
            file: config.filePath,
            snippet: `HERMES_YOLO_MODE=${yolo}`,
            detail: "Persistent YOLO mode bypasses dangerous-command prompts for every Hermes session"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Hermes tool-call approvals are enabled",
      failed: (n) => `Found ${n} approval-bypass setting(s) \u2014 every tool call runs without confirmation`,
      fixDescription: "Set approvals.mode: manual (or smart) in cli-config.yaml; remove HERMES_YOLO_MODE from .env"
    });
  }
});

// src/checks/hermes/hm-009-tirith-disabled.ts
init_utils();
var hm009 = defineCheck({
  id: "HM-009",
  name: "Hermes Tirith Pre-Exec Scanner Disabled or Fail-Open",
  category: "hermes",
  severity: "warning",
  description: "security.tirith_enabled is false, OR tirith_fail_open is true (default) and the tirith binary is missing \u2014 pre-execution dangerous-command scanning is silently disabled.",
  supportedAgents: ["hermes"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith("cli-config.yaml") && !config.filePath.endsWith("config.yaml")) continue;
      const enabled = getNestedValue(config.data, "security.tirith_enabled");
      if (enabled === false) {
        evidence.push({
          file: config.filePath,
          snippet: "security.tirith_enabled: false",
          detail: "Tirith pre-exec scanner explicitly disabled \u2014 agent-suggested commands run unscanned"
        });
        continue;
      }
      const failOpen = getNestedValue(config.data, "security.tirith_fail_open");
      const failOpenEffective = failOpen !== false;
      if (failOpenEffective) {
        let binaryPresent = false;
        try {
          const result = ctx.fs.execSync("which", ["tirith"], { timeout: 3e3 }).trim();
          binaryPresent = result.length > 0;
        } catch {
          binaryPresent = false;
        }
        if (!binaryPresent) {
          evidence.push({
            file: config.filePath,
            snippet: `security.tirith_fail_open: ${failOpen ?? "<default true>"} (binary missing)`,
            detail: "Tirith fail-open is enabled and the tirith binary is not on PATH \u2014 pre-exec scanning silently does nothing"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Tirith pre-exec scanner is enabled and reachable",
      failed: (n) => `Found ${n} Tirith configuration issue(s) \u2014 dangerous-command scanning may be inactive`,
      fixDescription: "Set security.tirith_enabled: true and security.tirith_fail_open: false; install tirith on PATH"
    });
  }
});

// src/checks/hermes/hm-010-mcp-server-hardening.ts
var PACKAGE_RUNNERS3 = /* @__PURE__ */ new Set(["npx", "pnpm", "yarn", "bunx", "uvx", "pipx"]);
var PINNED = /@\d+\.\d+\.\d+/;
var SHA_PINNED = /(?:@sha256:|#[a-f0-9]{7,40})/i;
var SHELL_C = /^(?:bash|sh|zsh|fish|cmd|powershell|pwsh)$/i;
var hm010 = defineCheck({
  id: "HM-010",
  name: "Hermes MCP Server Stdio Hardening",
  category: "hermes",
  severity: "warning",
  description: "Detect MCP servers in mcp_servers.<name> launched via shell-c (`bash -c \u2026`), running unpinned packages via npx/uvx/etc., or invoking a world-writable command path \u2014 supply-chain and TOCTOU vectors.",
  supportedAgents: ["hermes"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith("cli-config.yaml") && !config.filePath.endsWith("config.yaml")) continue;
      const servers = config.data.mcp_servers;
      if (!servers || typeof servers !== "object") continue;
      for (const [name, serverRaw] of Object.entries(servers)) {
        if (!serverRaw || typeof serverRaw !== "object") continue;
        const server = serverRaw;
        const command = server.command;
        const args = server.args;
        if (typeof command !== "string") continue;
        const argList = Array.isArray(args) ? args.filter((a) => typeof a === "string") : [];
        const baseCmd = command.split("/").pop() ?? command;
        if (SHELL_C.test(baseCmd) && argList.includes("-c")) {
          evidence.push({
            file: config.filePath,
            snippet: `mcp_servers.${name}: ${command} ${argList.join(" ")}`,
            detail: `MCP server invoked via "${baseCmd} -c \u2026" \u2014 argv injection becomes shell injection`
          });
        }
        if (command.startsWith("/")) {
          try {
            const stat4 = await ctx.fs.stat(command);
            const perms = stat4.mode & 511;
            if ((perms & 2) !== 0) {
              evidence.push({
                file: config.filePath,
                snippet: `${command} (mode 0${perms.toString(8)})`,
                detail: `MCP server command is world-writable \u2014 any local user can replace it before launch`
              });
            }
          } catch {
          }
        }
        if (PACKAGE_RUNNERS3.has(baseCmd)) {
          const pkgArg = argList.find((a) => !a.startsWith("-"));
          if (pkgArg && !PINNED.test(pkgArg) && !SHA_PINNED.test(pkgArg)) {
            evidence.push({
              file: config.filePath,
              snippet: `mcp_servers.${name}: ${command} ${argList.join(" ")}`,
              detail: `Runs "${pkgArg}" via ${baseCmd} with no version pin \u2014 supply-chain risk`
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Hermes MCP servers use safe stdio invocation and pinned packages",
      failed: (n) => `Found ${n} Hermes MCP server hygiene issue(s)`,
      fixDescription: "Drop `bash -c` wrappers (invoke the binary directly), pin package versions (e.g. `@modelcontextprotocol/server-foo@1.2.3`), and ensure command paths are not world-writable"
    });
  }
});

// src/checks/hermes/index.ts
var hermesChecks = [
  hm001,
  hm002,
  hm003,
  hm004,
  hm005,
  hm006,
  hm007,
  hm008,
  hm009,
  hm010
];

// src/checks/policy/pol-001-exec-approval.ts
init_types();
init_utils();
var pol001 = defineCheck({
  id: "POL-001",
  name: "Exec Approval Required",
  category: "policy",
  severity: "warning",
  description: "Verify tool execution requires user approval and is not auto-approved",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const execApproval = getNestedValue(config.data, "execApproval") ?? getNestedValue(config.data, "tool_approval") ?? getNestedValue(config.data, "security.execApproval") ?? getNestedValue(config.data, "security.tool_approval");
      const autoApprove = getNestedValue(config.data, "auto_approve") ?? getNestedValue(config.data, "autoApprove") ?? getNestedValue(config.data, "security.autoApprove") ?? getNestedValue(config.data, "tools.autoApprove");
      if (execApproval === false || execApproval === "disabled" || execApproval === "off") {
        evidence.push({
          file: config.filePath,
          detail: `Execution approval is disabled: ${String(execApproval)}`
        });
      }
      if (autoApprove === true || autoApprove === "all" || autoApprove === "*") {
        evidence.push({
          file: config.filePath,
          detail: `Tools are auto-approved: ${String(autoApprove)}`
        });
      }
    }
    const envAutoApprove = ctx.fs.getEnv("AGENT_AUTO_APPROVE_TOOLS");
    if (envAutoApprove === "true" || envAutoApprove === "1" || envAutoApprove === "all") {
      evidence.push({
        file: "environment",
        detail: `AGENT_AUTO_APPROVE_TOOLS=${envAutoApprove}`
      });
    }
    return h.fromEvidence(evidence, {
      passed: "Tool execution approval is properly configured",
      failed: (n) => `Found ${n} issue(s) with execution approval policy`
    });
  }
});

// src/checks/policy/pol-002-log-redaction.ts
init_types();
init_utils();
var pol002 = defineCheck({
  id: "POL-002",
  name: "Log Redaction",
  category: "policy",
  severity: "warning",
  description: "Verify logging has secret redaction configured when logging is enabled",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const loggingEnabled = getNestedValue(config.data, "logging.enabled") ?? getNestedValue(config.data, "log.enabled") ?? getNestedValue(config.data, "logs");
      if (loggingEnabled === true || loggingEnabled === "true" || typeof loggingEnabled === "object" && loggingEnabled !== null) {
        const redaction = getNestedValue(config.data, "logging.redact") ?? getNestedValue(config.data, "logRedaction") ?? getNestedValue(config.data, "redactSecrets") ?? getNestedValue(config.data, "log.redact") ?? getNestedValue(config.data, "logging.redactSecrets");
        if (!redaction) {
          evidence.push({
            file: config.filePath,
            detail: "Logging is enabled but no secret redaction is configured"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Log redaction is properly configured or logging is not enabled",
      failed: (n) => `Found ${n} config(s) with logging enabled but no redaction`
    });
  }
});

// src/checks/policy/pol-003-session-credentials.ts
var pol003 = defineCheck({
  id: "POL-003",
  name: "Session Credential Permissions",
  category: "policy",
  severity: "warning",
  description: "Check that adapter-declared session/token/auth files have restrictive permissions (0600)",
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const paths = ctx.credentialPaths ?? [];
    if (paths.length === 0) {
      return h.passed("Adapter does not declare credential paths; skipping");
    }
    const evidence = [];
    for (const fullPath of paths) {
      try {
        const stats = await ctx.fs.stat(fullPath);
        if (!stats.isFile()) continue;
        const mode = stats.mode & 511;
        if (mode & 63) {
          evidence.push({
            file: fullPath,
            detail: `Permissions: ${mode.toString(8)} (should be 600 or tighter)`
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All session/credential files have restrictive permissions",
      failed: (n) => `${n} session/credential file(s) have overly permissive permissions`
    });
  }
});

// src/checks/policy/pol-004-sandbox-enforcement.ts
init_types();
init_utils();
var pol004 = defineCheck({
  id: "POL-004",
  name: "Sandbox Policy Enforcement",
  category: "policy",
  severity: "warning",
  description: "Verify that enabled sandboxes have substantive constraints (exec, filesystem, network)",
  excludedAgents: CODING_AGENTS,
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const sandbox = getNestedValue(config.data, "sandbox") ?? getNestedValue(config.data, "security.sandbox") ?? getNestedValue(config.data, "isolation");
      if (!sandbox || sandbox === false || sandbox === "disabled" || sandbox === "off" || sandbox === "none") {
        continue;
      }
      let constraints = 0;
      const sandboxObj = typeof sandbox === "object" ? sandbox : config.data;
      const execRestriction = getNestedValue(sandboxObj, "allowedExec") ?? getNestedValue(sandboxObj, "safeBins") ?? getNestedValue(sandboxObj, "restrictedExec") ?? getNestedValue(sandboxObj, "execPolicy") ?? getNestedValue(config.data, "sandbox.allowedExec") ?? getNestedValue(config.data, "sandbox.execPolicy");
      if (execRestriction) constraints++;
      const fsRestriction = getNestedValue(sandboxObj, "filesystem") ?? getNestedValue(sandboxObj, "allowedPaths") ?? getNestedValue(sandboxObj, "workspace") ?? getNestedValue(sandboxObj, "rootDir") ?? getNestedValue(config.data, "sandbox.allowedPaths") ?? getNestedValue(config.data, "sandbox.filesystem");
      if (fsRestriction) constraints++;
      const netRestriction = getNestedValue(sandboxObj, "network") ?? getNestedValue(sandboxObj, "allowedHosts") ?? getNestedValue(sandboxObj, "networkPolicy") ?? getNestedValue(config.data, "sandbox.allowedHosts") ?? getNestedValue(config.data, "sandbox.networkPolicy");
      if (netRestriction) constraints++;
      if (constraints < 2) {
        evidence.push({
          file: config.filePath,
          detail: `Sandbox is enabled but has only ${constraints} constraint(s) (minimum 2 required: exec, filesystem, network)`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Sandbox policies have sufficient constraints",
      failed: (n) => `Found ${n} sandbox config(s) with insufficient constraints`
    });
  }
});

// src/checks/policy/pol-005-plaintext-credentials.ts
import { join as join61 } from "path";
var CREDENTIAL_FILES = /* @__PURE__ */ new Set([
  ".npmrc",
  ".netrc",
  ".pgpass",
  ".my.cnf",
  ".s3cfg",
  "credentials",
  "secrets.txt",
  ".boto",
  ".pypirc",
  ".authinfo"
]);
var pol005 = defineCheck({
  id: "POL-005",
  name: "Plaintext Credential Files",
  category: "policy",
  severity: "critical",
  description: "Scan common credential files for plaintext API keys and secrets",
  async run(ctx, h) {
    const installDir = ctx.installation.installDir;
    let entries;
    try {
      entries = await ctx.fs.readdirEntries(installDir, { recursive: true });
    } catch {
      return h.passed("Install directory not accessible");
    }
    const evidence = [];
    for (const entry of entries) {
      if (!entry.isFile) continue;
      if (!CREDENTIAL_FILES.has(entry.name)) continue;
      const fullPath = entry.parentPath ? join61(entry.parentPath, entry.name) : join61(installDir, entry.name);
      try {
        const content = await ctx.fs.readFile(fullPath);
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          for (const { pattern, name } of API_KEY_PATTERNS) {
            if (pattern.test(line)) {
              evidence.push({
                file: fullPath,
                line: i + 1,
                snippet: line.trim().slice(0, 80).replace(/[a-zA-Z0-9]{8,}/g, "****"),
                detail: `${name} found in plaintext credential file`
              });
              break;
            }
          }
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No plaintext credentials found in common credential files",
      failed: (n) => `Found ${n} plaintext credential(s) in credential files`
    });
  }
});

// src/checks/policy/index.ts
var policyChecks = [
  pol001,
  pol002,
  pol003,
  pol004,
  pol005
];

// src/checks/advisory/adv-001-version-vuln.ts
init_database2();
var adv001 = defineCheck({
  id: "ADV-001",
  name: "Known Framework Vulnerability",
  category: "advisory",
  severity: "critical",
  description: "Check installed agent version against known CVEs and security advisories",
  async run(ctx, h) {
    const version = ctx.installation.version;
    if (!version) return h.passed("Agent version not detected \u2014 skipping advisory check");
    const db = getAdvisoryDatabase();
    const agent = ctx.installation.agent;
    const matching = db.advisories.filter((adv) => {
      if (!adv.tags?.includes("framework") && !adv.tags?.includes("coding-agent")) return false;
      if (adv.agent !== agent && adv.agent !== "*") return false;
      if (adv.eolNotice) return false;
      return satisfies(version, adv.affectedVersions);
    });
    if (matching.length === 0) return h.passed(`No known vulnerabilities for ${agent} v${version}`);
    const evidence = matching.map((adv) => ({
      file: adv.reference ?? adv.id,
      detail: `${adv.id}: ${adv.title} (severity: ${adv.severity}${adv.fixedVersion ? `, fix: v${adv.fixedVersion}` : ""})`
    }));
    return h.result({
      passed: false,
      message: `${matching.length} known vulnerabilit${matching.length === 1 ? "y" : "ies"} affect ${agent} v${version}`,
      evidence
    });
  }
});

// src/checks/advisory/adv-002-dependency-vuln.ts
import { join as join62 } from "path";
init_database2();
var adv002 = defineCheck({
  id: "ADV-002",
  name: "Dependency Vulnerability",
  category: "advisory",
  severity: "warning",
  description: "Scan package.json/Cargo.toml dependencies against known advisory entries",
  async run(ctx, h) {
    const db = getAdvisoryDatabase();
    const depAdvisories = db.advisories.filter((a) => a.affectedDependency);
    if (depAdvisories.length === 0) return h.passed("No dependency advisories in database");
    const evidence = [];
    const installDir = ctx.installation.installDir;
    const deps = await loadPackageJsonDeps(ctx, installDir);
    const cargoDeps = await loadCargoTomlDeps(ctx, installDir);
    const allDeps = { ...deps, ...cargoDeps };
    for (const adv of depAdvisories) {
      const dep = adv.affectedDependency;
      const installedVersion = allDeps[dep.name];
      if (!installedVersion) continue;
      if (satisfies(installedVersion, dep.versionConstraint)) {
        evidence.push({
          file: installDir,
          detail: `${adv.id}: ${dep.name}@${installedVersion} \u2014 ${adv.title}`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No vulnerable dependencies detected",
      failed: (n) => `${n} vulnerable dependenc${n === 1 ? "y" : "ies"} detected`
    });
  }
});
async function loadPackageJsonDeps(ctx, dir) {
  try {
    const raw = await ctx.fs.readFile(join62(dir, "package.json"));
    const pkg = JSON.parse(raw);
    return {
      ...pkg.dependencies ?? {},
      ...pkg.devDependencies ?? {}
    };
  } catch {
    return {};
  }
}
async function loadCargoTomlDeps(ctx, dir) {
  try {
    const raw = await ctx.fs.readFile(join62(dir, "Cargo.toml"));
    const deps = {};
    const depSection = raw.match(/\[dependencies\]([\s\S]*?)(?:\n\[|$)/);
    if (depSection) {
      const lines = depSection[1].split("\n");
      for (const line of lines) {
        const m = /^(\S+)\s*=\s*"([^"]+)"/.exec(line.trim());
        if (m) deps[m[1]] = m[2];
      }
    }
    return deps;
  } catch {
    return {};
  }
}

// src/checks/advisory/adv-003-eol-version.ts
init_database2();
var adv003 = defineCheck({
  id: "ADV-003",
  name: "End-of-Life Version",
  category: "advisory",
  severity: "warning",
  description: "Detect end-of-life agent versions that no longer receive security patches",
  async run(ctx, h) {
    const version = ctx.installation.version;
    if (!version) return h.passed("Agent version not detected \u2014 skipping EOL check");
    const db = getAdvisoryDatabase();
    const agent = ctx.installation.agent;
    const eolAdvisories = db.advisories.filter((adv) => {
      if (!adv.eolNotice) return false;
      if (adv.agent !== agent && adv.agent !== "*") return false;
      return satisfies(version, adv.affectedVersions);
    });
    if (eolAdvisories.length === 0) return h.passed(`${agent} v${version} is not end-of-life`);
    const evidence = eolAdvisories.map((adv) => ({
      file: adv.id,
      detail: `${adv.id}: ${adv.description}`
    }));
    return h.result({
      passed: false,
      message: `${agent} v${version} is end-of-life and no longer receives security patches`,
      evidence
    });
  }
});

// src/checks/advisory/adv-004-known-exploit.ts
init_database2();
var adv004 = defineCheck({
  id: "ADV-004",
  name: "Known Exploit Available",
  category: "advisory",
  severity: "critical",
  description: "Flag vulnerabilities with known public exploits requiring immediate attention",
  async run(ctx, h) {
    const version = ctx.installation.version;
    if (!version) return h.passed("Agent version not detected \u2014 skipping exploit check");
    const db = getAdvisoryDatabase();
    const agent = ctx.installation.agent;
    const exploitable = db.advisories.filter((adv) => {
      if (!adv.exploitAvailable) return false;
      if (adv.agent !== agent && adv.agent !== "*") return false;
      return satisfies(version, adv.affectedVersions);
    });
    if (exploitable.length === 0) return h.passed(`No known exploits affect ${agent} v${version}`);
    const evidence = exploitable.map((adv) => ({
      file: adv.reference ?? adv.id,
      detail: `${adv.id}: ${adv.title} \u2014 EXPLOIT AVAILABLE${adv.fixedVersion ? ` (fix: v${adv.fixedVersion})` : ""}`
    }));
    return h.result({
      passed: false,
      message: `${exploitable.length} vulnerabilit${exploitable.length === 1 ? "y" : "ies"} with known exploits affect ${agent} v${version} \u2014 IMMEDIATE UPDATE RECOMMENDED`,
      evidence
    });
  }
});

// src/checks/advisory/adv-005-config-advisory.ts
init_database2();
init_utils();
var adv005 = defineCheck({
  id: "ADV-005",
  name: "Config-Based Advisory",
  category: "advisory",
  severity: "critical",
  description: "Match agent configurations against advisory config patterns",
  async run(ctx, h) {
    const db = getAdvisoryDatabase();
    const agent = ctx.installation.agent;
    const configAdvisories = db.advisories.filter((adv) => {
      if (!adv.configPattern) return false;
      return adv.agent === agent || adv.agent === "*";
    });
    if (configAdvisories.length === 0) return h.passed("No config-pattern advisories in database");
    const evidence = [];
    for (const config of ctx.configs) {
      for (const adv of configAdvisories) {
        const pattern = adv.configPattern;
        const value = getNestedValue(config.data, pattern.key);
        if (value === void 0 || value === null) continue;
        const valueStr = String(value);
        const re = new RegExp(pattern.valuePattern);
        if (re.test(valueStr)) {
          evidence.push({
            file: config.filePath,
            detail: `${adv.id}: ${adv.title} \u2014 config key "${pattern.key}" = "${valueStr}" matches dangerous pattern`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No config patterns match known advisories",
      failed: (n) => `${n} config${n === 1 ? "" : "s"} match${n === 1 ? "es" : ""} known advisory patterns`
    });
  }
});

// src/checks/advisory/index.ts
var advisoryChecks = [
  adv001,
  adv002,
  adv003,
  adv004,
  adv005
];

// src/checks/claude-code/cc-001-bypass-permissions.ts
init_utils();
var DANGEROUS_MODES = /* @__PURE__ */ new Set(["bypassPermissions", "acceptAll", "dangerouslySkipPermissions"]);
var cc001 = defineCheck({
  id: "CC-001",
  name: "Permission Bypass Mode",
  category: "coding-agent",
  severity: "critical",
  description: "Detect when Claude Code is configured to bypass tool approval prompts",
  supportedAgents: ["claude-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mode = getNestedValue(config.data, "permissions.defaultMode");
      if (mode && DANGEROUS_MODES.has(mode)) {
        evidence.push({
          file: config.filePath,
          detail: `permissions.defaultMode = "${mode}" \u2014 all tool executions skip user confirmation`
        });
      }
      const skipFlag = config.data.dangerouslySkipPermissions;
      if (skipFlag === true) {
        evidence.push({
          file: config.filePath,
          detail: "dangerouslySkipPermissions = true \u2014 agent will execute tools without approval"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Permission approval prompts are not bypassed",
      failed: () => "Permission bypass mode is enabled \u2014 Claude Code will execute tools without confirmation",
      fixDescription: 'Remove permissions.defaultMode = "bypassPermissions" or set it to "default"/"acceptEdits"'
    });
  }
});

// src/checks/claude-code/cc-002-broad-bash-allow.ts
init_utils();
var DANGEROUS_BASH_PATTERNS = [
  { pattern: /^Bash$/, reason: 'bare "Bash" allows any shell command' },
  { pattern: /^Bash\(\*\)$/, reason: "Bash(*) allows any shell command" },
  { pattern: /^Bash\(rm:/, reason: "rm with broad arguments can destroy files" },
  { pattern: /^Bash\(sudo:/, reason: "sudo grants privileged execution" },
  { pattern: /^Bash\(curl:/, reason: "curl can fetch and execute remote payloads" },
  { pattern: /^Bash\(wget:/, reason: "wget can fetch arbitrary remote content" },
  { pattern: /^Bash\(eval:/, reason: "eval executes arbitrary strings as commands" },
  { pattern: /^Bash\(sh:/, reason: "sh can run any command in a sub-shell" },
  { pattern: /^Bash\(bash:/, reason: "bash can run any command in a sub-shell" },
  { pattern: /^Bash\(chmod:/, reason: "chmod can change file permissions across the system" },
  { pattern: /^Bash\(.*\*\)$/, reason: "wildcard arguments expand the attack surface" }
];
var cc002 = defineCheck({
  id: "CC-002",
  name: "Broad Bash Allowlist",
  category: "coding-agent",
  severity: "warning",
  description: "Detect overly broad Bash patterns in Claude Code permissions.allow",
  supportedAgents: ["claude-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const allow = getNestedValue(config.data, "permissions.allow");
      if (!Array.isArray(allow)) continue;
      for (const entry of allow) {
        if (typeof entry !== "string") continue;
        for (const { pattern, reason } of DANGEROUS_BASH_PATTERNS) {
          if (pattern.test(entry)) {
            evidence.push({
              file: config.filePath,
              snippet: entry,
              detail: reason
            });
            break;
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No overly broad Bash permissions detected",
      failed: (n) => `Found ${n} risky Bash allow pattern(s) \u2014 narrow them to specific commands`,
      fixDescription: "Replace broad Bash patterns with specific subcommands (e.g. Bash(git:status))"
    });
  }
});

// src/checks/claude-code/cc-003-unsafe-hooks.ts
var UNQUOTED_VAR_PATTERN = /(?<!["'])\$(?:CLAUDE_[A-Z_]+|TOOL_INPUT|USER_PROMPT|FILE_PATH|\{[A-Z_]+\})(?!["'])/;
var COMMAND_SUBSTITUTION_PATTERN = /\$\([^)]*\$[A-Z]/;
var RAW_EVAL_PATTERN = /\b(?:eval|bash\s+-c|sh\s+-c|exec)\b/;
var cc003 = defineCheck({
  id: "CC-003",
  name: "Unsafe Hook Commands",
  category: "coding-agent",
  severity: "warning",
  description: "Detect Claude Code hooks that exec untrusted shell input without quoting",
  supportedAgents: ["claude-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const hooks = config.data.hooks;
      if (!hooks || typeof hooks !== "object") continue;
      for (const [event, entries] of Object.entries(hooks)) {
        if (!Array.isArray(entries)) continue;
        for (const entry of entries) {
          const hookList = Array.isArray(entry?.hooks) ? entry.hooks : [];
          for (const hook of hookList) {
            const cmd = hook?.command;
            if (typeof cmd !== "string") continue;
            const reasons = [];
            if (UNQUOTED_VAR_PATTERN.test(cmd)) {
              reasons.push("uses unquoted $-variables that could expand into a shell injection");
            }
            if (COMMAND_SUBSTITUTION_PATTERN.test(cmd)) {
              reasons.push("embeds variables inside command substitution");
            }
            if (RAW_EVAL_PATTERN.test(cmd)) {
              reasons.push("invokes eval/sh -c/bash -c on dynamic input");
            }
            if (reasons.length > 0) {
              evidence.push({
                file: config.filePath,
                snippet: `${event}${entry.matcher ? `(${entry.matcher})` : ""}: ${cmd.slice(0, 120)}`,
                detail: reasons.join("; ")
              });
            }
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No unsafe hook commands detected",
      failed: (n) => `Found ${n} hook command(s) that may execute untrusted input`,
      fixDescription: 'Quote $-variables ("$VAR") and avoid eval/sh -c with dynamic input'
    });
  }
});

// src/checks/claude-code/cc-004-plaintext-api-key.ts
var SECRET_KEY_NAMES = /(?:api[_-]?key|token|secret|password|credential|auth)/i;
var KNOWN_KEY_PREFIXES = [
  /^sk-ant-[A-Za-z0-9_-]{20,}/,
  /^sk-[A-Za-z0-9]{20,}/,
  /^ghp_[A-Za-z0-9]{20,}/,
  /^xoxb-[A-Za-z0-9-]{20,}/
];
var HIGH_ENTROPY_THRESHOLD4 = 4.5;
var MIN_LENGTH = 20;
var ENV_REF_PATTERN = /^\$\{?[A-Z_][A-Z0-9_]*\}?$/;
function isSecretValue(value) {
  if (value.length < MIN_LENGTH) return false;
  if (ENV_REF_PATTERN.test(value)) return false;
  if (KNOWN_KEY_PREFIXES.some((p) => p.test(value))) return true;
  return shannonEntropy(value) > HIGH_ENTROPY_THRESHOLD4;
}
function walkEnv(env, file, prefix, evidence) {
  for (const [key, value] of Object.entries(env)) {
    if (typeof value !== "string") continue;
    if (!SECRET_KEY_NAMES.test(key)) continue;
    if (!isSecretValue(value)) continue;
    evidence.push({
      file,
      snippet: `${prefix}${key}=${value.slice(0, 6)}\u2026`,
      detail: "Plaintext secret stored in Claude Code config \u2014 use $-references or apiKeyHelper"
    });
  }
}
var cc004 = defineCheck({
  id: "CC-004",
  name: "Plaintext API Key in Config",
  category: "coding-agent",
  severity: "critical",
  description: "Detect API keys or tokens stored in plaintext inside Claude Code settings",
  supportedAgents: ["claude-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const env = config.data.env;
      if (env && typeof env === "object") {
        walkEnv(env, config.filePath, "env.", evidence);
      }
      const mcpServers = config.data.mcpServers;
      if (mcpServers && typeof mcpServers === "object") {
        for (const [name, server] of Object.entries(mcpServers)) {
          if (!server || typeof server !== "object") continue;
          const serverEnv = server.env;
          if (serverEnv && typeof serverEnv === "object") {
            walkEnv(serverEnv, config.filePath, `mcpServers.${name}.env.`, evidence);
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No plaintext API keys detected in Claude Code settings",
      failed: (n) => `Found ${n} plaintext credential(s) in Claude Code settings`,
      fixDescription: 'Reference secrets via env vars ("$ANTHROPIC_API_KEY") or apiKeyHelper instead of inlining'
    });
  }
});

// src/checks/claude-code/cc-005-unpinned-mcp.ts
var PACKAGE_RUNNERS4 = /* @__PURE__ */ new Set(["npx", "pnpm", "yarn", "bunx", "uvx", "pipx"]);
var PINNED_PACKAGE = /@\d+\.\d+\.\d+/;
var SHA_PINNED2 = /(?:@sha256:|#[a-f0-9]{7,40})/i;
function checkServer(name, server, file, evidence, prefix) {
  const command = server.command;
  if (typeof command !== "string") return;
  const baseCmd = command.split("/").pop() ?? command;
  if (!PACKAGE_RUNNERS4.has(baseCmd)) return;
  const args = Array.isArray(server.args) ? server.args.filter((a) => typeof a === "string") : [];
  const pkgArg = args.find((a) => !a.startsWith("-"));
  if (!pkgArg) return;
  if (PINNED_PACKAGE.test(pkgArg) || SHA_PINNED2.test(pkgArg)) return;
  evidence.push({
    file,
    snippet: `${prefix}${name}: ${command} ${args.join(" ")}`,
    detail: `MCP server runs "${pkgArg}" via ${baseCmd} with no version pin \u2014 supply chain risk`
  });
}
var cc005 = defineCheck({
  id: "CC-005",
  name: "Unpinned MCP Server Package",
  category: "coding-agent",
  severity: "warning",
  description: "Detect MCP servers launched via npx/uvx/etc. without a pinned package version",
  supportedAgents: ["claude-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers;
      if (mcpServers && typeof mcpServers === "object") {
        for (const [name, srv] of Object.entries(mcpServers)) {
          if (srv && typeof srv === "object") {
            checkServer(name, srv, config.filePath, evidence, "mcpServers.");
          }
        }
      }
      const projects = config.data.projects;
      if (projects && typeof projects === "object") {
        for (const [projectPath, project] of Object.entries(projects)) {
          const projectServers = project?.mcpServers;
          if (projectServers && typeof projectServers === "object") {
            for (const [name, srv] of Object.entries(projectServers)) {
              if (srv && typeof srv === "object") {
                checkServer(name, srv, config.filePath, evidence, `projects[${projectPath}].mcpServers.`);
              }
            }
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All MCP server packages are version-pinned",
      failed: (n) => `Found ${n} MCP server(s) running unpinned packages`,
      fixDescription: "Pin packages to a specific version (e.g. @modelcontextprotocol/server-foo@1.2.3)"
    });
  }
});

// src/checks/claude-code/cc-006-auto-trust-project-mcp.ts
var cc006 = defineCheck({
  id: "CC-006",
  name: "Auto-Trust Project MCP Servers",
  category: "coding-agent",
  severity: "warning",
  description: "Detect enableAllProjectMcpServers, which trusts MCP servers from any project .mcp.json",
  supportedAgents: ["claude-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (config.data.enableAllProjectMcpServers === true) {
        evidence.push({
          file: config.filePath,
          detail: "enableAllProjectMcpServers = true \u2014 every project-level .mcp.json is auto-trusted"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Project-level MCP servers require explicit trust",
      failed: () => "enableAllProjectMcpServers is on \u2014 any cloned repo can run MCP servers without prompting",
      fixDescription: "Remove enableAllProjectMcpServers, or use enabledMcpjsonServers for an explicit allowlist"
    });
  }
});

// src/checks/claude-code/cc-007-api-key-helper-perms.ts
var cc007 = defineCheck({
  id: "CC-007",
  name: "apiKeyHelper Script Permissions",
  category: "coding-agent",
  severity: "warning",
  description: "Verify that an apiKeyHelper script is not world-writable",
  supportedAgents: ["claude-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const helper = config.data.apiKeyHelper;
      if (typeof helper !== "string" || helper.length === 0) continue;
      const path = helper.split(/\s+/)[0];
      try {
        if (!await ctx.fs.access(path)) {
          evidence.push({
            file: config.filePath,
            snippet: `apiKeyHelper = ${helper}`,
            detail: "apiKeyHelper script does not exist on disk"
          });
          continue;
        }
        const stat4 = await ctx.fs.stat(path);
        if ((stat4.mode & 2) !== 0) {
          evidence.push({
            file: config.filePath,
            snippet: `${path} (mode ${(stat4.mode & 511).toString(8)})`,
            detail: "apiKeyHelper is world-writable \u2014 any local user can replace it and exfiltrate the key"
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "apiKeyHelper script (if configured) has safe permissions",
      failed: (n) => `Found ${n} apiKeyHelper issue(s)`,
      fixDescription: "Run `chmod 700` on the apiKeyHelper script and ensure its parent directory is not world-writable"
    });
  }
});

// src/checks/claude-code/cc-008-missing-deny-rules.ts
init_utils();
var RECOMMENDED_DENY_PATTERNS = [
  "Bash(rm:*)",
  "Bash(sudo:*)",
  "Bash(curl:*)"
];
var cc008 = defineCheck({
  id: "CC-008",
  name: "Missing Sensitive Deny Rules",
  category: "coding-agent",
  severity: "info",
  description: "Suggest adding common deny rules when an allow list is configured but no deny list is set",
  supportedAgents: ["claude-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const allow = getNestedValue(config.data, "permissions.allow");
      const deny = getNestedValue(config.data, "permissions.deny");
      if (!Array.isArray(allow) || allow.length === 0) continue;
      const denyList = Array.isArray(deny) ? deny.filter((d) => typeof d === "string") : [];
      const missing = RECOMMENDED_DENY_PATTERNS.filter((p) => !denyList.includes(p));
      if (missing.length === RECOMMENDED_DENY_PATTERNS.length) {
        evidence.push({
          file: config.filePath,
          detail: `permissions.allow is configured but no deny rules cover dangerous commands (${missing.join(", ")})`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Permission deny list covers common destructive commands or none configured",
      failed: () => "No deny rules cover destructive commands \u2014 consider adding rm/sudo/curl deny patterns",
      fixDescription: "Add Bash(rm:*), Bash(sudo:*), Bash(curl:*) to permissions.deny"
    });
  }
});

// src/checks/claude-code/cc-009-sensitive-additional-dirs.ts
import { join as join63, normalize } from "path";
init_utils();
function buildSensitiveTargets(home) {
  return [
    { path: join63(home, ".ssh"), reason: "contains SSH private keys" },
    { path: join63(home, ".aws"), reason: "contains AWS credentials" },
    { path: join63(home, ".gnupg"), reason: "contains GPG private keys" },
    { path: join63(home, ".kube"), reason: "contains Kubernetes credentials" },
    { path: join63(home, ".docker"), reason: "contains Docker registry credentials" },
    { path: join63(home, ".netrc"), reason: "contains plaintext FTP/HTTP credentials" },
    { path: "/etc", reason: "system configuration directory" },
    { path: "/var", reason: "system runtime/log directory" },
    { path: "/root", reason: "root user home directory" }
  ];
}
function expandHome2(p, home) {
  if (p === "~") return home;
  if (p.startsWith("~/")) return join63(home, p.slice(2));
  return p;
}
function matchesSensitive(dir, targets, home) {
  const normalized = normalize(expandHome2(dir, home));
  return targets.find((t) => normalized === t.path || normalized.startsWith(t.path + "/"));
}
var cc009 = defineCheck({
  id: "CC-009",
  name: "Sensitive Additional Directories",
  category: "coding-agent",
  severity: "critical",
  description: "Detect when permissions.additionalDirectories grants Claude Code access to credential or system directories",
  supportedAgents: ["claude-code"],
  async run(ctx, h) {
    const evidence = [];
    const home = ctx.fs.homedir();
    const sensitiveTargets = buildSensitiveTargets(home);
    for (const config of ctx.configs) {
      const dirs = getNestedValue(config.data, "permissions.additionalDirectories");
      if (!Array.isArray(dirs)) continue;
      for (const entry of dirs) {
        if (typeof entry !== "string") continue;
        const match = matchesSensitive(entry, sensitiveTargets, home);
        if (match) {
          evidence.push({
            file: config.filePath,
            snippet: entry,
            detail: `Grants access to ${match.path} \u2014 ${match.reason}`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No sensitive paths in permissions.additionalDirectories",
      failed: (n) => `Found ${n} sensitive path(s) in permissions.additionalDirectories`,
      fixDescription: "Remove credential/system directories from permissions.additionalDirectories"
    });
  }
});

// src/checks/claude-code/cc-010-status-line-safety.ts
var UNQUOTED_VAR = /(?<!["'])\$(?:[A-Z_][A-Z0-9_]*|\{[A-Z_][A-Z0-9_]*\})(?!["'])/;
var REMOTE_FETCH = /\b(?:curl|wget|fetch)\b[^|]*\|\s*(?:ba)?sh/i;
var RAW_EVAL = /\b(?:eval|bash\s+-c|sh\s+-c)\b/;
var cc010 = defineCheck({
  id: "CC-010",
  name: "Unsafe Status Line Command",
  category: "coding-agent",
  severity: "warning",
  description: "Detect Claude Code statusLine commands that fetch remote scripts or interpolate unquoted input",
  supportedAgents: ["claude-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const sl = config.data.statusLine;
      if (!sl || typeof sl !== "object") continue;
      const cmd = sl.command;
      if (typeof cmd !== "string") continue;
      const reasons = [];
      if (REMOTE_FETCH.test(cmd)) reasons.push("fetches and executes a remote script");
      if (RAW_EVAL.test(cmd)) reasons.push("invokes eval/sh -c on dynamic input");
      if (UNQUOTED_VAR.test(cmd)) reasons.push("uses unquoted $-variables \u2014 potential injection");
      if (reasons.length > 0) {
        evidence.push({
          file: config.filePath,
          snippet: `statusLine.command: ${cmd.slice(0, 120)}`,
          detail: reasons.join("; ")
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Status line command (if any) looks safe",
      failed: () => "Status line command may execute untrusted input on every prompt",
      fixDescription: "Quote $-variables, avoid curl|sh patterns, point statusLine.command at a static script"
    });
  }
});

// src/checks/claude-code/cc-011-subagent-prompt-injection.ts
import { join as join64, extname as extname6 } from "path";
var PROMPT_INJECTION_RULES2 = SECURITY_PATTERNS.filter((r) => r.category === "prompt-injection");
async function getAgentDocs(dir, fs) {
  const files = [];
  try {
    const entries = await fs.readdirEntries(dir, { recursive: true });
    for (const entry of entries) {
      if (!entry.isFile) continue;
      if (extname6(entry.name).toLowerCase() !== ".md") continue;
      const fullPath = entry.parentPath ? join64(entry.parentPath, entry.name) : join64(dir, entry.name);
      files.push(fullPath);
    }
  } catch {
  }
  return files;
}
var cc011 = defineCheck({
  id: "CC-011",
  name: "Sub-Agent Prompt Injection",
  category: "coding-agent",
  severity: "warning",
  description: "Scan ~/.claude/agents/*.md sub-agent definitions for prompt injection patterns",
  supportedAgents: ["claude-code"],
  async run(ctx, h) {
    const agentsDir = join64(ctx.installation.installDir, "agents");
    if (!await ctx.fs.access(agentsDir)) return h.passed("No sub-agents directory present");
    const evidence = [];
    const files = await getAgentDocs(agentsDir, ctx.fs);
    for (const file of files) {
      try {
        const content = await ctx.fs.readFile(file);
        const matches = scanWithPatterns(content, PROMPT_INJECTION_RULES2);
        for (const m of matches) {
          evidence.push({
            file,
            line: m.line,
            snippet: m.snippet,
            detail: m.description
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No prompt injection patterns found in sub-agent definitions",
      failed: (n) => `Found ${n} prompt injection pattern(s) in sub-agent definitions`,
      fixDescription: "Audit the flagged sub-agent files; remove instructions that override or escape system prompts"
    });
  }
});

// src/checks/claude-code/cc-012-memory-secret-leak.ts
import { join as join65 } from "path";
var KNOWN_KEY_PREFIXES2 = [
  { pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/, name: "Anthropic API key" },
  { pattern: /\bsk-[A-Za-z0-9]{32,}/, name: "OpenAI-style API key" },
  { pattern: /\bghp_[A-Za-z0-9]{20,}/, name: "GitHub personal access token" },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}/, name: "GitHub fine-grained PAT" },
  { pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/, name: "Slack token" },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/, name: "AWS access key ID" }
];
var ENTROPY_THRESHOLD = 5.5;
var MIN_BLOCK_LEN = 40;
var cc012 = defineCheck({
  id: "CC-012",
  name: "Memory File Secret Leak",
  category: "coding-agent",
  severity: "critical",
  description: "Scan ~/.claude/CLAUDE.md and project CLAUDE.md for plaintext secrets and high-entropy strings",
  supportedAgents: ["claude-code"],
  async run(ctx, h) {
    const memoryFile = join65(ctx.installation.installDir, "CLAUDE.md");
    if (!await ctx.fs.access(memoryFile)) return h.passed("No CLAUDE.md memory file present");
    let content;
    try {
      content = await ctx.fs.readFile(memoryFile);
    } catch {
      return h.passed("CLAUDE.md is not readable");
    }
    const evidence = [];
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      for (const { pattern, name } of KNOWN_KEY_PREFIXES2) {
        const m = pattern.exec(lines[i]);
        if (m) {
          evidence.push({
            file: memoryFile,
            line: i + 1,
            snippet: `${m[0].slice(0, 12)}\u2026`,
            detail: `Plaintext ${name} in memory file`
          });
        }
      }
    }
    const blocks = findHighEntropyBlocks(content, ENTROPY_THRESHOLD, MIN_BLOCK_LEN);
    for (const b of blocks) {
      if (evidence.some((e) => e.line === b.line)) continue;
      evidence.push({
        file: memoryFile,
        line: b.line,
        snippet: b.snippet,
        detail: `High-entropy string (${b.entropy} bits) \u2014 possible embedded secret`
      });
    }
    return h.fromEvidence(evidence, {
      passed: "No secrets detected in CLAUDE.md memory file",
      failed: (n) => `Found ${n} potential secret(s) in CLAUDE.md`,
      fixDescription: "Remove the secret from CLAUDE.md and rotate the credential \u2014 memory files are often committed to git"
    });
  }
});

// src/checks/claude-code/index.ts
var claudeCodeChecks = [
  cc001,
  cc002,
  cc003,
  cc004,
  cc005,
  cc006,
  cc007,
  cc008,
  cc009,
  cc010,
  cc011,
  cc012
];

// src/checks/claude-desktop/cd-001-plaintext-api-key.ts
var SECRET_KEY_NAMES2 = /(?:api[_-]?key|token|secret|password|credential|auth)/i;
var KNOWN_KEY_PREFIXES3 = [
  /^sk-ant-[A-Za-z0-9_-]{20,}/,
  /^sk-[A-Za-z0-9]{20,}/,
  /^ghp_[A-Za-z0-9]{20,}/,
  /^xoxb-[A-Za-z0-9-]{20,}/
];
var HIGH_ENTROPY_THRESHOLD5 = 4.5;
var MIN_LENGTH2 = 20;
var ENV_REF_PATTERN2 = /^\$\{?[A-Z_][A-Z0-9_]*\}?$/;
function isSecretValue2(value) {
  if (value.length < MIN_LENGTH2) return false;
  if (ENV_REF_PATTERN2.test(value)) return false;
  if (KNOWN_KEY_PREFIXES3.some((p) => p.test(value))) return true;
  return shannonEntropy(value) > HIGH_ENTROPY_THRESHOLD5;
}
function walkEnv2(env, file, prefix, evidence) {
  for (const [key, value] of Object.entries(env)) {
    if (typeof value !== "string") continue;
    if (!SECRET_KEY_NAMES2.test(key)) continue;
    if (!isSecretValue2(value)) continue;
    evidence.push({
      file,
      snippet: `${prefix}${key}=${value.slice(0, 6)}\u2026`,
      detail: "Plaintext secret stored in Claude Desktop config \u2014 every MCP server child process inherits this env"
    });
  }
}
var cd001 = defineCheck({
  id: "CD-001",
  name: "Plaintext API Key in Desktop Config",
  category: "coding-agent",
  severity: "critical",
  description: "Detect API keys or tokens stored in plaintext inside claude_desktop_config.json",
  supportedAgents: ["claude-desktop"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers;
      if (!mcpServers || typeof mcpServers !== "object") continue;
      for (const [name, server] of Object.entries(mcpServers)) {
        if (!server || typeof server !== "object") continue;
        const serverEnv = server.env;
        if (serverEnv && typeof serverEnv === "object") {
          walkEnv2(serverEnv, config.filePath, `mcpServers.${name}.env.`, evidence);
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No plaintext API keys detected in Claude Desktop config",
      failed: (n) => `Found ${n} plaintext credential(s) in Claude Desktop config`,
      fixDescription: "Move secrets out of mcpServers.*.env into the system keychain or env vars referenced via shell"
    });
  }
});

// src/checks/claude-desktop/cd-002-config-file-perms.ts
var cd002 = defineCheck({
  id: "CD-002",
  name: "Desktop Config File Permissions",
  category: "coding-agent",
  severity: "warning",
  description: "Verify claude_desktop_config.json is not group/world-readable when it contains MCP env values",
  supportedAgents: ["claude-desktop"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers;
      let hasEnv = false;
      if (mcpServers && typeof mcpServers === "object") {
        for (const server of Object.values(mcpServers)) {
          if (server && typeof server === "object" && server.env) {
            hasEnv = true;
            break;
          }
        }
      }
      if (!hasEnv) continue;
      try {
        const stat4 = await ctx.fs.stat(config.filePath);
        const mode = stat4.mode & 511;
        if ((mode & 36) !== 0) {
          evidence.push({
            file: config.filePath,
            snippet: `mode ${mode.toString(8)}`,
            detail: "config holds mcpServers.*.env values and is group/world-readable \u2014 any local user can read embedded secrets"
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "claude_desktop_config.json is not group/world-readable (or holds no env material)",
      failed: (n) => `Found ${n} config file(s) with permissive read perms`,
      fixDescription: "chmod 600 ~/Library/Application\\ Support/Claude/claude_desktop_config.json"
    });
  }
});

// src/checks/claude-desktop/cd-003-unpinned-mcp.ts
var PACKAGE_RUNNERS5 = /* @__PURE__ */ new Set(["npx", "pnpm", "yarn", "bunx", "uvx", "pipx"]);
var PINNED_PACKAGE2 = /@\d+\.\d+\.\d+/;
var SHA_PINNED3 = /(?:@sha256:|#[a-f0-9]{7,40})/i;
function checkServer2(name, server, file, evidence) {
  const command = server.command;
  if (typeof command !== "string") return;
  const baseCmd = command.split("/").pop() ?? command;
  if (!PACKAGE_RUNNERS5.has(baseCmd)) return;
  const args = Array.isArray(server.args) ? server.args.filter((a) => typeof a === "string") : [];
  const pkgArg = args.find((a) => !a.startsWith("-"));
  if (!pkgArg) return;
  if (PINNED_PACKAGE2.test(pkgArg) || SHA_PINNED3.test(pkgArg)) return;
  evidence.push({
    file,
    snippet: `mcpServers.${name}: ${command} ${args.join(" ")}`,
    detail: `MCP server runs "${pkgArg}" via ${baseCmd} with no version pin \u2014 supply chain risk`
  });
}
var cd003 = defineCheck({
  id: "CD-003",
  name: "Unpinned MCP Server Package",
  category: "coding-agent",
  severity: "warning",
  description: "Detect MCP servers launched via npx/uvx/etc. without a pinned package version",
  supportedAgents: ["claude-desktop"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers;
      if (!mcpServers || typeof mcpServers !== "object") continue;
      for (const [name, srv] of Object.entries(mcpServers)) {
        if (srv && typeof srv === "object") {
          checkServer2(name, srv, config.filePath, evidence);
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All MCP server packages are version-pinned",
      failed: (n) => `Found ${n} MCP server(s) running unpinned packages`,
      fixDescription: "Pin packages to a specific version (e.g. @modelcontextprotocol/server-foo@1.2.3)"
    });
  }
});

// src/checks/claude-desktop/cd-004-http-mcp.ts
var cd004 = defineCheck({
  id: "CD-004",
  name: "Cleartext HTTP MCP Server",
  category: "coding-agent",
  severity: "warning",
  description: "Detect MCP servers configured with http:// URLs (no TLS)",
  supportedAgents: ["claude-desktop"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers;
      if (!mcpServers || typeof mcpServers !== "object") continue;
      for (const [name, srv] of Object.entries(mcpServers)) {
        if (!srv || typeof srv !== "object") continue;
        const url = srv.url;
        if (typeof url !== "string") continue;
        if (!/^http:\/\//i.test(url)) continue;
        if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/i.test(url)) continue;
        evidence.push({
          file: config.filePath,
          snippet: `mcpServers.${name}.url = ${url}`,
          detail: "MCP server reached over plaintext HTTP \u2014 tokens, prompts, and tool calls travel unencrypted"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No cleartext HTTP MCP servers configured",
      failed: (n) => `Found ${n} MCP server(s) using http:// (non-loopback)`,
      fixDescription: "Switch the MCP server URL to https:// or proxy through a TLS-terminating gateway"
    });
  }
});

// src/checks/claude-desktop/cd-005-unverified-mcpb-extensions.ts
import { join as join66 } from "path";
var EXTENSIONS_DIR = "Claude Extensions";
var cd005 = defineCheck({
  id: "CD-005",
  name: "Unverified MCPB Desktop Extensions",
  category: "coding-agent",
  severity: "warning",
  description: "Inventory installed .mcpb Desktop Extensions and flag those without a signature/author",
  supportedAgents: ["claude-desktop"],
  async run(ctx, h) {
    const evidence = [];
    const extDir = join66(ctx.installation.installDir, EXTENSIONS_DIR);
    if (!await ctx.fs.access(extDir)) {
      return h.passed("No Claude Extensions directory present");
    }
    let entries;
    try {
      entries = await ctx.fs.readdirEntries(extDir);
    } catch {
      return h.passed("Claude Extensions directory not readable");
    }
    for (const entry of entries) {
      if (!entry.isDirectory) continue;
      const manifestPath = join66(extDir, entry.name, "manifest.json");
      if (!await ctx.fs.access(manifestPath)) continue;
      let manifest = {};
      try {
        const raw = await ctx.fs.readFile(manifestPath);
        manifest = JSON.parse(raw);
      } catch {
        evidence.push({
          file: manifestPath,
          detail: `Extension "${entry.name}" has an unparseable manifest.json`
        });
        continue;
      }
      const hasSignature = manifest.signature != null || manifest.signed === true;
      const author = typeof manifest.author === "string" ? manifest.author : void 0;
      if (!hasSignature) {
        const name = typeof manifest.name === "string" ? manifest.name : entry.name;
        evidence.push({
          file: manifestPath,
          snippet: `extension: ${name}${author ? ` (author: ${author})` : ""}`,
          detail: "MCPB extension has no signature in manifest \u2014 installed bundle was not verified at install time"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All installed Desktop Extensions carry a signature",
      failed: (n) => `Found ${n} unsigned Desktop Extension(s)`,
      fixDescription: "Reinstall extensions from a trusted source that ships signed .mcpb bundles, or remove untrusted ones from the Extensions directory"
    });
  }
});

// src/checks/claude-desktop/cd-006-always-approve.ts
var APPROVAL_KEYS = ["alwaysApprove", "autoApprove", "autoApproveTools"];
function collectApprovals(obj) {
  for (const key of APPROVAL_KEYS) {
    const v = obj[key];
    if (Array.isArray(v)) return v.filter((s) => typeof s === "string");
    if (v === true) return ["*"];
  }
  return [];
}
var cd006 = defineCheck({
  id: "CD-006",
  name: "Always-Approve MCP Tools",
  category: "coding-agent",
  severity: "critical",
  description: "Detect alwaysApprove / autoApprove configuration that bypasses tool confirmation prompts",
  supportedAgents: ["claude-desktop"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const top = collectApprovals(config.data);
      if (top.length > 0) {
        evidence.push({
          file: config.filePath,
          snippet: `top-level alwaysApprove = ${JSON.stringify(top)}`,
          detail: "Global auto-approve list \u2014 every MCP tool runs without user confirmation"
        });
      }
      const mcpServers = config.data.mcpServers;
      if (!mcpServers || typeof mcpServers !== "object") continue;
      for (const [name, srv] of Object.entries(mcpServers)) {
        if (!srv || typeof srv !== "object") continue;
        const tools = collectApprovals(srv);
        if (tools.length === 0) continue;
        const broad = tools.includes("*") || tools.length >= 5;
        evidence.push({
          file: config.filePath,
          snippet: `mcpServers.${name}.alwaysApprove = ${JSON.stringify(tools)}`,
          detail: broad ? "Server has broad auto-approve \u2014 prompt-injection tool calls execute without user confirmation" : `Server auto-approves ${tools.length} tool(s) \u2014 narrow the list and re-evaluate each entry`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No always-approve auto-trust configured for MCP tools",
      failed: (n) => `Found ${n} alwaysApprove configuration(s) \u2014 confirmation prompts bypassed`,
      fixDescription: "Remove alwaysApprove entries; require explicit confirmation per tool call"
    });
  }
});

// src/checks/claude-desktop/cd-007-filesystem-server-scope.ts
import { join as join67, normalize as normalize2 } from "path";
function buildSensitiveTargets2(home) {
  return [
    { path: home, reason: "entire user home directory \u2014 too broad" },
    { path: join67(home, ".ssh"), reason: "contains SSH private keys" },
    { path: join67(home, ".aws"), reason: "contains AWS credentials" },
    { path: join67(home, ".gnupg"), reason: "contains GPG private keys" },
    { path: join67(home, ".kube"), reason: "contains Kubernetes credentials" },
    { path: join67(home, ".docker"), reason: "contains Docker registry credentials" },
    { path: join67(home, ".netrc"), reason: "contains plaintext FTP/HTTP credentials" },
    { path: "/", reason: "root of the filesystem \u2014 total exposure" },
    { path: "/etc", reason: "system configuration directory" },
    { path: "/var", reason: "system runtime/log directory" },
    { path: "/Library", reason: "macOS system Library" }
  ];
}
var FILESYSTEM_SERVER_HINTS = ["filesystem", "fs-mcp", "mcp-filesystem"];
function expandHome3(p, home) {
  if (p === "~") return home;
  if (p.startsWith("~/")) return join67(home, p.slice(2));
  return p;
}
function isFilesystemServer(name, command, args) {
  const lower = name.toLowerCase();
  if (FILESYSTEM_SERVER_HINTS.some((h) => lower.includes(h))) return true;
  const cmdLine = `${command ?? ""} ${(args ?? []).join(" ")}`;
  return /server-filesystem/i.test(cmdLine);
}
function matchesSensitive2(dir, targets, home) {
  const normalized = normalize2(expandHome3(dir, home));
  return targets.find((t) => normalized === t.path || normalized.startsWith(t.path + "/"));
}
var cd007 = defineCheck({
  id: "CD-007",
  name: "Sensitive Filesystem Server Scope",
  category: "coding-agent",
  severity: "critical",
  description: "Detect MCP filesystem servers granted access to credential or system directories",
  supportedAgents: ["claude-desktop"],
  async run(ctx, h) {
    const evidence = [];
    const home = ctx.fs.homedir();
    const sensitiveTargets = buildSensitiveTargets2(home);
    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers;
      if (!mcpServers || typeof mcpServers !== "object") continue;
      for (const [name, srv] of Object.entries(mcpServers)) {
        if (!srv || typeof srv !== "object") continue;
        const server = srv;
        const command = typeof server.command === "string" ? server.command : void 0;
        const args = Array.isArray(server.args) ? server.args.filter((a) => typeof a === "string") : [];
        if (!isFilesystemServer(name, command, args)) continue;
        const pathArgs = args.filter((a) => a.startsWith("/") || a.startsWith("~") || a.startsWith("./") || a.startsWith("../"));
        for (const p of pathArgs) {
          const match = matchesSensitive2(p, sensitiveTargets, home);
          if (match) {
            evidence.push({
              file: config.filePath,
              snippet: `mcpServers.${name} \u2192 ${p}`,
              detail: `Filesystem server granted ${match.path} \u2014 ${match.reason}`
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No MCP filesystem servers granted sensitive paths",
      failed: (n) => `Found ${n} filesystem server scope(s) covering sensitive paths`,
      fixDescription: "Narrow filesystem server args to a dedicated working directory; never include $HOME, /etc, ~/.ssh, or ~/.aws"
    });
  }
});

// src/checks/claude-desktop/cd-008-stdio-shell.ts
var SHELL_BINS2 = /* @__PURE__ */ new Set(["sh", "bash", "zsh", "fish", "dash", "ksh"]);
var SHELL_EXEC_FLAGS2 = /* @__PURE__ */ new Set(["-c", "-cu", "-uc"]);
function basename15(p) {
  const idx = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
  return idx >= 0 ? p.slice(idx + 1) : p;
}
var cd008 = defineCheck({
  id: "CD-008",
  name: "Stdio MCP via Shell -c",
  category: "coding-agent",
  severity: "critical",
  description: "Detect stdio MCP servers launched through sh -c / bash -c, where args become shell input",
  supportedAgents: ["claude-desktop"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers;
      if (!mcpServers || typeof mcpServers !== "object") continue;
      for (const [name, srv] of Object.entries(mcpServers)) {
        if (!srv || typeof srv !== "object") continue;
        const server = srv;
        const command = typeof server.command === "string" ? server.command : void 0;
        if (!command) continue;
        const args = Array.isArray(server.args) ? server.args.filter((a) => typeof a === "string") : [];
        const base = basename15(command);
        if (!SHELL_BINS2.has(base)) continue;
        if (!args.some((a) => SHELL_EXEC_FLAGS2.has(a))) continue;
        evidence.push({
          file: config.filePath,
          snippet: `mcpServers.${name}: ${command} ${args.join(" ")}`,
          detail: `MCP server launched via ${base} -c \u2014 env vars and args are reparsed as shell, opening the door to injection`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No MCP servers are launched through a shell -c invocation",
      failed: (n) => `Found ${n} MCP server(s) launched via shell -c`,
      fixDescription: 'Invoke the server binary directly with argv (command: "/path/to/server", args: [...]); avoid shell -c wrappers'
    });
  }
});

// src/checks/claude-desktop/cd-009-world-writable-command.ts
import { dirname as dirname6 } from "path";
var cd009 = defineCheck({
  id: "CD-009",
  name: "World-Writable MCP Command Path",
  category: "coding-agent",
  severity: "warning",
  description: "Detect MCP server command binaries (or their parent dirs) that any local user can replace",
  supportedAgents: ["claude-desktop"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers;
      if (!mcpServers || typeof mcpServers !== "object") continue;
      for (const [name, srv] of Object.entries(mcpServers)) {
        if (!srv || typeof srv !== "object") continue;
        const command = srv.command;
        if (typeof command !== "string" || !command.startsWith("/")) continue;
        try {
          const stat4 = await ctx.fs.stat(command);
          if ((stat4.mode & 2) !== 0) {
            evidence.push({
              file: config.filePath,
              snippet: `mcpServers.${name}.command = ${command} (mode ${(stat4.mode & 511).toString(8)})`,
              detail: "MCP command binary is world-writable \u2014 any local user can replace it and run code as you"
            });
            continue;
          }
        } catch {
          continue;
        }
        try {
          const parent = dirname6(command);
          const parentStat = await ctx.fs.stat(parent);
          if ((parentStat.mode & 2) !== 0) {
            evidence.push({
              file: config.filePath,
              snippet: `${parent} (mode ${(parentStat.mode & 511).toString(8)})`,
              detail: `Parent directory of MCP command is world-writable \u2014 attacker can swap ${command}`
            });
          }
        } catch {
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No MCP commands live on world-writable paths",
      failed: (n) => `Found ${n} MCP command(s) on world-writable paths`,
      fixDescription: "Move MCP command binaries to a non-world-writable location and chmod o-w the parent directory"
    });
  }
});

// src/checks/claude-desktop/cd-010-credentials-in-url.ts
var CRED_QUERY = /[?&](?:api[_-]?key|token|secret|password|access_token)=([^&]+)/i;
var BASIC_AUTH = /^https?:\/\/[^/@]+:[^/@]+@/i;
var BEARER_HEADER_VALUE = /^Bearer\s+[A-Za-z0-9._\-~+/=]{12,}$/i;
var cd010 = defineCheck({
  id: "CD-010",
  name: "Credentials Embedded in MCP URL/Headers",
  category: "coding-agent",
  severity: "warning",
  description: "Detect MCP server URLs with embedded basic-auth or query-string credentials, or static Bearer tokens in headers",
  supportedAgents: ["claude-desktop"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers;
      if (!mcpServers || typeof mcpServers !== "object") continue;
      for (const [name, srv] of Object.entries(mcpServers)) {
        if (!srv || typeof srv !== "object") continue;
        const server = srv;
        const url = typeof server.url === "string" ? server.url : void 0;
        if (url) {
          if (BASIC_AUTH.test(url)) {
            evidence.push({
              file: config.filePath,
              snippet: `mcpServers.${name}.url contains user:pass@host`,
              detail: "HTTP basic-auth credentials embedded in URL \u2014 visible to anyone who can read this config"
            });
          } else if (CRED_QUERY.test(url)) {
            evidence.push({
              file: config.filePath,
              snippet: `mcpServers.${name}.url contains credential query parameter`,
              detail: "API token in query string \u2014 gets logged by upstream proxies and may leak via Referer"
            });
          }
        }
        const headers = server.headers;
        if (headers && typeof headers === "object") {
          for (const [hk, hv] of Object.entries(headers)) {
            if (typeof hv !== "string") continue;
            if (BEARER_HEADER_VALUE.test(hv)) {
              evidence.push({
                file: config.filePath,
                snippet: `mcpServers.${name}.headers.${hk} = "Bearer \u2026"`,
                detail: "Static Bearer token stored in plaintext header \u2014 rotate and source from a secret manager instead"
              });
            }
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No credentials embedded in MCP URLs or headers",
      failed: (n) => `Found ${n} embedded credential(s) in MCP URL/headers`,
      fixDescription: "Move credentials out of mcpServers.*.url / .headers; use a secret manager or env-var indirection"
    });
  }
});

// src/checks/claude-desktop/index.ts
var claudeDesktopChecks = [
  cd001,
  cd002,
  cd003,
  cd004,
  cd005,
  cd006,
  cd007,
  cd008,
  cd009,
  cd010
];

// src/checks/chatgpt-desktop/cg-001-conversations-world-readable.ts
import { join as join68 } from "path";
var SCAN_DIR_PREFIXES = [
  "conversations-v3-",
  "drafts-v2-",
  "gizmos-",
  "system-hints-",
  "health-system-hints-",
  "pinned-items-user-",
  "order-orders-"
];
var MAX_SAMPLES = 3;
var cg001 = defineCheck({
  id: "CG-001",
  name: "Workspace Data Files World-Readable",
  category: "coding-agent",
  severity: "warning",
  description: "Detect when ChatGPT workspace data files (.data) carry mode 644+ and leak filenames/sizes to other local users",
  supportedAgents: ["chatgpt-desktop"],
  supportedPlatforms: ["darwin"],
  async run(ctx, h) {
    const evidence = [];
    const supportDir = ctx.installation.installDir;
    let topEntries;
    try {
      topEntries = await ctx.fs.readdirEntries(supportDir);
    } catch {
      return h.passed("ChatGPT support directory not readable");
    }
    for (const entry of topEntries) {
      if (!entry.isDirectory) continue;
      if (!SCAN_DIR_PREFIXES.some((p) => entry.name.startsWith(p))) continue;
      const subDir = join68(supportDir, entry.name);
      let files;
      try {
        files = await ctx.fs.readdirEntries(subDir);
      } catch {
        continue;
      }
      let sampled = 0;
      for (const f of files) {
        if (!f.isFile) continue;
        if (sampled >= MAX_SAMPLES) break;
        const fullPath = join68(subDir, f.name);
        try {
          const stat4 = await ctx.fs.stat(fullPath);
          if ((stat4.mode & 4) !== 0) {
            evidence.push({
              file: subDir,
              snippet: `${f.name} (mode ${(stat4.mode & 511).toString(8)})`,
              detail: "Workspace artifact is other-readable \u2014 even when encrypted, filenames/sizes/count leak to local processes and backups"
            });
            break;
          }
        } catch {
        }
        sampled++;
      }
    }
    return h.fromEvidence(evidence, {
      passed: "ChatGPT workspace data files are not other-readable",
      failed: (n) => `Found ${n} workspace director(ies) with other-readable artifacts`,
      fixDescription: "chmod -R o-r ~/Library/Application\\ Support/com.openai.chat \u2014 note ChatGPT may rewrite these on next launch"
    });
  }
});

// src/checks/chatgpt-desktop/cg-002-plaintext-email.ts
var STATSIG_PLIST = "com.openai.chat.StatsigService.plist";
var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function maskEmail(addr) {
  const at = addr.indexOf("@");
  if (at <= 1) return "\u2026@\u2026";
  return `${addr.slice(0, 1)}\u2026@${addr.slice(at + 1)}`;
}
var cg002 = defineCheck({
  id: "CG-002",
  name: "Account Email Stored in Plaintext",
  category: "coding-agent",
  severity: "info",
  description: "ChatGPT writes the signed-in account email plaintext to StatsigService.plist; surfaces in Time Machine / iCloud backups",
  supportedAgents: ["chatgpt-desktop"],
  supportedPlatforms: ["darwin"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith(STATSIG_PLIST)) continue;
      const email = config.data.userEmail;
      if (typeof email !== "string" || !EMAIL_RE.test(email)) continue;
      evidence.push({
        file: config.filePath,
        snippet: `userEmail = ${maskEmail(email)}`,
        detail: "Account email persists in cleartext outside the keychain \u2014 included in Time Machine snapshots and any FileVault-decrypted backup"
      });
    }
    return h.fromEvidence(evidence, {
      passed: "No plaintext account email detected in ChatGPT preferences",
      failed: () => "ChatGPT account email is stored in plaintext in StatsigService.plist",
      fixDescription: "Sign out and back in via the app \u2014 note OpenAI re-populates this on session restore; consider excluding the plist from backups"
    });
  }
});

// src/checks/chatgpt-desktop/cg-003-training-allowed.ts
var MAIN_PLIST = "com.openai.chat.plist";
var cg003 = defineCheck({
  id: "CG-003",
  name: "Training Data Opt-In Active",
  category: "coding-agent",
  severity: "info",
  description: "Surface when the active ChatGPT account allows OpenAI to train on conversation data",
  supportedAgents: ["chatgpt-desktop"],
  supportedPlatforms: ["darwin"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith(MAIN_PLIST)) continue;
      for (const [key, value] of Object.entries(config.data)) {
        if (!key.startsWith("lastAccountSettingsResponse_")) continue;
        if (typeof value !== "string") continue;
        try {
          const parsed = JSON.parse(value);
          if (parsed.settings?.trainingAllowed === true) {
            evidence.push({
              file: config.filePath,
              snippet: `${key}.settings.trainingAllowed = true`,
              detail: "Conversations from this workspace may be used by OpenAI for model training"
            });
          }
        } catch {
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Training-data opt-in is off (or not configurable in this account)",
      failed: () => "ChatGPT is configured to allow conversation data to be used for training",
      fixDescription: 'In ChatGPT \u2192 Settings \u2192 Data Controls, disable "Improve the model for everyone" / training on chats'
    });
  }
});

// src/checks/chatgpt-desktop/cg-004-precise-location.ts
var MAIN_PLIST2 = "com.openai.chat.plist";
var cg004 = defineCheck({
  id: "CG-004",
  name: "Precise Location Enabled",
  category: "coding-agent",
  severity: "info",
  description: "Surface when the ChatGPT account has agreed to share precise location with the model",
  supportedAgents: ["chatgpt-desktop"],
  supportedPlatforms: ["darwin"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith(MAIN_PLIST2)) continue;
      for (const [key, value] of Object.entries(config.data)) {
        if (!key.startsWith("lastAccountSettingsResponse_")) continue;
        if (typeof value !== "string") continue;
        try {
          const parsed = JSON.parse(value);
          if (parsed.settings?.preciseLocationAllowed === true) {
            evidence.push({
              file: config.filePath,
              snippet: `${key}.settings.preciseLocationAllowed = true`,
              detail: "Precise location data may be sent to ChatGPT alongside prompts"
            });
          }
        } catch {
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Precise location sharing is off",
      failed: () => "ChatGPT account is configured to share precise location with the model",
      fixDescription: 'In ChatGPT \u2192 Settings \u2192 Data Controls, set Location to "Approximate" or off'
    });
  }
});

// src/checks/chatgpt-desktop/cg-005-codesign-team-id.ts
var APP_BUNDLE_PATH4 = "/Applications/ChatGPT.app";
var EXPECTED_TEAM_ID = "2DC432GLL2";
var TEAM_ID_RE = /TeamIdentifier=([A-Z0-9]+)/;
var IDENTIFIER_RE = /Identifier=([\w.-]+)/;
var EXPECTED_IDENTIFIER = "com.openai.chat";
var cg005 = defineCheck({
  id: "CG-005",
  name: "ChatGPT.app Codesign / Team ID",
  category: "coding-agent",
  severity: "critical",
  description: "Verify /Applications/ChatGPT.app is signed with the expected OpenAI Team ID \u2014 catches a swapped/impersonated app",
  supportedAgents: ["chatgpt-desktop"],
  supportedPlatforms: ["darwin"],
  async run(ctx, h) {
    if (!ctx.installation.appBundle) {
      return h.passed("ChatGPT.app not installed under /Applications");
    }
    let result;
    try {
      result = await ctx.fs.exec("codesign", ["-dv", APP_BUNDLE_PATH4], { timeout: 5e3 });
    } catch {
      return h.passed("codesign tool not available \u2014 skipping");
    }
    const text = `${result.stdout}
${result.stderr}`;
    const teamMatch = text.match(TEAM_ID_RE);
    const idMatch = text.match(IDENTIFIER_RE);
    const evidence = [];
    if (!teamMatch || !idMatch) {
      evidence.push({
        file: APP_BUNDLE_PATH4,
        detail: "codesign returned no TeamIdentifier/Identifier \u2014 bundle is unsigned or signature is broken"
      });
    } else {
      const team = teamMatch[1];
      const id = idMatch[1];
      if (team !== EXPECTED_TEAM_ID) {
        evidence.push({
          file: APP_BUNDLE_PATH4,
          snippet: `TeamIdentifier=${team} (expected ${EXPECTED_TEAM_ID})`,
          detail: "ChatGPT.app is signed by an unexpected developer \u2014 this is not the official OpenAI build"
        });
      }
      if (id !== EXPECTED_IDENTIFIER) {
        evidence.push({
          file: APP_BUNDLE_PATH4,
          snippet: `Identifier=${id} (expected ${EXPECTED_IDENTIFIER})`,
          detail: "Bundle identifier mismatch \u2014 app at this path may have been swapped"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "ChatGPT.app codesign matches the expected OpenAI Team ID",
      failed: (n) => `Found ${n} codesign mismatch(es) on /Applications/ChatGPT.app`,
      fixDescription: "Reinstall ChatGPT from chatgpt.com/desktop or the App Store; verify the download host before trusting any prompts shown by the current bundle"
    });
  }
});

// src/checks/chatgpt-desktop/cg-006-paired-apps-inventory.ts
import { join as join69 } from "path";
var PAIRING_DIR2 = "app_pairing_extensions";
var cg006 = defineCheck({
  id: "CG-006",
  name: "Paired Apps Inventory",
  category: "coding-agent",
  severity: "info",
  description: "Inventory connectors/Apps paired with ChatGPT \u2014 when populated, this is the on-disk crumb of the connector trust set",
  supportedAgents: ["chatgpt-desktop"],
  supportedPlatforms: ["darwin"],
  async run(ctx, h) {
    const dir = join69(ctx.installation.installDir, PAIRING_DIR2);
    if (!await ctx.fs.access(dir)) {
      return h.passed("No app_pairing_extensions directory present");
    }
    let entries;
    try {
      entries = await ctx.fs.readdirEntries(dir);
    } catch {
      return h.passed("app_pairing_extensions directory not readable");
    }
    const items = entries.filter((e) => e.isFile || e.isDirectory).map((e) => e.name);
    if (items.length === 0) {
      return h.passed("No connectors / Apps paired with ChatGPT");
    }
    const evidence = items.map((name) => ({
      file: join69(dir, name),
      snippet: name,
      detail: "Paired connector \u2014 review whether this app should retain access to ChatGPT prompts/results"
    }));
    return h.result({
      passed: true,
      message: `${items.length} ChatGPT connector(s) / paired app(s) on disk \u2014 review the trust set`,
      evidence
    });
  }
});

// src/checks/chatgpt-desktop/index.ts
var chatgptDesktopChecks = [
  cg001,
  cg002,
  cg003,
  cg004,
  cg005,
  cg006
];

// src/checks/codex/cdx-001-approval-policy.ts
var DANGEROUS_POLICIES = /* @__PURE__ */ new Set(["never", "none", "auto"]);
var cdx001 = defineCheck({
  id: "CDX-001",
  name: "Codex Approval Policy Disabled",
  category: "coding-agent",
  severity: "critical",
  description: "Detect when Codex approval_policy is set to a value that skips user confirmation",
  supportedAgents: ["codex"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const policy = config.data.approval_policy ?? config.data.approvalPolicy;
      if (typeof policy === "string" && DANGEROUS_POLICIES.has(policy.toLowerCase())) {
        evidence.push({
          file: config.filePath,
          detail: `approval_policy = "${policy}" \u2014 Codex will execute commands without user approval`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Codex approval policy requires user confirmation",
      failed: () => "Codex approval policy bypasses user confirmation",
      fixDescription: 'Set approval_policy to "untrusted", "on-failure", or "on-request" in ~/.codex/config.toml'
    });
  }
});

// src/checks/codex/cdx-002-sandbox-mode.ts
var DANGEROUS_SANDBOX_MODES = /* @__PURE__ */ new Set([
  "danger-full-access",
  "danger_full_access",
  "dangerously-bypass-sandbox",
  "none",
  "disabled"
]);
var cdx002 = defineCheck({
  id: "CDX-002",
  name: "Codex Sandbox Disabled",
  category: "coding-agent",
  severity: "critical",
  description: "Detect when Codex sandbox_mode grants unrestricted host access",
  supportedAgents: ["codex"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mode = config.data.sandbox_mode ?? config.data.sandboxMode;
      if (typeof mode === "string" && DANGEROUS_SANDBOX_MODES.has(mode.toLowerCase())) {
        evidence.push({
          file: config.filePath,
          detail: `sandbox_mode = "${mode}" \u2014 Codex commands run with full host access`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Codex sandbox is restricting command execution",
      failed: () => "Codex sandbox is disabled \u2014 commands have full host access",
      fixDescription: 'Set sandbox_mode to "read-only" or "workspace-write" in ~/.codex/config.toml'
    });
  }
});

// src/checks/codex/cdx-003-auth-file-perms.ts
import { join as join70 } from "path";
var cdx003 = defineCheck({
  id: "CDX-003",
  name: "Codex Auth File Permissions",
  category: "coding-agent",
  severity: "warning",
  description: "Verify that ~/.codex/auth.json is not readable by other users",
  supportedAgents: ["codex"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const authPath = join70(ctx.installation.installDir, "auth.json");
    if (!await ctx.fs.access(authPath)) return h.passed("auth.json not present");
    const evidence = [];
    try {
      const stat4 = await ctx.fs.stat(authPath);
      const perms = stat4.mode & 511;
      if ((perms & 63) !== 0) {
        evidence.push({
          file: authPath,
          snippet: `mode 0${perms.toString(8)}`,
          detail: "auth.json is readable or writable by group/other \u2014 credentials may be exposed"
        });
      }
    } catch {
    }
    return h.fromEvidence(evidence, {
      passed: "Codex auth.json has restricted permissions",
      failed: () => "Codex auth.json is over-permissive \u2014 restrict it to 0600",
      fixDescription: "Run `chmod 600 ~/.codex/auth.json` to restrict access to the owner"
    });
  }
});

// src/checks/codex/cdx-004-unpinned-mcp.ts
var PACKAGE_RUNNERS6 = /* @__PURE__ */ new Set(["npx", "pnpm", "yarn", "bunx", "uvx", "pipx"]);
var PINNED_PACKAGE3 = /@\d+\.\d+\.\d+/;
var SHA_PINNED4 = /(?:@sha256:|#[a-f0-9]{7,40})/i;
var cdx004 = defineCheck({
  id: "CDX-004",
  name: "Codex Unpinned MCP Server",
  category: "coding-agent",
  severity: "warning",
  description: "Detect MCP servers in Codex config launched via package runners without a pinned version",
  supportedAgents: ["codex"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const servers = config.data.mcp_servers;
      if (!servers || typeof servers !== "object") continue;
      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== "object") continue;
        const command = server.command;
        const args = server.args;
        if (typeof command !== "string") continue;
        const baseCmd = command.split("/").pop() ?? command;
        if (!PACKAGE_RUNNERS6.has(baseCmd)) continue;
        const argList = Array.isArray(args) ? args.filter((a) => typeof a === "string") : [];
        const pkgArg = argList.find((a) => !a.startsWith("-"));
        if (!pkgArg) continue;
        if (PINNED_PACKAGE3.test(pkgArg) || SHA_PINNED4.test(pkgArg)) continue;
        evidence.push({
          file: config.filePath,
          snippet: `mcp_servers.${name}: ${command} ${argList.join(" ")}`,
          detail: `Runs "${pkgArg}" via ${baseCmd} with no version pin \u2014 supply chain risk`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All Codex MCP server packages are version-pinned",
      failed: (n) => `Found ${n} Codex MCP server(s) running unpinned packages`,
      fixDescription: "Pin packages to a specific version in [mcp_servers.*] config"
    });
  }
});

// src/checks/codex/cdx-005-shell-env-policy.ts
init_utils();
var cdx005 = defineCheck({
  id: "CDX-005",
  name: "Codex Shell Env Inherits All",
  category: "coding-agent",
  severity: "critical",
  description: 'Detect when shell_environment_policy.inherit = "all" leaks every env var (including secrets) to subprocess shells',
  supportedAgents: ["codex"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const inherit = getNestedValue(config.data, "shell_environment_policy.inherit") ?? getNestedValue(config.data, "shellEnvironmentPolicy.inherit");
      if (typeof inherit === "string" && inherit.toLowerCase() === "all") {
        evidence.push({
          file: config.filePath,
          detail: 'shell_environment_policy.inherit = "all" \u2014 every parent env var (incl. AWS_*, GITHUB_TOKEN, ANTHROPIC_API_KEY) is exposed to tool subprocesses and MCP servers'
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Codex shell environment policy is restricted",
      failed: () => "Codex inherits the entire process environment into tool subprocesses",
      fixDescription: 'Set [shell_environment_policy] inherit = "core" (or "none") and use include_only/set for the specific vars tools need'
    });
  }
});

// src/checks/codex/cdx-006-trusted-projects-scope.ts
import { normalize as normalize3 } from "path";
function buildBroadPaths(home) {
  return [
    { path: "/", reason: "covers the entire filesystem" },
    { path: home, reason: "covers the entire home directory" },
    { path: "/tmp", reason: "shared by all local users" },
    { path: "/var/tmp", reason: "shared by all local users" },
    { path: "/etc", reason: "system configuration directory" }
  ];
}
function expandHome4(p, home) {
  if (p === "~") return home;
  if (p.startsWith("~/")) return `${home}/${p.slice(2)}`;
  return p;
}
function isBroad(rawPath, broadPaths, home) {
  const normalized = normalize3(expandHome4(rawPath, home));
  return broadPaths.find((b) => normalized === b.path);
}
function extractTrustedPaths(data) {
  const paths = [];
  const arr = data.trusted_projects ?? data.trustedProjects;
  if (Array.isArray(arr)) {
    for (const p of arr) if (typeof p === "string") paths.push(p);
  }
  const projects = data.projects;
  if (projects && typeof projects === "object") {
    for (const [path, entry] of Object.entries(projects)) {
      if (!entry || typeof entry !== "object") continue;
      const trust = entry.trust_level ?? entry.trustLevel;
      if (typeof trust === "string" && trust.toLowerCase() === "trusted") {
        paths.push(path);
      }
    }
  }
  return paths;
}
var cdx006 = defineCheck({
  id: "CDX-006",
  name: "Codex Trusted Projects Too Broad",
  category: "coding-agent",
  severity: "warning",
  description: "Detect Codex trusted_projects entries that grant approval bypass over /, $HOME, /tmp, or /etc",
  supportedAgents: ["codex"],
  async run(ctx, h) {
    const evidence = [];
    const home = ctx.fs.homedir();
    const broadPaths = buildBroadPaths(home);
    for (const config of ctx.configs) {
      const paths = extractTrustedPaths(config.data);
      for (const p of paths) {
        const broad = isBroad(p, broadPaths, home);
        if (broad) {
          evidence.push({
            file: config.filePath,
            snippet: p,
            detail: `Trusted project path "${p}" ${broad.reason} \u2014 defeats the approval prompt for any tool run inside it`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Codex trusted projects scope is reasonable",
      failed: (n) => `Found ${n} overly broad trusted project path(s)`,
      fixDescription: "Trust specific project directories (e.g. ~/code/myrepo), not /, $HOME, or /tmp"
    });
  }
});

// src/checks/codex/cdx-007-memory-secret-leak.ts
import { join as join71 } from "path";
var KNOWN_KEY_PREFIXES4 = [
  { pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/, name: "Anthropic API key" },
  { pattern: /\bsk-[A-Za-z0-9]{32,}/, name: "OpenAI-style API key" },
  { pattern: /\bghp_[A-Za-z0-9]{20,}/, name: "GitHub personal access token" },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}/, name: "GitHub fine-grained PAT" },
  { pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/, name: "Slack token" },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/, name: "AWS access key ID" }
];
var ENTROPY_THRESHOLD2 = 5.5;
var MIN_BLOCK_LEN2 = 40;
var MEMORY_FILES2 = ["AGENTS.md", "instructions.md"];
async function scanFile(file, ctx, evidence) {
  if (!await ctx.fs.access(file)) return;
  let content;
  try {
    content = await ctx.fs.readFile(file);
  } catch {
    return;
  }
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    for (const { pattern, name } of KNOWN_KEY_PREFIXES4) {
      const m = pattern.exec(lines[i]);
      if (m) {
        evidence.push({
          file,
          line: i + 1,
          snippet: `${m[0].slice(0, 12)}\u2026`,
          detail: `Plaintext ${name} in memory file`
        });
      }
    }
  }
  const blocks = findHighEntropyBlocks(content, ENTROPY_THRESHOLD2, MIN_BLOCK_LEN2);
  for (const b of blocks) {
    if (evidence.some((e) => e.file === file && e.line === b.line)) continue;
    evidence.push({
      file,
      line: b.line,
      snippet: b.snippet,
      detail: `High-entropy string (${b.entropy} bits) \u2014 possible embedded secret`
    });
  }
}
var cdx007 = defineCheck({
  id: "CDX-007",
  name: "Codex Memory File Secret Leak",
  category: "coding-agent",
  severity: "critical",
  description: "Scan ~/.codex/AGENTS.md and ~/.codex/instructions.md for plaintext secrets and high-entropy strings",
  supportedAgents: ["codex"],
  async run(ctx, h) {
    const evidence = [];
    for (const filename of MEMORY_FILES2) {
      await scanFile(join71(ctx.installation.installDir, filename), ctx, evidence);
    }
    return h.fromEvidence(evidence, {
      passed: "No secrets detected in Codex memory files",
      failed: (n) => `Found ${n} potential secret(s) in Codex memory files`,
      fixDescription: "Remove the secret from the memory file and rotate the credential \u2014 these files are often committed to git"
    });
  }
});

// src/checks/codex/cdx-008-profile-downgrade.ts
var DANGEROUS_APPROVAL = /* @__PURE__ */ new Set(["never", "none", "auto"]);
var DANGEROUS_SANDBOX = /* @__PURE__ */ new Set([
  "danger-full-access",
  "danger_full_access",
  "dangerously-bypass-sandbox",
  "none",
  "disabled"
]);
function isDangerousApproval(v) {
  return typeof v === "string" && DANGEROUS_APPROVAL.has(v.toLowerCase());
}
function isDangerousSandbox(v) {
  return typeof v === "string" && DANGEROUS_SANDBOX.has(v.toLowerCase());
}
var cdx008 = defineCheck({
  id: "CDX-008",
  name: "Codex Profile Security Downgrade",
  category: "coding-agent",
  severity: "warning",
  description: "Detect Codex profiles that override approval_policy or sandbox_mode to a more permissive value than the root config",
  supportedAgents: ["codex"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const profiles = config.data.profiles;
      if (!profiles || typeof profiles !== "object") continue;
      const rootApproval = config.data.approval_policy ?? config.data.approvalPolicy;
      const rootSandbox = config.data.sandbox_mode ?? config.data.sandboxMode;
      for (const [name, profile] of Object.entries(profiles)) {
        if (!profile || typeof profile !== "object") continue;
        const p = profile;
        const approval = p.approval_policy ?? p.approvalPolicy;
        if (isDangerousApproval(approval) && !isDangerousApproval(rootApproval)) {
          evidence.push({
            file: config.filePath,
            snippet: `[profiles.${name}] approval_policy = "${approval}"`,
            detail: "Profile sets approval_policy to a value that skips user confirmation (root config does not)"
          });
        }
        const sandbox = p.sandbox_mode ?? p.sandboxMode;
        if (isDangerousSandbox(sandbox) && !isDangerousSandbox(rootSandbox)) {
          evidence.push({
            file: config.filePath,
            snippet: `[profiles.${name}] sandbox_mode = "${sandbox}"`,
            detail: "Profile disables the sandbox (root config does not) \u2014 `codex --profile " + name + "` runs unrestricted"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No Codex profile downgrades the root security posture",
      failed: (n) => `Found ${n} Codex profile(s) that weaken approval/sandbox vs. root config`,
      fixDescription: "Remove the override from the profile, or remove the profile entirely \u2014 the root config is the floor"
    });
  }
});

// src/checks/codex/cdx-009-unsafe-notify.ts
var SHELL_BINS3 = /* @__PURE__ */ new Set(["sh", "bash", "zsh", "fish", "dash", "ksh"]);
var SHELL_EXEC_FLAGS3 = /* @__PURE__ */ new Set(["-c", "-cu", "-uc"]);
var EVAL_LIKE = /* @__PURE__ */ new Set(["eval", "exec"]);
var WORLD_WRITABLE_DIRS = ["/tmp/", "/var/tmp/", "/private/tmp/"];
function basename16(p) {
  const idx = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
  return idx >= 0 ? p.slice(idx + 1) : p;
}
function inspectNotify(notify) {
  if (!Array.isArray(notify) || notify.length === 0) return [];
  const argv = notify.filter((v) => typeof v === "string");
  if (argv.length === 0) return [];
  const findings = [];
  const cmd = argv[0];
  const base = basename16(cmd);
  if (SHELL_BINS3.has(base) && argv.slice(1).some((a) => SHELL_EXEC_FLAGS3.has(a))) {
    findings.push({
      reason: `invokes ${base} -c, so any variable Codex injects is parsed as shell \u2014 same risk class as Claude Code unsafe hooks`
    });
  }
  if (EVAL_LIKE.has(base)) {
    findings.push({ reason: `top-level command is "${base}" \u2014 dynamic input becomes code` });
  }
  if (cmd && !cmd.startsWith("/") && !cmd.startsWith("~") && !cmd.startsWith("./") && !cmd.startsWith("../")) {
    findings.push({
      reason: `relative command name "${cmd}" \u2014 resolved via $PATH at session-end, vulnerable to PATH hijack`
    });
  }
  for (const a of argv) {
    for (const dir of WORLD_WRITABLE_DIRS) {
      if (a.startsWith(dir)) {
        findings.push({
          reason: `references ${dir} \u2014 world-writable on shared hosts, any local user can replace the script`
        });
        break;
      }
    }
  }
  return findings;
}
var cdx009 = defineCheck({
  id: "CDX-009",
  name: "Codex Unsafe Notify Command",
  category: "coding-agent",
  severity: "warning",
  description: "Detect Codex `notify` automation that invokes a shell (-c), uses a relative command name, or runs a script from a world-writable directory",
  supportedAgents: ["codex"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const rootNotify = config.data.notify;
      for (const f of inspectNotify(rootNotify)) {
        evidence.push({
          file: config.filePath,
          snippet: `notify = ${JSON.stringify(rootNotify)}`,
          detail: f.reason
        });
      }
      const profiles = config.data.profiles;
      if (profiles && typeof profiles === "object") {
        for (const [name, profile] of Object.entries(profiles)) {
          if (!profile || typeof profile !== "object") continue;
          const pn = profile.notify;
          for (const f of inspectNotify(pn)) {
            evidence.push({
              file: config.filePath,
              snippet: `[profiles.${name}] notify = ${JSON.stringify(pn)}`,
              detail: f.reason
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Codex notify command is safely configured (or not set)",
      failed: (n) => `Found ${n} unsafe Codex notify configuration(s)`,
      fixDescription: 'Use an absolute path to a non-shell script (e.g. notify = ["/usr/local/bin/codex-notify"]); avoid sh -c and /tmp scripts'
    });
  }
});

// src/checks/codex/index.ts
var codexChecks = [
  cdx001,
  cdx002,
  cdx003,
  cdx004,
  cdx005,
  cdx006,
  cdx007,
  cdx008,
  cdx009
];

// src/checks/opencode/opc-001-auth-file-perms.ts
var opc001 = defineCheck({
  id: "OPC-001",
  name: "OpenCode Auth File Permissions",
  category: "coding-agent",
  severity: "warning",
  description: "Verify that ~/.local/share/opencode/auth.json is not readable by other users",
  supportedAgents: ["opencode"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const paths = ctx.installation.agent === "opencode" ? [`${dataDirFromInstall(ctx.installation.installDir)}/auth.json`] : [];
    const evidence = [];
    for (const authPath of paths) {
      if (!await ctx.fs.access(authPath)) continue;
      try {
        const stat4 = await ctx.fs.stat(authPath);
        const perms = stat4.mode & 511;
        if ((perms & 63) !== 0) {
          evidence.push({
            file: authPath,
            snippet: `mode 0${perms.toString(8)}`,
            detail: "auth.json is readable or writable by group/other \u2014 credentials may be exposed"
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "OpenCode auth.json has restricted permissions",
      failed: () => "OpenCode auth.json is over-permissive \u2014 restrict it to 0600",
      fixDescription: "Run `chmod 600 ~/.local/share/opencode/auth.json` to restrict access to the owner"
    });
  }
});
function dataDirFromInstall(installDir) {
  return installDir.replace(/\/\.?config\/opencode$/, "/.local/share/opencode");
}

// src/checks/opencode/opc-002-permissive-permissions.ts
var HIGH_RISK_KEYS = /* @__PURE__ */ new Set(["bash", "edit", "task", "webfetch", "external_directory"]);
function actionFor(rule) {
  if (typeof rule === "string") return rule;
  if (rule && typeof rule === "object") {
    const obj = rule;
    const star = obj["*"];
    if (typeof star === "string") return star;
    for (const v of Object.values(obj)) {
      if (typeof v === "string" && v.toLowerCase() === "allow") return "allow";
    }
  }
  return void 0;
}
var opc002 = defineCheck({
  id: "OPC-002",
  name: "OpenCode Permission Auto-Allow",
  category: "coding-agent",
  severity: "critical",
  description: "Detect when OpenCode permissions auto-allow shell, edit, or other high-risk tools",
  supportedAgents: ["opencode"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const perm = config.data.permission;
      if (typeof perm === "string" && perm.toLowerCase() === "allow") {
        evidence.push({
          file: config.filePath,
          detail: 'permission = "allow" \u2014 every tool runs without user confirmation'
        });
        continue;
      }
      if (perm && typeof perm === "object") {
        for (const key of HIGH_RISK_KEYS) {
          const action = actionFor(perm[key]);
          if (action && action.toLowerCase() === "allow") {
            evidence.push({
              file: config.filePath,
              snippet: `permission.${key} = "allow"`,
              detail: `${key} runs without user confirmation`
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "OpenCode permissions require user confirmation for high-risk tools",
      failed: (n) => `Found ${n} high-risk OpenCode permission(s) set to "allow"`,
      fixDescription: 'Set permission.bash and permission.edit to "ask" (or "deny") in opencode.json'
    });
  }
});

// src/checks/opencode/opc-003-unpinned-mcp.ts
var PACKAGE_RUNNERS7 = /* @__PURE__ */ new Set(["npx", "pnpm", "yarn", "bunx", "uvx", "pipx"]);
var PINNED_PACKAGE4 = /@\d+\.\d+\.\d+/;
var SHA_PINNED5 = /(?:@sha256:|#[a-f0-9]{7,40})/i;
function checkLocal(name, server, file, evidence) {
  const cmd = server.command;
  if (!Array.isArray(cmd) || cmd.length === 0) return;
  const exec = cmd[0];
  if (typeof exec !== "string") return;
  const baseCmd = exec.split("/").pop() ?? exec;
  if (PACKAGE_RUNNERS7.has(baseCmd)) {
    const pkgArg = cmd.slice(1).find((a) => typeof a === "string" && !a.startsWith("-"));
    if (pkgArg && !PINNED_PACKAGE4.test(pkgArg) && !SHA_PINNED5.test(pkgArg)) {
      evidence.push({
        file,
        snippet: `mcp.${name}.command = ${cmd.join(" ")}`,
        detail: `MCP server runs "${pkgArg}" via ${baseCmd} with no version pin \u2014 supply chain risk`
      });
    }
    return;
  }
  if (!exec.startsWith("/") && !exec.startsWith("./") && !exec.startsWith("../") && !exec.startsWith("~")) {
    evidence.push({
      file,
      snippet: `mcp.${name}.command = ${exec}`,
      detail: `MCP server "${name}" launches bare binary "${exec}" \u2014 first match on PATH wins`
    });
  }
}
function checkRemote(name, server, file, evidence) {
  const url = server.url;
  if (typeof url !== "string") return;
  if (url.startsWith("http://")) {
    evidence.push({
      file,
      snippet: `mcp.${name}.url = ${url}`,
      detail: `Remote MCP server uses plaintext HTTP \u2014 credentials and tool calls travel unencrypted`
    });
  }
}
var opc003 = defineCheck({
  id: "OPC-003",
  name: "OpenCode MCP Server Pinning & Transport",
  category: "coding-agent",
  severity: "warning",
  description: "Detect unpinned MCP packages, bare-binary MCP launchers, and plaintext-HTTP remote MCP endpoints",
  supportedAgents: ["opencode"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mcp = config.data.mcp;
      if (!mcp || typeof mcp !== "object") continue;
      for (const [name, srv] of Object.entries(mcp)) {
        if (!srv || typeof srv !== "object") continue;
        const obj = srv;
        if (obj.type === "local") {
          checkLocal(name, obj, config.filePath, evidence);
        } else if (obj.type === "remote") {
          checkRemote(name, obj, config.filePath, evidence);
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "OpenCode MCP servers are pinned and use safe transports",
      failed: (n) => `Found ${n} OpenCode MCP server issue(s)`,
      fixDescription: "Use absolute paths for local MCP commands, pin npx/uvx packages, and prefer https:// for remote MCP URLs"
    });
  }
});

// src/checks/opencode/opc-004-auto-share.ts
var opc004 = defineCheck({
  id: "OPC-004",
  name: "OpenCode Auto-Share Sessions",
  category: "coding-agent",
  severity: "warning",
  description: "Detect when OpenCode automatically uploads sessions to the cloud share service",
  supportedAgents: ["opencode"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const share = config.data.share;
      if (typeof share === "string" && share.toLowerCase() === "auto") {
        evidence.push({
          file: config.filePath,
          snippet: 'share = "auto"',
          detail: "Sessions auto-upload to OpenCode cloud \u2014 code, prompts, and tool output may leak"
        });
      }
      if (config.data.autoshare === true) {
        evidence.push({
          file: config.filePath,
          snippet: "autoshare = true",
          detail: "Deprecated autoshare flag is enabled \u2014 sessions auto-upload to cloud"
        });
      }
    }
    const envFlag = ctx.fs.getEnv("OPENCODE_AUTO_SHARE");
    if (envFlag && envFlag !== "0" && envFlag.toLowerCase() !== "false") {
      evidence.push({
        file: "<env>",
        snippet: `OPENCODE_AUTO_SHARE=${envFlag}`,
        detail: "Environment forces auto-share regardless of config \u2014 sessions upload to cloud"
      });
    }
    return h.fromEvidence(evidence, {
      passed: "OpenCode session sharing is manual or disabled",
      failed: () => "OpenCode is configured to auto-share sessions to the cloud",
      fixDescription: 'Set "share": "manual" or "disabled" in opencode.json, and unset OPENCODE_AUTO_SHARE'
    });
  }
});

// src/checks/opencode/opc-005-unsafe-plugin-source.ts
function specToString(spec) {
  if (typeof spec === "string") return spec;
  if (Array.isArray(spec) && typeof spec[0] === "string") return spec[0];
  return void 0;
}
var opc005 = defineCheck({
  id: "OPC-005",
  name: "OpenCode Plugin Loaded from Unsafe Source",
  category: "coding-agent",
  severity: "warning",
  description: "Detect OpenCode plugins loaded from plaintext HTTP URLs (insecure remote code execution)",
  supportedAgents: ["opencode"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const plugins = config.data.plugin;
      if (!Array.isArray(plugins)) continue;
      for (const entry of plugins) {
        const spec = specToString(entry);
        if (!spec) continue;
        if (spec.startsWith("http://")) {
          evidence.push({
            file: config.filePath,
            snippet: `plugin entry: ${spec}`,
            detail: "Plugin source is plaintext HTTP \u2014 code can be tampered in transit and runs in-process"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "OpenCode plugins are loaded from safe sources",
      failed: (n) => `Found ${n} OpenCode plugin(s) loaded over plaintext HTTP`,
      fixDescription: "Use https:// URLs, npm package names, or local file paths for plugin sources"
    });
  }
});

// src/checks/opencode/opc-006-subagent-permission-downgrade.ts
var RISK_LEVEL = { deny: 0, ask: 1, allow: 2 };
var TRACKED_KEYS = ["bash", "edit", "webfetch", "task"];
function actionLevel(rule) {
  if (typeof rule === "string") return RISK_LEVEL[rule.toLowerCase()];
  if (rule && typeof rule === "object") {
    const obj = rule;
    const star = obj["*"];
    if (typeof star === "string") return RISK_LEVEL[star.toLowerCase()];
    let maxLevel;
    for (const v of Object.values(obj)) {
      if (typeof v !== "string") continue;
      const lvl = RISK_LEVEL[v.toLowerCase()];
      if (lvl === void 0) continue;
      if (maxLevel === void 0 || lvl > maxLevel) maxLevel = lvl;
    }
    return maxLevel;
  }
  return void 0;
}
function topLevelLevel(perm, key) {
  if (typeof perm === "string") return RISK_LEVEL[perm.toLowerCase()];
  if (perm && typeof perm === "object") {
    return actionLevel(perm[key]);
  }
  return void 0;
}
var opc006 = defineCheck({
  id: "OPC-006",
  name: "OpenCode Sub-Agent Permission Downgrade",
  category: "coding-agent",
  severity: "warning",
  description: "Detect when an OpenCode sub-agent has weaker permissions than the top-level config",
  supportedAgents: ["opencode"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const agents = config.data.agent;
      if (!agents || typeof agents !== "object") continue;
      const topPerm = config.data.permission;
      for (const [name, agent] of Object.entries(agents)) {
        if (!agent || typeof agent !== "object") continue;
        const subPerm = agent.permission;
        if (subPerm === void 0) continue;
        for (const key of TRACKED_KEYS) {
          const top = topLevelLevel(topPerm, key);
          const sub = topLevelLevel(subPerm, key);
          if (top === void 0 || sub === void 0) continue;
          if (sub > top) {
            evidence.push({
              file: config.filePath,
              snippet: `agent.${name}.permission.${key}`,
              detail: `Sub-agent "${name}" upgrades ${key} from "${levelName(top)}" to "${levelName(sub)}"`
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "OpenCode sub-agents do not loosen top-level permissions",
      failed: (n) => `Found ${n} OpenCode sub-agent permission downgrade(s)`,
      fixDescription: "Remove the per-agent permission override or tighten it to match the top-level policy"
    });
  }
});
function levelName(level) {
  return Object.keys(RISK_LEVEL).find((k) => RISK_LEVEL[k] === level) ?? String(level);
}

// src/checks/opencode/opc-007-memory-secret-leak.ts
import { join as join72 } from "path";
var KNOWN_KEY_PREFIXES5 = [
  { pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/, name: "Anthropic API key" },
  { pattern: /\bsk-[A-Za-z0-9]{32,}/, name: "OpenAI-style API key" },
  { pattern: /\bghp_[A-Za-z0-9]{20,}/, name: "GitHub personal access token" },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}/, name: "GitHub fine-grained PAT" },
  { pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/, name: "Slack token" },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/, name: "AWS access key ID" }
];
var ENTROPY_THRESHOLD3 = 5.5;
var MIN_BLOCK_LEN3 = 40;
var MEMORY_FILES3 = ["AGENTS.md", "CLAUDE.md"];
async function scanFile2(file, ctx, evidence) {
  if (!await ctx.fs.access(file)) return;
  let content;
  try {
    content = await ctx.fs.readFile(file);
  } catch {
    return;
  }
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    for (const { pattern, name } of KNOWN_KEY_PREFIXES5) {
      const m = pattern.exec(lines[i]);
      if (m) {
        evidence.push({
          file,
          line: i + 1,
          snippet: `${m[0].slice(0, 12)}\u2026`,
          detail: `Plaintext ${name} in memory file`
        });
      }
    }
  }
  const blocks = findHighEntropyBlocks(content, ENTROPY_THRESHOLD3, MIN_BLOCK_LEN3);
  for (const b of blocks) {
    if (evidence.some((e) => e.file === file && e.line === b.line)) continue;
    evidence.push({
      file,
      line: b.line,
      snippet: b.snippet,
      detail: `High-entropy string (${b.entropy} bits) \u2014 possible embedded secret`
    });
  }
}
var opc007 = defineCheck({
  id: "OPC-007",
  name: "OpenCode Memory File Secret Leak",
  category: "coding-agent",
  severity: "critical",
  description: "Scan ~/.config/opencode/AGENTS.md (and CLAUDE.md fallback) for plaintext secrets and high-entropy strings",
  supportedAgents: ["opencode"],
  async run(ctx, h) {
    const evidence = [];
    for (const filename of MEMORY_FILES3) {
      await scanFile2(join72(ctx.installation.installDir, filename), ctx, evidence);
    }
    return h.fromEvidence(evidence, {
      passed: "No secrets detected in OpenCode memory files",
      failed: (n) => `Found ${n} potential secret(s) in OpenCode memory files`,
      fixDescription: "Remove the secret from the memory file and rotate the credential \u2014 these files are often committed to git"
    });
  }
});

// src/checks/opencode/opc-008-continue-on-deny.ts
init_utils();
var opc008 = defineCheck({
  id: "OPC-008",
  name: "OpenCode Continue Loop on Deny",
  category: "coding-agent",
  severity: "warning",
  description: "Detect when experimental.continue_loop_on_deny is enabled \u2014 the agent retries after a user deny",
  supportedAgents: ["opencode"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const flag = getNestedValue(config.data, "experimental.continue_loop_on_deny");
      if (flag === true) {
        evidence.push({
          file: config.filePath,
          snippet: "experimental.continue_loop_on_deny = true",
          detail: "Agent loop continues after the user denies a tool \u2014 denial no longer halts execution"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "OpenCode halts the loop when a user denies a tool",
      failed: () => "OpenCode is configured to continue running after a user denies a tool",
      fixDescription: "Remove experimental.continue_loop_on_deny from opencode.json or set it to false"
    });
  }
});

// src/checks/opencode/opc-009-enterprise-plaintext.ts
init_utils();
var opc009 = defineCheck({
  id: "OPC-009",
  name: "OpenCode Enterprise URL Plaintext",
  category: "coding-agent",
  severity: "warning",
  description: "Detect when enterprise.url is set to plaintext HTTP \u2014 well-known config and tokens travel unencrypted",
  supportedAgents: ["opencode"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const url = getNestedValue(config.data, "enterprise.url");
      if (typeof url === "string" && url.startsWith("http://")) {
        evidence.push({
          file: config.filePath,
          snippet: `enterprise.url = ${url}`,
          detail: "Enterprise endpoint uses plaintext HTTP \u2014 config payload and bearer tokens travel unencrypted"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "OpenCode enterprise URL uses HTTPS (or is unset)",
      failed: () => "OpenCode enterprise URL uses plaintext HTTP",
      fixDescription: "Change enterprise.url to https:// in opencode.json"
    });
  }
});

// src/checks/opencode/opc-010-relative-plugin-path.ts
function specToString2(spec) {
  if (typeof spec === "string") return spec;
  if (Array.isArray(spec) && typeof spec[0] === "string") return spec[0];
  return void 0;
}
var opc010 = defineCheck({
  id: "OPC-010",
  name: "OpenCode Project-Relative Plugin Path",
  category: "coding-agent",
  severity: "warning",
  description: "Detect plugin entries that resolve relative to the active project \u2014 any project can ship matching code",
  supportedAgents: ["opencode"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const plugins = config.data.plugin;
      if (!Array.isArray(plugins)) continue;
      for (const entry of plugins) {
        const spec = specToString2(entry);
        if (!spec) continue;
        if (spec.startsWith("./") || spec.startsWith("../")) {
          evidence.push({
            file: config.filePath,
            snippet: `plugin entry: ${spec}`,
            detail: "Plugin path is relative \u2014 resolves under whichever project OpenCode is run from"
          });
          continue;
        }
        if (/^file:(?!\/\/)/.test(spec) || /^file:\/\/(?!\/)/.test(spec)) {
          evidence.push({
            file: config.filePath,
            snippet: `plugin entry: ${spec}`,
            detail: "Plugin file: URL is not absolute \u2014 resolution depends on the active project"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "OpenCode plugin entries use absolute paths or stable identifiers",
      failed: (n) => `Found ${n} project-relative OpenCode plugin entr${n === 1 ? "y" : "ies"}`,
      fixDescription: "Use absolute file paths (file:///abs/path/plugin.ts) or npm package names for plugins"
    });
  }
});

// src/checks/opencode/opc-011-snapshot-disabled.ts
var opc011 = defineCheck({
  id: "OPC-011",
  name: "OpenCode Snapshot Disabled",
  category: "coding-agent",
  severity: "info",
  description: "Detect when snapshot is disabled \u2014 file rollback after a destructive edit is not available",
  supportedAgents: ["opencode"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (config.data.snapshot === false) {
        evidence.push({
          file: config.filePath,
          snippet: "snapshot = false",
          detail: "Snapshot disabled \u2014 there is no rollback path if the agent makes a destructive edit"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "OpenCode snapshot is enabled (default)",
      failed: () => "OpenCode snapshot is disabled \u2014 no rollback after destructive edits",
      fixDescription: 'Remove "snapshot": false from opencode.json (snapshot defaults to true)'
    });
  }
});

// src/checks/opencode/opc-012-autoupdate-disabled.ts
var opc012 = defineCheck({
  id: "OPC-012",
  name: "OpenCode Auto-Update Disabled",
  category: "coding-agent",
  severity: "info",
  description: "Detect when OpenCode auto-update is disabled \u2014 binary may drift past security fixes",
  supportedAgents: ["opencode"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (config.data.autoupdate === false) {
        evidence.push({
          file: config.filePath,
          snippet: "autoupdate = false",
          detail: "Auto-update disabled \u2014 no notification when a security release ships"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "OpenCode auto-update is enabled or set to notify",
      failed: () => "OpenCode auto-update is disabled",
      fixDescription: 'Remove "autoupdate": false from opencode.json, or set it to "notify"'
    });
  }
});

// src/checks/opencode/index.ts
var opencodeChecks = [
  opc001,
  opc002,
  opc003,
  opc004,
  opc005,
  opc006,
  opc007,
  opc008,
  opc009,
  opc010,
  opc011,
  opc012
];

// src/checks/gemini-cli/gem-001-plaintext-api-key.ts
var SECRET_KEY_NAMES3 = /(?:api[_-]?key|token|secret|password|credential|auth)/i;
var KNOWN_KEY_PREFIXES6 = [
  /^sk-or-v1-[A-Za-z0-9]{32,}/,
  /^sk-ant-[A-Za-z0-9_-]{20,}/,
  /^sk-[A-Za-z0-9]{20,}/,
  /^ghp_[A-Za-z0-9]{20,}/,
  /^xox[baprs]-[A-Za-z0-9-]{10,}/,
  /^AIza[0-9A-Za-z_-]{30,}/
  // Google API key
];
var HIGH_ENTROPY_THRESHOLD6 = 4.5;
var MIN_LENGTH3 = 20;
var ENV_REF_PATTERN3 = /^\$\{?[A-Z_][A-Z0-9_]*\}?$/;
function isSecretValue3(value) {
  if (value.length < MIN_LENGTH3) return false;
  if (ENV_REF_PATTERN3.test(value)) return false;
  if (KNOWN_KEY_PREFIXES6.some((p) => p.test(value))) return true;
  return shannonEntropy(value) > HIGH_ENTROPY_THRESHOLD6;
}
function walkEnv3(env, file, prefix, evidence) {
  for (const [key, value] of Object.entries(env)) {
    if (typeof value !== "string") continue;
    if (!SECRET_KEY_NAMES3.test(key) && !isSecretValue3(value)) continue;
    if (!isSecretValue3(value)) continue;
    evidence.push({
      file,
      snippet: `${prefix}${key}=${value.slice(0, 8)}\u2026`,
      detail: "Plaintext secret in Gemini settings \u2014 use $-references or external env"
    });
  }
}
var gem001 = defineCheck({
  id: "GEM-001",
  name: "Plaintext API Key in Gemini Settings",
  category: "coding-agent",
  severity: "critical",
  description: "Detect API keys or tokens stored in plaintext inside ~/.gemini/settings.json",
  supportedAgents: ["gemini-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const env = config.data.env;
      if (env && typeof env === "object") walkEnv3(env, config.filePath, "env.", evidence);
      const mcpServers = config.data.mcpServers;
      if (mcpServers && typeof mcpServers === "object") {
        for (const [name, server] of Object.entries(mcpServers)) {
          if (!server || typeof server !== "object") continue;
          const serverEnv = server.env;
          if (serverEnv && typeof serverEnv === "object") {
            walkEnv3(serverEnv, config.filePath, `mcpServers.${name}.env.`, evidence);
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No plaintext API keys detected in Gemini settings",
      failed: (n) => `Found ${n} plaintext credential(s) in Gemini settings`,
      fixDescription: "Move keys to environment variables (GEMINI_API_KEY, GOOGLE_API_KEY) \u2014 Gemini reads them from process env"
    });
  }
});

// src/checks/gemini-cli/gem-002-credential-perms.ts
import { join as join73 } from "path";
var CREDENTIAL_FILES2 = [
  "settings.json",
  "oauth_creds.json",
  "google_accounts.json",
  "mcp-oauth-tokens.json",
  "a2a-oauth-tokens.json"
];
var gem002 = defineCheck({
  id: "GEM-002",
  name: "Gemini Credential File Permissions",
  category: "coding-agent",
  severity: "critical",
  description: "Verify Gemini credential and OAuth token files are not group/world readable",
  supportedAgents: ["gemini-cli"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    for (const filename of CREDENTIAL_FILES2) {
      const filePath = join73(ctx.installation.installDir, filename);
      if (!await ctx.fs.access(filePath)) continue;
      try {
        const stat4 = await ctx.fs.stat(filePath);
        const perms = stat4.mode & 511;
        if ((perms & 63) !== 0) {
          evidence.push({
            file: filePath,
            snippet: `mode 0${perms.toString(8)}`,
            detail: `${filename} is readable or writable by group/other \u2014 credentials may leak`
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Gemini credential files have restricted permissions",
      failed: (n) => `Found ${n} Gemini credential file(s) with overly permissive mode`,
      fixDescription: "Run `chmod 600 ~/.gemini/{settings,oauth_creds,google_accounts,mcp-oauth-tokens}.json` to restrict access"
    });
  }
});

// src/checks/gemini-cli/gem-003-overbroad-allow.ts
var OVERBROAD_PATTERNS = [
  /^run_shell_command$/,
  /^run_shell_command\s*\(\s*\*\s*\)$/,
  /^run_shell_command\s*\(\s*(bash|sh|zsh|fish|cmd|powershell|pwsh)\s*\)$/i,
  /^run_shell_command\s*\(\s*(rm|sudo|curl|wget|nc|ncat)\s*\)$/i,
  /^\*$/
];
var gem003 = defineCheck({
  id: "GEM-003",
  name: "Gemini Overbroad Tools Allow",
  category: "coding-agent",
  severity: "critical",
  description: "Detect tools.allowed entries that grant unbounded shell access",
  supportedAgents: ["gemini-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const tools = config.data.tools;
      const allowed = tools?.allowed;
      if (!Array.isArray(allowed)) continue;
      const confirmList = Array.isArray(tools?.confirmationRequired) ? new Set(tools.confirmationRequired.filter((s) => typeof s === "string")) : /* @__PURE__ */ new Set();
      for (const entry of allowed) {
        if (typeof entry !== "string") continue;
        if (confirmList.has(entry)) continue;
        if (!OVERBROAD_PATTERNS.some((p) => p.test(entry))) continue;
        evidence.push({
          file: config.filePath,
          snippet: `tools.allowed: "${entry}"`,
          detail: "Auto-approves arbitrary shell commands \u2014 covers far more than intended"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Gemini tools.allowed has no overbroad shell entries",
      failed: (n) => `Found ${n} overbroad shell allow rule(s) in Gemini config`,
      fixDescription: "Replace catch-alls with specific commands (e.g. `run_shell_command(git status)`, `run_shell_command(npm test)`)"
    });
  }
});

// src/checks/gemini-cli/gem-004-yolo-guard.ts
var gem004 = defineCheck({
  id: "GEM-004",
  name: "Gemini YOLO Mode Guard Removed",
  category: "coding-agent",
  severity: "critical",
  description: "Detect when security.disableYoloMode is explicitly set to false \u2014 `--yolo` CLI flag remains usable",
  supportedAgents: ["gemini-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const security = config.data.security;
      if (!security || typeof security !== "object") continue;
      if (security.disableYoloMode === false) {
        evidence.push({
          file: config.filePath,
          snippet: "security.disableYoloMode = false",
          detail: "YOLO guard explicitly off \u2014 `gemini --yolo` will auto-approve every tool call this session"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Gemini YOLO mode guard is not explicitly disabled",
      failed: () => "Gemini security.disableYoloMode is explicitly off \u2014 anyone can launch yolo sessions",
      fixDescription: "Set security.disableYoloMode: true in ~/.gemini/settings.json to block --yolo at the CLI layer"
    });
  }
});

// src/checks/gemini-cli/gem-005-sandbox-disabled.ts
var gem005 = defineCheck({
  id: "GEM-005",
  name: "Gemini Sandbox Disabled",
  category: "coding-agent",
  severity: "warning",
  description: "Detect when tools.sandbox is explicitly disabled in Gemini settings",
  supportedAgents: ["gemini-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const tools = config.data.tools;
      if (!tools || typeof tools !== "object") continue;
      if (tools.sandbox === false) {
        evidence.push({
          file: config.filePath,
          snippet: "tools.sandbox = false",
          detail: "Tools run unsandboxed \u2014 shell commands and file ops touch the host directly"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Gemini sandbox is not explicitly disabled",
      failed: () => "Gemini sandbox is disabled \u2014 tools execute on the host",
      fixDescription: 'Set tools.sandbox: true (or "docker"/"podman") in ~/.gemini/settings.json'
    });
  }
});

// src/checks/gemini-cli/gem-006-sandbox-network.ts
var gem006 = defineCheck({
  id: "GEM-006",
  name: "Gemini Sandbox Network Access Enabled",
  category: "coding-agent",
  severity: "warning",
  description: "Detect when tools.sandboxNetworkAccess is enabled \u2014 sandboxed tools can reach the network",
  supportedAgents: ["gemini-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const tools = config.data.tools;
      if (!tools || typeof tools !== "object") continue;
      if (tools.sandboxNetworkAccess === true) {
        evidence.push({
          file: config.filePath,
          snippet: "tools.sandboxNetworkAccess = true",
          detail: "Sandboxed tools can reach the network \u2014 exfiltration paths exist even when sandbox is on"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Gemini sandbox network access is restricted",
      failed: () => "Gemini sandboxed tools have network access",
      fixDescription: "Set tools.sandboxNetworkAccess: false in ~/.gemini/settings.json unless your tools genuinely need it"
    });
  }
});

// src/checks/gemini-cli/gem-007-unpinned-mcp.ts
var PACKAGE_RUNNERS8 = /* @__PURE__ */ new Set(["npx", "pnpm", "yarn", "bunx", "uvx", "pipx"]);
var PINNED_PACKAGE5 = /@\d+\.\d+\.\d+/;
var SHA_PINNED6 = /(?:@sha256:|#[a-f0-9]{7,40})/i;
var gem007 = defineCheck({
  id: "GEM-007",
  name: "Gemini Unpinned MCP Server",
  category: "coding-agent",
  severity: "warning",
  description: "Detect MCP servers in Gemini config launched via package runners without a pinned version",
  supportedAgents: ["gemini-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const servers = config.data.mcpServers;
      if (!servers || typeof servers !== "object") continue;
      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== "object") continue;
        const command = server.command;
        const args = server.args;
        if (typeof command !== "string") continue;
        const baseCmd = command.split("/").pop() ?? command;
        if (!PACKAGE_RUNNERS8.has(baseCmd)) continue;
        const argList = Array.isArray(args) ? args.filter((a) => typeof a === "string") : [];
        const pkgArg = argList.find((a) => !a.startsWith("-"));
        if (!pkgArg) continue;
        if (PINNED_PACKAGE5.test(pkgArg) || SHA_PINNED6.test(pkgArg)) continue;
        evidence.push({
          file: config.filePath,
          snippet: `mcpServers.${name}: ${command} ${argList.join(" ")}`,
          detail: `Runs "${pkgArg}" via ${baseCmd} with no version pin \u2014 supply chain risk`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All Gemini MCP server packages are version-pinned",
      failed: (n) => `Found ${n} Gemini MCP server(s) running unpinned packages`,
      fixDescription: 'Pin packages to a specific version in mcpServers.<name>.args (e.g. "@modelcontextprotocol/server-foo@1.2.3")'
    });
  }
});

// src/checks/gemini-cli/gem-008-mcp-http.ts
var URL_FIELDS = ["url", "httpUrl", "sseUrl"];
var gem008 = defineCheck({
  id: "GEM-008",
  name: "Gemini MCP Server Over Plaintext HTTP",
  category: "coding-agent",
  severity: "warning",
  description: "Detect MCP servers configured to use http:// rather than https://",
  supportedAgents: ["gemini-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const servers = config.data.mcpServers;
      if (!servers || typeof servers !== "object") continue;
      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== "object") continue;
        const obj = server;
        for (const field of URL_FIELDS) {
          const value = obj[field];
          if (typeof value !== "string") continue;
          if (!value.startsWith("http://")) continue;
          if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(value)) continue;
          evidence.push({
            file: config.filePath,
            snippet: `mcpServers.${name}.${field} = ${value}`,
            detail: "MCP traffic over plaintext HTTP \u2014 credentials, tool args, and prompts traverse unencrypted"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All Gemini MCP servers use HTTPS or localhost transports",
      failed: (n) => `Found ${n} Gemini MCP server(s) using plaintext HTTP`,
      fixDescription: "Switch the server URL to https:// (or move it behind a TLS-terminating proxy)"
    });
  }
});

// src/checks/gemini-cli/gem-009-auto-edit.ts
var gem009 = defineCheck({
  id: "GEM-009",
  name: "Gemini Auto-Approve Edit Mode",
  category: "coding-agent",
  severity: "warning",
  description: 'Detect when general.defaultApprovalMode is set to "auto_edit" \u2014 file edits run without prompting',
  supportedAgents: ["gemini-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const general = config.data.general;
      const mode = general?.defaultApprovalMode;
      if (typeof mode === "string" && mode.toLowerCase() === "auto_edit") {
        evidence.push({
          file: config.filePath,
          snippet: `general.defaultApprovalMode = "${mode}"`,
          detail: "Edit tools (file write, patch) auto-approve without per-call prompt"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Gemini default approval mode requires confirmation",
      failed: () => "Gemini default approval mode auto-approves edits",
      fixDescription: 'Set general.defaultApprovalMode to "default" (or "plan" for read-only) in ~/.gemini/settings.json'
    });
  }
});

// src/checks/gemini-cli/gem-010-memory-secrets.ts
import { join as join74 } from "path";
var KNOWN_KEY_PREFIXES7 = [
  { pattern: /\bsk-or-v1-[A-Za-z0-9]{32,}/, name: "OpenRouter API key" },
  { pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/, name: "Anthropic API key" },
  { pattern: /\bsk-[A-Za-z0-9]{32,}/, name: "OpenAI-style API key" },
  { pattern: /\bAIza[0-9A-Za-z_-]{30,}/, name: "Google API key" },
  { pattern: /\bghp_[A-Za-z0-9]{20,}/, name: "GitHub personal access token" },
  { pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/, name: "Slack token" },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/, name: "AWS access key ID" }
];
var ENTROPY_THRESHOLD4 = 5.5;
var MIN_BLOCK_LEN4 = 40;
var MEMORY_FILES4 = ["memory.md", "GEMINI.md"];
async function scanFile3(file, ctx, evidence) {
  if (!await ctx.fs.access(file)) return;
  let content;
  try {
    content = await ctx.fs.readFile(file);
  } catch {
    return;
  }
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    for (const { pattern, name } of KNOWN_KEY_PREFIXES7) {
      const m = pattern.exec(lines[i]);
      if (m) {
        evidence.push({
          file,
          line: i + 1,
          snippet: `${m[0].slice(0, 12)}\u2026`,
          detail: `Plaintext ${name} in memory file`
        });
      }
    }
  }
  const blocks = findHighEntropyBlocks(content, ENTROPY_THRESHOLD4, MIN_BLOCK_LEN4);
  for (const b of blocks) {
    if (evidence.some((e) => e.file === file && e.line === b.line)) continue;
    evidence.push({
      file,
      line: b.line,
      snippet: b.snippet,
      detail: `High-entropy string (${b.entropy} bits) \u2014 possible embedded secret`
    });
  }
}
var gem010 = defineCheck({
  id: "GEM-010",
  name: "Gemini Memory File Secret Leak",
  category: "coding-agent",
  severity: "info",
  description: "Scan ~/.gemini/memory.md and GEMINI.md for plaintext secrets and high-entropy strings",
  supportedAgents: ["gemini-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const filename of MEMORY_FILES4) {
      await scanFile3(join74(ctx.installation.installDir, filename), ctx, evidence);
    }
    return h.fromEvidence(evidence, {
      passed: "No secrets detected in Gemini memory files",
      failed: (n) => `Found ${n} potential secret(s) in Gemini memory files`,
      fixDescription: "Remove the secret from the memory file and rotate the credential \u2014 these files often end up in git or shared workspaces"
    });
  }
});

// src/checks/gemini-cli/index.ts
var geminiCliChecks = [
  gem001,
  gem002,
  gem003,
  gem004,
  gem005,
  gem006,
  gem007,
  gem008,
  gem009,
  gem010
];

// src/checks/qwen-code/qc-001-plaintext-api-key.ts
var KNOWN_KEY_PREFIXES8 = [
  /^sk-or-v1-[A-Za-z0-9]{32,}/,
  /^sk-ant-[A-Za-z0-9_-]{20,}/,
  /^sk-[A-Za-z0-9]{20,}/,
  /^ghp_[A-Za-z0-9]{20,}/,
  /^xox[baprs]-[A-Za-z0-9-]{10,}/,
  /^AIza[0-9A-Za-z_-]{30,}/
];
var HIGH_ENTROPY_THRESHOLD7 = 4.5;
var MIN_LENGTH4 = 20;
var ENV_REF_PATTERN4 = /^\$\{?[A-Z_][A-Z0-9_]*\}?$/;
function isSecretValue4(value) {
  if (value.length < MIN_LENGTH4) return false;
  if (ENV_REF_PATTERN4.test(value)) return false;
  if (KNOWN_KEY_PREFIXES8.some((p) => p.test(value))) return true;
  return shannonEntropy(value) > HIGH_ENTROPY_THRESHOLD7;
}
function walkEnv4(env, file, prefix, evidence) {
  for (const [key, value] of Object.entries(env)) {
    if (typeof value !== "string") continue;
    if (!isSecretValue4(value)) continue;
    evidence.push({
      file,
      snippet: `${prefix}${key}=${value.slice(0, 8)}\u2026`,
      detail: "Plaintext secret in Qwen settings \u2014 keys here are documented as lowest-priority fallback; prefer process env"
    });
  }
}
var qc001 = defineCheck({
  id: "QC-001",
  name: "Plaintext API Key in Qwen Settings",
  category: "coding-agent",
  severity: "critical",
  description: "Detect API keys stored in plaintext in ~/.qwen/settings.json under env or modelProviders",
  supportedAgents: ["qwen-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const env = config.data.env;
      if (env && typeof env === "object") walkEnv4(env, config.filePath, "env.", evidence);
      const providers = config.data.modelProviders;
      if (providers && typeof providers === "object") {
        for (const [provName, list] of Object.entries(providers)) {
          if (!Array.isArray(list)) continue;
          for (let i = 0; i < list.length; i++) {
            const item = list[i];
            if (!item || typeof item !== "object") continue;
            const obj = item;
            const apiKey = obj.apiKey;
            if (typeof apiKey === "string" && isSecretValue4(apiKey)) {
              evidence.push({
                file: config.filePath,
                snippet: `modelProviders.${provName}[${i}].apiKey=${apiKey.slice(0, 8)}\u2026`,
                detail: "Inline apiKey in modelProviders entry \u2014 use envKey reference instead"
              });
            }
          }
        }
      }
      const mcpServers = config.data.mcpServers;
      if (mcpServers && typeof mcpServers === "object") {
        for (const [name, server] of Object.entries(mcpServers)) {
          if (!server || typeof server !== "object") continue;
          const serverEnv = server.env;
          if (serverEnv && typeof serverEnv === "object") {
            walkEnv4(serverEnv, config.filePath, `mcpServers.${name}.env.`, evidence);
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No plaintext API keys detected in Qwen settings",
      failed: (n) => `Found ${n} plaintext credential(s) in Qwen settings`,
      fixDescription: "Move keys to environment variables (referenced via envKey in modelProviders); rotate any key found here"
    });
  }
});

// src/checks/qwen-code/qc-002-credential-perms.ts
import { join as join75 } from "path";
var CREDENTIAL_FILES3 = [
  "settings.json",
  "oauth_creds.json",
  "mcp-oauth-tokens.json",
  "google_accounts.json",
  ".env"
];
var qc002 = defineCheck({
  id: "QC-002",
  name: "Qwen Credential File Permissions",
  category: "coding-agent",
  severity: "critical",
  description: "Verify Qwen credential and OAuth token files are not group/world readable",
  supportedAgents: ["qwen-code"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    for (const filename of CREDENTIAL_FILES3) {
      const filePath = join75(ctx.installation.installDir, filename);
      if (!await ctx.fs.access(filePath)) continue;
      try {
        const stat4 = await ctx.fs.stat(filePath);
        const perms = stat4.mode & 511;
        if ((perms & 63) !== 0) {
          evidence.push({
            file: filePath,
            snippet: `mode 0${perms.toString(8)}`,
            detail: `${filename} is readable or writable by group/other \u2014 credentials may leak`
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Qwen credential files have restricted permissions",
      failed: (n) => `Found ${n} Qwen credential file(s) with overly permissive mode`,
      fixDescription: "Run `chmod 600 ~/.qwen/{settings,oauth_creds,mcp-oauth-tokens,google_accounts}.json ~/.qwen/.env` to restrict access"
    });
  }
});

// src/checks/qwen-code/qc-003-yolo-mode.ts
var DANGEROUS_MODES2 = /* @__PURE__ */ new Set(["yolo"]);
var qc003 = defineCheck({
  id: "QC-003",
  name: "Qwen YOLO Approval Mode",
  category: "coding-agent",
  severity: "critical",
  description: 'Detect approvalMode set to "yolo" \u2014 auto-approves every tool call',
  supportedAgents: ["qwen-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mode = config.data.approvalMode;
      if (typeof mode === "string" && DANGEROUS_MODES2.has(mode.toLowerCase())) {
        evidence.push({
          file: config.filePath,
          snippet: `approvalMode = "${mode}"`,
          detail: "Qwen will execute every tool \u2014 including shell commands \u2014 without prompting"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Qwen approval mode is not yolo",
      failed: () => "Qwen approvalMode is set to yolo \u2014 every tool auto-approves",
      fixDescription: 'Set approvalMode to "default" (or "plan" for read-only) in ~/.qwen/settings.json'
    });
  }
});

// src/checks/qwen-code/qc-004-mcp-trust.ts
var qc004 = defineCheck({
  id: "QC-004",
  name: "Qwen MCP Server Marked Trusted",
  category: "coding-agent",
  severity: "critical",
  description: "Detect MCP servers with trust:true \u2014 bypasses tool-call approval",
  supportedAgents: ["qwen-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const servers = config.data.mcpServers;
      if (!servers || typeof servers !== "object") continue;
      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== "object") continue;
        if (server.trust === true) {
          evidence.push({
            file: config.filePath,
            snippet: `mcpServers.${name}.trust = true`,
            detail: "Tool calls from this MCP server execute without approval \u2014 equivalent to yolo for that server"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No Qwen MCP server is marked as trusted",
      failed: (n) => `Found ${n} Qwen MCP server(s) with trust:true`,
      fixDescription: "Remove trust:true; rely on per-call approval or specific allow rules in permissions.allow"
    });
  }
});

// src/checks/qwen-code/qc-005-deny-vs-allow.ts
var BROAD_ALLOW = /\*|^run_shell_command$|^Shell\b/i;
var qc005 = defineCheck({
  id: "QC-005",
  name: "Qwen Allow With Empty Deny",
  category: "coding-agent",
  severity: "warning",
  description: "Detect permissions.allow containing wildcards/broad patterns when permissions.deny is empty",
  supportedAgents: ["qwen-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const perms = config.data.permissions;
      if (!perms || typeof perms !== "object") continue;
      const allow = Array.isArray(perms.allow) ? perms.allow.filter((a) => typeof a === "string") : [];
      const deny = Array.isArray(perms.deny) ? perms.deny.filter((a) => typeof a === "string") : [];
      if (deny.length > 0) continue;
      const broad = allow.filter((rule) => BROAD_ALLOW.test(rule));
      if (broad.length === 0) continue;
      evidence.push({
        file: config.filePath,
        snippet: `permissions.allow has ${broad.length} broad rule(s); permissions.deny is empty`,
        detail: `Broad allow rules without a deny net: ${broad.slice(0, 3).join(", ")}${broad.length > 3 ? ", \u2026" : ""}`
      });
    }
    return h.fromEvidence(evidence, {
      passed: "Qwen permissions either lack broad allow rules or have a deny net",
      failed: () => "Qwen permissions.allow includes broad patterns with empty permissions.deny",
      fixDescription: 'Add explicit deny rules (e.g., "Shell(rm)", "Write(.env)") or narrow the allow patterns'
    });
  }
});

// src/checks/qwen-code/qc-006-unpinned-mcp.ts
var PACKAGE_RUNNERS9 = /* @__PURE__ */ new Set(["npx", "pnpm", "yarn", "bunx", "uvx", "pipx"]);
var PINNED_PACKAGE6 = /@\d+\.\d+\.\d+/;
var SHA_PINNED7 = /(?:@sha256:|#[a-f0-9]{7,40})/i;
var qc006 = defineCheck({
  id: "QC-006",
  name: "Qwen Unpinned MCP Server",
  category: "coding-agent",
  severity: "warning",
  description: "Detect MCP servers in Qwen config launched via package runners without a pinned version",
  supportedAgents: ["qwen-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const servers = config.data.mcpServers;
      if (!servers || typeof servers !== "object") continue;
      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== "object") continue;
        const command = server.command;
        const args = server.args;
        if (typeof command !== "string") continue;
        const baseCmd = command.split("/").pop() ?? command;
        if (!PACKAGE_RUNNERS9.has(baseCmd)) continue;
        const argList = Array.isArray(args) ? args.filter((a) => typeof a === "string") : [];
        const pkgArg = argList.find((a) => !a.startsWith("-"));
        if (!pkgArg) continue;
        if (PINNED_PACKAGE6.test(pkgArg) || SHA_PINNED7.test(pkgArg)) continue;
        evidence.push({
          file: config.filePath,
          snippet: `mcpServers.${name}: ${command} ${argList.join(" ")}`,
          detail: `Runs "${pkgArg}" via ${baseCmd} with no version pin \u2014 supply chain risk`
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All Qwen MCP server packages are version-pinned",
      failed: (n) => `Found ${n} Qwen MCP server(s) running unpinned packages`,
      fixDescription: 'Pin packages in mcpServers.<name>.args (e.g. "@modelcontextprotocol/server-foo@1.2.3")'
    });
  }
});

// src/checks/qwen-code/qc-007-mcp-http.ts
var URL_FIELDS2 = ["url", "httpUrl", "sseUrl"];
var qc007 = defineCheck({
  id: "QC-007",
  name: "Qwen MCP Server Over Plaintext HTTP",
  category: "coding-agent",
  severity: "warning",
  description: "Detect Qwen MCP servers configured to use http:// rather than https://",
  supportedAgents: ["qwen-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const servers = config.data.mcpServers;
      if (!servers || typeof servers !== "object") continue;
      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== "object") continue;
        const obj = server;
        for (const field of URL_FIELDS2) {
          const value = obj[field];
          if (typeof value !== "string") continue;
          if (!value.startsWith("http://")) continue;
          if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(value)) continue;
          evidence.push({
            file: config.filePath,
            snippet: `mcpServers.${name}.${field} = ${value}`,
            detail: "MCP traffic over plaintext HTTP \u2014 credentials, tool args, and prompts traverse unencrypted"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All Qwen MCP servers use HTTPS or localhost transports",
      failed: (n) => `Found ${n} Qwen MCP server(s) using plaintext HTTP`,
      fixDescription: "Switch the server URL to https:// (or move it behind a TLS-terminating proxy)"
    });
  }
});

// src/checks/qwen-code/qc-008-auto-edit.ts
var qc008 = defineCheck({
  id: "QC-008",
  name: "Qwen Auto-Edit Mode",
  category: "coding-agent",
  severity: "warning",
  description: 'Detect approvalMode set to "auto-edit" \u2014 file edits run without prompting',
  supportedAgents: ["qwen-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mode = config.data.approvalMode;
      if (typeof mode === "string" && mode.toLowerCase() === "auto-edit") {
        evidence.push({
          file: config.filePath,
          snippet: `approvalMode = "${mode}"`,
          detail: "Edit tools (file write, patch) auto-approve without per-call prompt"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Qwen approval mode requires confirmation for edits",
      failed: () => "Qwen approvalMode is auto-edit \u2014 file changes run without prompting",
      fixDescription: 'Set approvalMode to "default" (or "plan" for read-only) in ~/.qwen/settings.json'
    });
  }
});

// src/checks/qwen-code/qc-009-telemetry-prompts.ts
var qc009 = defineCheck({
  id: "QC-009",
  name: "Qwen Telemetry Logs Prompts",
  category: "coding-agent",
  severity: "info",
  description: "Detect telemetry.logPrompts set to true \u2014 user prompts are sent to telemetry",
  supportedAgents: ["qwen-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const telemetry = config.data.telemetry;
      if (!telemetry || typeof telemetry !== "object") continue;
      if (telemetry.logPrompts === true) {
        evidence.push({
          file: config.filePath,
          snippet: "telemetry.logPrompts = true",
          detail: "Prompts (which may contain code, secrets, or PII) are sent to the telemetry endpoint"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Qwen telemetry does not log prompt content",
      failed: () => "Qwen telemetry.logPrompts is enabled \u2014 prompt content is uploaded",
      fixDescription: "Set telemetry.logPrompts: false in ~/.qwen/settings.json (or omit telemetry entirely)"
    });
  }
});

// src/checks/qwen-code/qc-010-memory-secrets.ts
import { join as join76 } from "path";
var KNOWN_KEY_PREFIXES9 = [
  { pattern: /\bsk-or-v1-[A-Za-z0-9]{32,}/, name: "OpenRouter API key" },
  { pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/, name: "Anthropic API key" },
  { pattern: /\bsk-[A-Za-z0-9]{32,}/, name: "OpenAI-style API key" },
  { pattern: /\bAIza[0-9A-Za-z_-]{30,}/, name: "Google API key" },
  { pattern: /\bghp_[A-Za-z0-9]{20,}/, name: "GitHub personal access token" },
  { pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/, name: "Slack token" },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/, name: "AWS access key ID" }
];
var ENTROPY_THRESHOLD5 = 5.5;
var MIN_BLOCK_LEN5 = 40;
var MEMORY_FILES5 = ["memory.md", "AGENTS.md"];
async function scanFile4(file, ctx, evidence) {
  if (!await ctx.fs.access(file)) return;
  let content;
  try {
    content = await ctx.fs.readFile(file);
  } catch {
    return;
  }
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    for (const { pattern, name } of KNOWN_KEY_PREFIXES9) {
      const m = pattern.exec(lines[i]);
      if (m) {
        evidence.push({
          file,
          line: i + 1,
          snippet: `${m[0].slice(0, 12)}\u2026`,
          detail: `Plaintext ${name} in memory file`
        });
      }
    }
  }
  const blocks = findHighEntropyBlocks(content, ENTROPY_THRESHOLD5, MIN_BLOCK_LEN5);
  for (const b of blocks) {
    if (evidence.some((e) => e.file === file && e.line === b.line)) continue;
    evidence.push({
      file,
      line: b.line,
      snippet: b.snippet,
      detail: `High-entropy string (${b.entropy} bits) \u2014 possible embedded secret`
    });
  }
}
var qc010 = defineCheck({
  id: "QC-010",
  name: "Qwen Memory File Secret Leak",
  category: "coding-agent",
  severity: "info",
  description: "Scan ~/.qwen/memory.md and AGENTS.md for plaintext secrets and high-entropy strings",
  supportedAgents: ["qwen-code"],
  async run(ctx, h) {
    const evidence = [];
    for (const filename of MEMORY_FILES5) {
      await scanFile4(join76(ctx.installation.installDir, filename), ctx, evidence);
    }
    return h.fromEvidence(evidence, {
      passed: "No secrets detected in Qwen memory files",
      failed: (n) => `Found ${n} potential secret(s) in Qwen memory files`,
      fixDescription: "Remove the secret from the memory file and rotate the credential \u2014 these files often end up in git"
    });
  }
});

// src/checks/qwen-code/index.ts
var qwenCodeChecks = [
  qc001,
  qc002,
  qc003,
  qc004,
  qc005,
  qc006,
  qc007,
  qc008,
  qc009,
  qc010
];

// src/checks/cursor-cli/cur-001-sandbox-disabled.ts
var cur001 = defineCheck({
  id: "CUR-001",
  name: "Cursor Sandbox Disabled",
  category: "coding-agent",
  severity: "critical",
  description: 'Detect when sandbox.mode is set to "disabled" \u2014 tools run unsandboxed on the host',
  supportedAgents: ["cursor-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const sandbox = config.data.sandbox;
      if (!sandbox || typeof sandbox !== "object") continue;
      const mode = sandbox.mode;
      if (typeof mode === "string" && mode.toLowerCase() === "disabled") {
        evidence.push({
          file: config.filePath,
          snippet: `sandbox.mode = "${mode}"`,
          detail: "All Cursor tool calls execute on the host without sandboxing \u2014 relies entirely on permissions.allow as the only gate"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Cursor sandbox is enabled",
      failed: () => "Cursor sandbox is disabled \u2014 tools execute directly on the host",
      fixDescription: 'Set sandbox.mode to "enabled" (or another non-disabled mode) in ~/.cursor/cli-config.json'
    });
  }
});

// src/checks/cursor-cli/cur-002-unsafe-approval.ts
var UNSAFE_MODES = /* @__PURE__ */ new Set(["yolo", "auto", "run-everything", "force", "auto-everything"]);
var cur002 = defineCheck({
  id: "CUR-002",
  name: "Cursor Unsafe Approval Mode",
  category: "coding-agent",
  severity: "critical",
  description: "Detect approvalMode set to a value that auto-approves all tool calls",
  supportedAgents: ["cursor-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const mode = config.data.approvalMode;
      if (typeof mode === "string" && UNSAFE_MODES.has(mode.toLowerCase())) {
        evidence.push({
          file: config.filePath,
          snippet: `approvalMode = "${mode}"`,
          detail: "Cursor will execute tool calls (including shell commands) without per-call confirmation"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Cursor approval mode requires explicit allow rules or per-call confirmation",
      failed: () => "Cursor approvalMode auto-approves every tool call",
      fixDescription: 'Set approvalMode to "default" or "allowlist" in ~/.cursor/cli-config.json'
    });
  }
});

// src/checks/cursor-cli/cur-003-overbroad-shell.ts
var OVERBROAD_SHELL = [
  /^Shell$/i,
  /^Shell\s*\(\s*\*\s*\)$/i,
  /^Shell\s*\(\s*(bash|sh|zsh|fish|cmd|powershell|pwsh)\s*\)$/i,
  /^Shell\s*\(\s*(rm|sudo|curl|wget|nc|ncat|eval|exec)\s*\)$/i
];
var cur003 = defineCheck({
  id: "CUR-003",
  name: "Cursor Overbroad Shell Allow",
  category: "coding-agent",
  severity: "critical",
  description: "Detect permissions.allow entries that grant unbounded shell access",
  supportedAgents: ["cursor-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const perms = config.data.permissions;
      if (!perms || typeof perms !== "object") continue;
      const allow = Array.isArray(perms.allow) ? perms.allow.filter((a) => typeof a === "string") : [];
      const deny = Array.isArray(perms.deny) ? perms.deny.filter((a) => typeof a === "string") : [];
      const denySet = new Set(deny.map((d) => d.toLowerCase()));
      for (const rule of allow) {
        if (denySet.has(rule.toLowerCase())) continue;
        if (!OVERBROAD_SHELL.some((p) => p.test(rule))) continue;
        evidence.push({
          file: config.filePath,
          snippet: `permissions.allow: "${rule}"`,
          detail: "Auto-approves arbitrary shell commands \u2014 covers far more than intended"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Cursor permissions.allow has no overbroad shell entries",
      failed: (n) => `Found ${n} overbroad Shell allow rule(s) in Cursor config`,
      fixDescription: "Replace catch-alls with specific commands (e.g. Shell(git), Shell(npm)) and add deny rules for risky shells"
    });
  }
});

// src/checks/cursor-cli/cur-004-config-perms.ts
import { join as join77 } from "path";
var PROTECTED_FILES = ["cli-config.json", "mcp.json"];
var cur004 = defineCheck({
  id: "CUR-004",
  name: "Cursor Config File Permissions",
  category: "coding-agent",
  severity: "critical",
  description: "Verify ~/.cursor/cli-config.json (and mcp.json) are not readable by group or other users",
  supportedAgents: ["cursor-cli"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    for (const filename of PROTECTED_FILES) {
      const filePath = join77(ctx.installation.installDir, filename);
      if (!await ctx.fs.access(filePath)) continue;
      try {
        const stat4 = await ctx.fs.stat(filePath);
        const perms = stat4.mode & 511;
        if ((perms & 63) !== 0) {
          evidence.push({
            file: filePath,
            snippet: `mode 0${perms.toString(8)}`,
            detail: `${filename} is readable or writable by group/other \u2014 auth state and tokens may leak`
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Cursor config files have restricted permissions",
      failed: (n) => `Found ${n} Cursor config file(s) with overly permissive mode`,
      fixDescription: "Run `chmod 600 ~/.cursor/cli-config.json ~/.cursor/mcp.json` to restrict access to the owner"
    });
  }
});

// src/checks/cursor-cli/cur-005-deny-vs-allow.ts
var BROAD_PATTERNS = [
  /Shell\s*\(\s*\*\s*\)/i,
  /Write\s*\(\s*\*\s*\)/i,
  /Read\s*\(\s*\*\s*\)/i,
  /WebFetch\s*\(\s*\*\s*\)/i,
  /Mcp\s*\(\s*\*\s*\)/i
];
var cur005 = defineCheck({
  id: "CUR-005",
  name: "Cursor Allow With Empty Deny",
  category: "coding-agent",
  severity: "warning",
  description: "Detect permissions.allow containing wildcard patterns when permissions.deny is empty",
  supportedAgents: ["cursor-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const perms = config.data.permissions;
      if (!perms || typeof perms !== "object") continue;
      const allow = Array.isArray(perms.allow) ? perms.allow.filter((a) => typeof a === "string") : [];
      const deny = Array.isArray(perms.deny) ? perms.deny.filter((a) => typeof a === "string") : [];
      if (deny.length > 0) continue;
      const broad = allow.filter((rule) => BROAD_PATTERNS.some((p) => p.test(rule)));
      if (broad.length === 0) continue;
      evidence.push({
        file: config.filePath,
        snippet: `permissions.deny is empty; allow has ${broad.length} wildcard rule(s)`,
        detail: `Wildcard allows without a deny net: ${broad.slice(0, 3).join(", ")}${broad.length > 3 ? ", \u2026" : ""}`
      });
    }
    return h.fromEvidence(evidence, {
      passed: "Cursor permissions either lack wildcards or have a deny net",
      failed: () => "Cursor permissions.allow uses wildcards but permissions.deny is empty",
      fixDescription: "Add explicit deny rules (e.g. Shell(rm), Write(**/*.env)) or narrow the allow patterns"
    });
  }
});

// src/checks/cursor-cli/cur-006-mcp-http.ts
import { join as join78 } from "path";
var URL_FIELDS3 = ["url", "httpUrl", "sseUrl"];
var cur006 = defineCheck({
  id: "CUR-006",
  name: "Cursor MCP Server Over Plaintext HTTP",
  category: "coding-agent",
  severity: "warning",
  description: "Detect MCP servers in ~/.cursor/mcp.json configured to use http:// rather than https://",
  supportedAgents: ["cursor-cli"],
  async run(ctx, h) {
    const evidence = [];
    const mcpPath = join78(ctx.installation.installDir, "mcp.json");
    if (!await ctx.fs.access(mcpPath)) {
      return h.passed("No mcp.json present");
    }
    let parsed;
    try {
      const raw = await ctx.fs.readFile(mcpPath);
      parsed = JSON.parse(stripJsonc(raw));
    } catch {
      return h.passed("mcp.json could not be parsed");
    }
    const servers = parsed.mcpServers;
    if (!servers || typeof servers !== "object") {
      return h.passed("No MCP servers configured");
    }
    for (const [name, server] of Object.entries(servers)) {
      if (!server || typeof server !== "object") continue;
      const obj = server;
      for (const field of URL_FIELDS3) {
        const value = obj[field];
        if (typeof value !== "string") continue;
        if (!value.startsWith("http://")) continue;
        if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(value)) continue;
        evidence.push({
          file: mcpPath,
          snippet: `mcpServers.${name}.${field} = ${value}`,
          detail: "MCP traffic over plaintext HTTP \u2014 bearer tokens in headers traverse unencrypted"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "All Cursor MCP servers use HTTPS or localhost transports",
      failed: (n) => `Found ${n} Cursor MCP server(s) using plaintext HTTP`,
      fixDescription: "Switch the server URL to https:// (or move it behind a TLS-terminating proxy)"
    });
  }
});

// src/checks/cursor-cli/cur-007-privacy-mode.ts
var cur007 = defineCheck({
  id: "CUR-007",
  name: "Cursor Privacy Mode Disabled",
  category: "coding-agent",
  severity: "warning",
  description: "Detect when privacyCache shows ghostMode=false or privacyMode != 1 (training data may be retained)",
  supportedAgents: ["cursor-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const privacy = config.data.privacyCache;
      if (!privacy || typeof privacy !== "object") continue;
      if (privacy.ghostMode === false) {
        evidence.push({
          file: config.filePath,
          snippet: "privacyCache.ghostMode = false",
          detail: "Ghost mode off \u2014 Cursor may store and use code/prompts beyond the active session"
        });
      }
      if (typeof privacy.privacyMode === "number" && privacy.privacyMode !== 1) {
        evidence.push({
          file: config.filePath,
          snippet: `privacyCache.privacyMode = ${privacy.privacyMode}`,
          detail: "Privacy mode disabled (1 = on) \u2014 code may be sent to model providers for training"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Cursor privacy mode is enabled (ZDR active)",
      failed: (n) => `Cursor privacy mode is weakened (${n} signal(s))`,
      fixDescription: "Enable Privacy Mode in Cursor settings \u2014 ensures Zero Data Retention with model providers"
    });
  }
});

// src/checks/cursor-cli/cur-008-sandbox-network.ts
var UNRESTRICTED_VALUES = /* @__PURE__ */ new Set(["unrestricted", "allowed", "all", "true"]);
var cur008 = defineCheck({
  id: "CUR-008",
  name: "Cursor Sandbox Network Unrestricted",
  category: "coding-agent",
  severity: "warning",
  description: "Detect sandbox.networkAccess set to an unrestricted value \u2014 sandboxed tools can reach arbitrary hosts",
  supportedAgents: ["cursor-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const sandbox = config.data.sandbox;
      if (!sandbox || typeof sandbox !== "object") continue;
      const access4 = sandbox.networkAccess;
      if (typeof access4 === "string" && UNRESTRICTED_VALUES.has(access4.toLowerCase())) {
        evidence.push({
          file: config.filePath,
          snippet: `sandbox.networkAccess = "${access4}"`,
          detail: "Sandboxed tools have unrestricted network access \u2014 exfiltration paths exist even when sandbox is on"
        });
      } else if (access4 === true) {
        evidence.push({
          file: config.filePath,
          snippet: "sandbox.networkAccess = true",
          detail: "Sandboxed tools have unrestricted network access"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Cursor sandbox network access is restricted (or unset)",
      failed: () => "Cursor sandbox network access is unrestricted",
      fixDescription: 'Set sandbox.networkAccess to "user_config_with_defaults" or a stricter value in ~/.cursor/cli-config.json'
    });
  }
});

// src/checks/cursor-cli/cur-009-overbroad-paths.ts
var OVERBROAD_PATH_RULES = [
  /^Write\s*\(\s*\*\s*\)$/i,
  /^Write\s*\(\s*\/\.?\s*\)$/i,
  /^Write\s*\(\s*\*\*\s*\)$/i,
  /^Read\s*\(\s*\/\.?\s*\)$/i,
  /^Read\s*\(\s*\*\s*\)$/i,
  /^WebFetch\s*\(\s*\*\s*\)$/i,
  /^Mcp\s*\(\s*\*\s*\)$/i
];
var cur009 = defineCheck({
  id: "CUR-009",
  name: "Cursor Overbroad Path/Web Allow",
  category: "coding-agent",
  severity: "warning",
  description: "Detect permissions.allow entries granting unbounded Write/Read/WebFetch/Mcp access",
  supportedAgents: ["cursor-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const perms = config.data.permissions;
      if (!perms || typeof perms !== "object") continue;
      const allow = Array.isArray(perms.allow) ? perms.allow.filter((a) => typeof a === "string") : [];
      for (const rule of allow) {
        if (!OVERBROAD_PATH_RULES.some((p) => p.test(rule))) continue;
        evidence.push({
          file: config.filePath,
          snippet: `permissions.allow: "${rule}"`,
          detail: "Wildcard path/web rule grants far more access than typically intended"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Cursor allow rules have no unbounded path or web wildcards",
      failed: (n) => `Found ${n} overbroad path/web allow rule(s) in Cursor config`,
      fixDescription: "Narrow rules to specific paths/domains (e.g. Write(src/**), WebFetch(*.example.com))"
    });
  }
});

// src/checks/cursor-cli/cur-010-attribution.ts
var cur010 = defineCheck({
  id: "CUR-010",
  name: "Cursor Attributes Commits/PRs to Agent",
  category: "coding-agent",
  severity: "info",
  description: "Surface when attribution.attributeCommitsToAgent or attributePRsToAgent is enabled",
  supportedAgents: ["cursor-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const attr2 = config.data.attribution;
      if (!attr2 || typeof attr2 !== "object") continue;
      if (attr2.attributeCommitsToAgent === true) {
        evidence.push({
          file: config.filePath,
          snippet: "attribution.attributeCommitsToAgent = true",
          detail: 'Cursor adds an "agent" co-author/trailer to commits \u2014 visible in git history and audit logs'
        });
      }
      if (attr2.attributePRsToAgent === true) {
        evidence.push({
          file: config.filePath,
          snippet: "attribution.attributePRsToAgent = true",
          detail: "Cursor marks PR descriptions as agent-authored"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Cursor commit/PR attribution is not configured to mark agent authorship",
      failed: (n) => `Cursor attribution flags enabled (${n}) \u2014 agent authorship will be recorded`,
      fixDescription: "Decide whether agent attribution is required by your audit policy; toggle attribution.* in ~/.cursor/cli-config.json"
    });
  }
});

// src/checks/cursor-cli/index.ts
var cursorCliChecks = [
  cur001,
  cur002,
  cur003,
  cur004,
  cur005,
  cur006,
  cur007,
  cur008,
  cur009,
  cur010
];

// src/checks/copilot-cli/ghc-001-dir-perms.ts
import { join as join79 } from "path";
var PROTECTED_FILES2 = [
  "config.json",
  "settings.json",
  "lsp-config.json",
  "command-history-state.json"
];
var PROTECTED_DIRS = [".", "session-state"];
var ghc001 = defineCheck({
  id: "GHC-001",
  name: "Copilot CLI Directory Permissions",
  category: "coding-agent",
  severity: "critical",
  description: "Verify ~/.copilot/, session-state/, and credential files are not group/world readable",
  supportedAgents: ["copilot-cli"],
  supportedPlatforms: ["darwin", "linux"],
  async run(ctx, h) {
    const evidence = [];
    for (const subdir of PROTECTED_DIRS) {
      const path = subdir === "." ? ctx.installation.installDir : join79(ctx.installation.installDir, subdir);
      if (!await ctx.fs.access(path)) continue;
      try {
        const stat4 = await ctx.fs.stat(path);
        const perms = stat4.mode & 511;
        if ((perms & 63) !== 0) {
          evidence.push({
            file: path,
            snippet: `mode 0${perms.toString(8)}`,
            detail: `${subdir === "." ? "~/.copilot/" : `${subdir}/`} is readable or writable by group/other \u2014 auth/session state may leak`
          });
        }
      } catch {
      }
    }
    for (const filename of PROTECTED_FILES2) {
      const filePath = join79(ctx.installation.installDir, filename);
      if (!await ctx.fs.access(filePath)) continue;
      try {
        const stat4 = await ctx.fs.stat(filePath);
        const perms = stat4.mode & 511;
        if ((perms & 63) !== 0) {
          evidence.push({
            file: filePath,
            snippet: `mode 0${perms.toString(8)}`,
            detail: `${filename} is readable or writable by group/other`
          });
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Copilot CLI directory and config files are owner-only",
      failed: (n) => `Found ${n} Copilot CLI path(s) with overly permissive mode`,
      fixDescription: "Run `chmod -R go-rwx ~/.copilot` to restrict access to the owner"
    });
  }
});

// src/checks/copilot-cli/ghc-002-allow-all-permissions.ts
var ghc002 = defineCheck({
  id: "GHC-002",
  name: "Copilot CLI Allow-All Permissions",
  category: "coding-agent",
  severity: "critical",
  description: "Detect allowAllPermissions:true in settings.json \u2014 every tool call auto-approves",
  supportedAgents: ["copilot-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith("settings.json")) continue;
      if (config.data.allowAllPermissions === true) {
        evidence.push({
          file: config.filePath,
          snippet: "allowAllPermissions = true",
          detail: "Every tool call (including shell commands) auto-approves without prompting"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Copilot CLI requires per-tool approval",
      failed: () => "Copilot CLI allowAllPermissions is enabled \u2014 every tool auto-approves",
      fixDescription: "Set allowAllPermissions: false (or remove it) in ~/.copilot/settings.json"
    });
  }
});

// src/checks/copilot-cli/ghc-003-plaintext-token.ts
var GITHUB_TOKEN_PATTERNS = [
  { pattern: /\bgho_[A-Za-z0-9]{20,}/, name: "GitHub OAuth token" },
  { pattern: /\bghp_[A-Za-z0-9]{20,}/, name: "GitHub personal access token" },
  { pattern: /\bghs_[A-Za-z0-9]{20,}/, name: "GitHub server token" },
  { pattern: /\bghu_[A-Za-z0-9]{20,}/, name: "GitHub user-to-server token" },
  { pattern: /\bghr_[A-Za-z0-9]{20,}/, name: "GitHub refresh token" },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}/, name: "GitHub fine-grained PAT" }
];
var ghc003 = defineCheck({
  id: "GHC-003",
  name: "Copilot CLI Plaintext GitHub Token",
  category: "coding-agent",
  severity: "critical",
  description: "Scan ~/.copilot/{config,settings}.json for inline GitHub tokens (gho_, ghp_, etc.)",
  supportedAgents: ["copilot-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (!config.raw) continue;
      for (const { pattern, name } of GITHUB_TOKEN_PATTERNS) {
        const m = pattern.exec(config.raw);
        if (m) {
          evidence.push({
            file: config.filePath,
            snippet: `${m[0].slice(0, 8)}\u2026`,
            detail: `Plaintext ${name} in Copilot config \u2014 rotate immediately and rely on the OS keychain or gh CLI's hosts.yml`
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No plaintext GitHub tokens detected in Copilot CLI config files",
      failed: (n) => `Found ${n} plaintext GitHub token(s) in Copilot CLI config`,
      fixDescription: "Revoke the token at https://github.com/settings/tokens; let Copilot store auth via keychain or gh CLI integration"
    });
  }
});

// src/checks/copilot-cli/ghc-004-mcp-http.ts
import { join as join80 } from "path";
var URL_FIELDS4 = ["url", "httpUrl", "sseUrl"];
var ghc004 = defineCheck({
  id: "GHC-004",
  name: "Copilot CLI MCP Server Over Plaintext HTTP",
  category: "coding-agent",
  severity: "warning",
  description: "Detect MCP servers in workspace .mcp.json that use http:// rather than https://",
  supportedAgents: ["copilot-cli"],
  async run(ctx, h) {
    const evidence = [];
    const sources = [];
    for (const c of ctx.configs) {
      if (c.filePath.endsWith(".mcp.json")) {
        sources.push({ path: c.filePath, data: c.data });
      }
    }
    const cwdMcp = join80(process.cwd(), ".mcp.json");
    const alreadyHandled = sources.some((s) => s.path === cwdMcp);
    if (!alreadyHandled && await ctx.fs.access(cwdMcp)) {
      try {
        const raw = await ctx.fs.readFile(cwdMcp);
        const data = JSON.parse(stripJsonc(raw));
        sources.push({ path: cwdMcp, data });
      } catch {
      }
    }
    for (const { path, data } of sources) {
      const servers = data.mcpServers;
      if (!servers || typeof servers !== "object") continue;
      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== "object") continue;
        const obj = server;
        for (const field of URL_FIELDS4) {
          const value = obj[field];
          if (typeof value !== "string") continue;
          if (!value.startsWith("http://")) continue;
          if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(value)) continue;
          evidence.push({
            file: path,
            snippet: `mcpServers.${name}.${field} = ${value}`,
            detail: "MCP traffic over plaintext HTTP \u2014 bearer tokens in headers traverse unencrypted"
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No Copilot CLI MCP servers using plaintext HTTP",
      failed: (n) => `Found ${n} Copilot CLI MCP server(s) using plaintext HTTP`,
      fixDescription: "Switch the MCP server URL to https:// (or proxy via TLS)"
    });
  }
});

// src/checks/copilot-cli/ghc-005-prerelease-channel.ts
var ghc005 = defineCheck({
  id: "GHC-005",
  name: "Copilot CLI Prerelease Update Channel",
  category: "coding-agent",
  severity: "warning",
  description: 'Surface when updateChannel is set to "prerelease" \u2014 less-vetted code paths',
  supportedAgents: ["copilot-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith("settings.json")) continue;
      const channel = config.data.updateChannel;
      if (typeof channel === "string" && channel.toLowerCase() === "prerelease") {
        evidence.push({
          file: config.filePath,
          snippet: `updateChannel = "${channel}"`,
          detail: "Auto-updates pull prerelease builds \u2014 these may include features not yet vetted for production"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Copilot CLI updateChannel is stable",
      failed: () => 'Copilot CLI updateChannel is "prerelease"',
      fixDescription: 'Set updateChannel: "stable" in ~/.copilot/settings.json unless you intentionally test prereleases'
    });
  }
});

// src/checks/copilot-cli/ghc-006-experimental-mode.ts
var ghc006 = defineCheck({
  id: "GHC-006",
  name: "Copilot CLI Experimental Mode Enabled",
  category: "coding-agent",
  severity: "warning",
  description: "Surface when experimentalMode is enabled in settings.json",
  supportedAgents: ["copilot-cli"],
  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith("settings.json")) continue;
      if (config.data.experimentalMode === true) {
        evidence.push({
          file: config.filePath,
          snippet: "experimentalMode = true",
          detail: "Unstable features may be active \u2014 behaviors and APIs not yet stable"
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: "Copilot CLI experimental mode is off",
      failed: () => "Copilot CLI experimentalMode is enabled",
      fixDescription: "Set experimentalMode: false in ~/.copilot/settings.json for production use"
    });
  }
});

// src/checks/copilot-cli/ghc-007-lsp-command-injection.ts
import { join as join81 } from "path";
var SHELL_METACHARS = /[;&|`$()<>]/;
async function scanLspConfig(filePath, ctx, evidence) {
  if (!await ctx.fs.access(filePath)) return;
  let parsed;
  try {
    const raw = await ctx.fs.readFile(filePath);
    parsed = JSON.parse(stripJsonc(raw));
  } catch {
    return;
  }
  const servers = parsed.lspServers;
  if (!servers || typeof servers !== "object") return;
  for (const [name, server] of Object.entries(servers)) {
    if (!server || typeof server !== "object") continue;
    const command = server.command;
    if (typeof command !== "string") continue;
    if (!SHELL_METACHARS.test(command)) continue;
    evidence.push({
      file: filePath,
      snippet: `lspServers.${name}.command = ${command}`,
      detail: "Shell metacharacters in LSP command \u2014 may be evaluated by a shell, enabling command injection"
    });
  }
}
var ghc007 = defineCheck({
  id: "GHC-007",
  name: "Copilot CLI LSP Command Injection Risk",
  category: "coding-agent",
  severity: "warning",
  description: "Detect LSP server commands containing shell metacharacters in user or project LSP config",
  supportedAgents: ["copilot-cli"],
  async run(ctx, h) {
    const evidence = [];
    await scanLspConfig(join81(ctx.installation.installDir, "lsp-config.json"), ctx, evidence);
    await scanLspConfig(join81(process.cwd(), ".github", "lsp.json"), ctx, evidence);
    return h.fromEvidence(evidence, {
      passed: "Copilot CLI LSP server commands have no shell metacharacters",
      failed: (n) => `Found ${n} Copilot CLI LSP server command(s) with shell metacharacters`,
      fixDescription: "Replace shell-style commands with the binary path + args[] array; never embed pipes/semicolons in command"
    });
  }
});

// src/checks/copilot-cli/ghc-008-instructions-secrets.ts
import { join as join82 } from "path";
var KNOWN_KEY_PREFIXES10 = [
  { pattern: /\bgho_[A-Za-z0-9]{20,}/, name: "GitHub OAuth token" },
  { pattern: /\bghp_[A-Za-z0-9]{20,}/, name: "GitHub PAT" },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}/, name: "GitHub fine-grained PAT" },
  { pattern: /\bsk-or-v1-[A-Za-z0-9]{32,}/, name: "OpenRouter API key" },
  { pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/, name: "Anthropic API key" },
  { pattern: /\bsk-[A-Za-z0-9]{32,}/, name: "OpenAI-style API key" },
  { pattern: /\bAIza[0-9A-Za-z_-]{30,}/, name: "Google API key" },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/, name: "AWS access key ID" }
];
var ENTROPY_THRESHOLD6 = 5.5;
var MIN_BLOCK_LEN6 = 40;
async function scanFile5(file, ctx, evidence) {
  if (!await ctx.fs.access(file)) return;
  let content;
  try {
    content = await ctx.fs.readFile(file);
  } catch {
    return;
  }
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    for (const { pattern, name } of KNOWN_KEY_PREFIXES10) {
      const m = pattern.exec(lines[i]);
      if (m) {
        evidence.push({
          file,
          line: i + 1,
          snippet: `${m[0].slice(0, 12)}\u2026`,
          detail: `Plaintext ${name} in instructions file`
        });
      }
    }
  }
  const blocks = findHighEntropyBlocks(content, ENTROPY_THRESHOLD6, MIN_BLOCK_LEN6);
  for (const b of blocks) {
    if (evidence.some((e) => e.file === file && e.line === b.line)) continue;
    evidence.push({
      file,
      line: b.line,
      snippet: b.snippet,
      detail: `High-entropy string (${b.entropy} bits) \u2014 possible embedded secret`
    });
  }
}
var ghc008 = defineCheck({
  id: "GHC-008",
  name: "Copilot CLI Instruction File Secret Leak",
  category: "coding-agent",
  severity: "info",
  description: "Scan ~/.copilot/instructions/*.instructions.md and .github/copilot-instructions.md for plaintext secrets",
  supportedAgents: ["copilot-cli"],
  async run(ctx, h) {
    const evidence = [];
    await scanFile5(join82(process.cwd(), ".github", "copilot-instructions.md"), ctx, evidence);
    const userInstrDir = join82(ctx.installation.installDir, "instructions");
    if (await ctx.fs.access(userInstrDir)) {
      try {
        const entries = await ctx.fs.readdirEntries(userInstrDir);
        for (const e of entries) {
          if (!e.isFile) continue;
          if (!e.name.endsWith(".instructions.md")) continue;
          await scanFile5(join82(userInstrDir, e.name), ctx, evidence);
        }
      } catch {
      }
    }
    return h.fromEvidence(evidence, {
      passed: "No secrets detected in Copilot instruction files",
      failed: (n) => `Found ${n} potential secret(s) in Copilot instruction files`,
      fixDescription: "Remove the secret and rotate the credential \u2014 instruction files often end up in git"
    });
  }
});

// src/checks/copilot-cli/index.ts
var copilotCliChecks = [
  ghc001,
  ghc002,
  ghc003,
  ghc004,
  ghc005,
  ghc006,
  ghc007,
  ghc008
];

// src/checks/index.ts
function registerAllChecks() {
  checkRegistry.registerAll(configChecks);
  checkRegistry.registerAll(skillChecks);
  checkRegistry.registerAll(iocChecks);
  checkRegistry.registerAll(networkChecks);
  checkRegistry.registerAll(runtimeChecks);
  checkRegistry.registerAll(mcpChecks);
  checkRegistry.registerAll(openclawChecks);
  checkRegistry.registerAll(nanoclawChecks);
  checkRegistry.registerAll(ironclawChecks);
  checkRegistry.registerAll(nanobotChecks);
  checkRegistry.registerAll(zeroclawChecks);
  checkRegistry.registerAll(lyrieChecks);
  checkRegistry.registerAll(hermesChecks);
  checkRegistry.registerAll(policyChecks);
  checkRegistry.registerAll(advisoryChecks);
  checkRegistry.registerAll(claudeCodeChecks);
  checkRegistry.registerAll(claudeDesktopChecks);
  checkRegistry.registerAll(chatgptDesktopChecks);
  checkRegistry.registerAll(codexChecks);
  checkRegistry.registerAll(opencodeChecks);
  checkRegistry.registerAll(geminiCliChecks);
  checkRegistry.registerAll(qwenCodeChecks);
  checkRegistry.registerAll(cursorCliChecks);
  checkRegistry.registerAll(copilotCliChecks);
  applyAgenticTags(checkRegistry.getAll());
}

// src/cli.ts
init_database();
init_updater();
init_database2();
init_updater2();
init_loader();
init_rules();
init_check_registry();
init_debug();

// src/core/zone-graph-validator.ts
function validateZoneGraph(graph, knownCheckIds, adapterName = "<graph>") {
  const errors = [];
  const zoneIds = new Set(graph.zones.map((z) => z.id));
  const componentIds = new Set(graph.components.map((c) => c.id));
  const trustLevels = /* @__PURE__ */ new Map();
  for (const zone of graph.zones) {
    if (!zone.id) {
      errors.push({ adapter: adapterName, rule: "zone-id-nonempty", detail: "zone id must be a non-empty string" });
      continue;
    }
    const existing = trustLevels.get(zone.trustLevel);
    if (existing !== void 0) {
      errors.push({
        adapter: adapterName,
        rule: "zone-trust-level-unique",
        detail: `zones "${existing}" and "${zone.id}" share trustLevel ${zone.trustLevel}`
      });
    } else {
      trustLevels.set(zone.trustLevel, zone.id);
    }
  }
  for (const component of graph.components) {
    if (!component.id) {
      errors.push({ adapter: adapterName, rule: "component-id-nonempty", detail: "component id must be a non-empty string" });
      continue;
    }
    if (!zoneIds.has(component.zone)) {
      errors.push({
        adapter: adapterName,
        rule: "component-zone-exists",
        detail: `component "${component.id}" references unknown zone "${component.zone}"`
      });
    }
    for (const checkId of component.guardCheckIds ?? []) {
      if (!knownCheckIds.has(checkId)) {
        errors.push({
          adapter: adapterName,
          rule: "check-id-registered",
          detail: `component "${component.id}" guardCheckIds references unknown check "${checkId}"`
        });
      }
    }
  }
  const trustByComponent = /* @__PURE__ */ new Map();
  for (const component of graph.components) {
    const zone = graph.zones.find((z) => z.id === component.zone);
    if (zone) trustByComponent.set(component.id, zone.trustLevel);
  }
  for (const edge of graph.edges) {
    if (!edge.from || !edge.to) {
      errors.push({ adapter: adapterName, rule: "edge-endpoints-nonempty", detail: "edge from/to must be non-empty strings" });
      continue;
    }
    if (!componentIds.has(edge.from)) {
      errors.push({
        adapter: adapterName,
        rule: "edge-endpoint-exists",
        detail: `edge.from "${edge.from}" \u2192 "${edge.to}" references unknown component`
      });
    }
    if (!componentIds.has(edge.to)) {
      errors.push({
        adapter: adapterName,
        rule: "edge-endpoint-exists",
        detail: `edge.to "${edge.from}" \u2192 "${edge.to}" references unknown component`
      });
    }
    for (const checkId of edge.triggerCheckIds ?? []) {
      if (!knownCheckIds.has(checkId)) {
        errors.push({
          adapter: adapterName,
          rule: "check-id-registered",
          detail: `edge "${edge.from}" \u2192 "${edge.to}" triggerCheckIds references unknown check "${checkId}"`
        });
      }
    }
    const fromTrust = trustByComponent.get(edge.from);
    const toTrust = trustByComponent.get(edge.to);
    if (fromTrust !== void 0 && toTrust !== void 0 && toTrust - fromTrust >= 2 && (!edge.triggerCheckIds || edge.triggerCheckIds.length === 0)) {
      errors.push({
        adapter: adapterName,
        rule: "inversion-requires-trigger",
        detail: `edge "${edge.from}" \u2192 "${edge.to}" crosses ${toTrust - fromTrust} trust levels but has no triggerCheckIds (always-on inversion)`
      });
    }
  }
  return errors;
}
function validateAllZoneGraphs(adapters, checks, fallback) {
  const knownCheckIds = new Set(checks.getAll().map((c) => c.id));
  const errors = [];
  for (const adapter of adapters.getAdapters()) {
    const graph = adapter.getZoneGraph?.() ?? fallback();
    errors.push(...validateZoneGraph(graph, knownCheckIds, adapter.agent));
  }
  return errors;
}
var ZoneGraphValidationFailedError = class extends Error {
  constructor(errors) {
    const lines = errors.map((e) => `  [${e.adapter}] ${e.rule}: ${e.detail}`);
    super(`ZoneGraph validation failed (${errors.length} error${errors.length === 1 ? "" : "s"}):
${lines.join("\n")}`);
    this.errors = errors;
    this.name = "ZoneGraphValidationFailedError";
  }
};
function assertZoneGraphsValid(adapters, checks, fallback) {
  const errors = validateAllZoneGraphs(adapters, checks, fallback);
  if (errors.length > 0) throw new ZoneGraphValidationFailedError(errors);
}

// src/cli.ts
init_default_zone_graph();
init_types();
init_version();
var SCANNABLE_AGENTS = AGENT_TYPES.filter((t) => t !== "mcp" && t !== "skill-audit").join(", ");
function validateAgentOption(options) {
  if (options.agent && !isScannableAgentType(options.agent)) {
    console.error(chalk15.red(`Invalid --agent "${options.agent}". Use one of: ${SCANNABLE_AGENTS}.`));
    process.exitCode = 2;
    return false;
  }
  return true;
}
var BANNER = `
${chalk15.red("\u2588\u2588\u2557   \u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557")}
${chalk15.red("\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255D\u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557")}
${chalk15.red("\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2551   \u2588\u2588\u2551")}
${chalk15.red("\u255A\u2588\u2588\u2557 \u2588\u2588\u2554\u255D\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u255A\u2550\u2550\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551")}
${chalk15.red(" \u255A\u2588\u2588\u2588\u2588\u2554\u255D \u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u255A\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255D")}
${chalk15.red("  \u255A\u2550\u2550\u2550\u255D  \u255A\u2550\u255D  \u255A\u2550\u255D\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u255D \u255A\u2550\u2550\u2550\u2550\u2550\u255D")}
${chalk15.dim(`  VULNEX Agent Security Observer v${VERSION}`)}
${chalk15.dim("  Agent-agnostic security scanner for AI deployments")}
`;
function printBanner() {
  console.log(BANNER);
}
adapterRegistry.register(openclawAdapter);
adapterRegistry.register(nanoclawAdapter);
adapterRegistry.register(picoclawAdapter);
adapterRegistry.register(ironclawAdapter);
adapterRegistry.register(nanobotAdapter);
adapterRegistry.register(zeroclawAdapter);
adapterRegistry.register(nemoclawAdapter);
adapterRegistry.register(hermesAdapter);
adapterRegistry.register(lyrieAdapter);
adapterRegistry.register(claudeCodeAdapter);
adapterRegistry.register(claudeDesktopAdapter);
adapterRegistry.register(chatgptDesktopAdapter);
adapterRegistry.register(codexAdapter);
adapterRegistry.register(opencodeAdapter);
adapterRegistry.register(geminiAdapter);
adapterRegistry.register(qwenCodeAdapter);
adapterRegistry.register(copilotCliAdapter);
adapterRegistry.register(cursorCliAdapter);
registerAllChecks();
assertZoneGraphsValid(adapterRegistry, checkRegistry, defaultZoneGraph);
var program = new Command();
program.name("vaso").description("VULNEX Agent Security Observer \u2014 security scanner for AI agent deployments").version(VERSION, "-v, --version").option("--debug", "print full stack traces on errors").hook("preAction", async (_thisCommand, actionCommand) => {
  setDebug(Boolean(program.opts().debug));
  const subOpts = actionCommand.opts?.() ?? {};
  const silent = Boolean(subOpts.silent);
  if (!silent) printBanner();
  const userPlugins = await loadUserPlugins();
  if (!silent) {
    for (const p of userPlugins) {
      if (p.status === "error") {
        console.log(chalk15.yellow(`  Warning: user plugin "${p.name}" failed to load: ${p.error}
`));
      }
    }
  }
  const commandName = actionCommand.name();
  const needsRules = commandName === "scan" || commandName === "fix";
  if (needsRules) {
    const skipRules = subOpts.customRules === false;
    if (!skipRules) {
      const extraPaths = subOpts.rules;
      const rulesResult = await loadAndRegisterRules(checkRegistry, { extraPaths });
      if (!silent) {
        for (const err of rulesResult.loadResult.allErrors) {
          const loc = err.rule ? ` (rule ${err.rule})` : "";
          console.log(chalk15.yellow(`  Warning: rule file ${err.file}${loc}: ${err.message}
`));
        }
        for (const skip of rulesResult.skipped) {
          console.log(chalk15.yellow(`  Warning: rule "${skip.id}" skipped: ${skip.reason}
`));
        }
        if (rulesResult.registered.length > 0) {
          console.log(chalk15.dim(`  Loaded ${rulesResult.registered.length} declarative rule(s)
`));
        }
      }
    }
  }
  await initIOCDatabase();
  await initAdvisoryDatabase();
  if (!silent && actionCommand.name() !== "update") {
    if (isFeedStale()) {
      console.log(
        chalk15.yellow("  IOC feed is stale. Run `vaso update` for latest threat data.\n")
      );
    }
    if (isAdvisoryFeedStale()) {
      console.log(
        chalk15.yellow("  Advisory feed is stale. Run `vaso update` for latest advisories.\n")
      );
    }
  }
});
var originalHelp = program.helpInformation.bind(program);
program.helpInformation = function() {
  printBanner();
  return originalHelp();
};
program.command("scan").description("Scan installed AI agents for security issues").option("-a, --agent <type>", `scan a specific agent (${SCANNABLE_AGENTS})`).option("-f, --format <format>", "output format (terminal, json, sarif, markdown, html, csv, junit)", "terminal").option("-o, --output <file>", "write report to file (single combined output)").option("--output-dir <dir>", "multi-host: write one file per host as <dir>/<hostname>.<ext>").option("--save-baseline", "save scan results as baseline").option("--diff", "compare against saved baseline").option("--all-users", "scan all user accounts (requires root/sudo)").option("--silent", "suppress all stdout/stderr chatter (requires -o or --output-dir)").option("--rules <paths...>", "load additional rule files").option("--no-custom-rules", "skip declarative rules").option("--host <targets...>", "remote host(s) to scan via SSH (user@host[:port])").option("--inventory <path>", "YAML file listing hosts to scan").option("--ssh-key <path>", "SSH identity file for remote connections").option("--ssh-timeout <seconds>", "SSH connection timeout in seconds", "60").option("--ssh-retries <n>", "additional SSH attempts after the first failure (default 0)", "0").option("--parallel <n>", "max hosts to scan concurrently (default 5)", "5").option("--sudo", "attempt privilege escalation via sudo on remote hosts").option("--snapshot <path>", "scan from a pre-collected probe snapshot file").option("--save-snapshot <dir>", "after fetching SSH snapshots, write each as <hostname>.json under this directory").option("--no-color", "disable colored output").option("--fail-on <severity>", "exit non-zero on findings of this severity or higher (critical, warning, info, none)", "critical").action(async (options) => {
  if (!validateAgentOption(options)) return;
  const { runScan: runScan2 } = await Promise.resolve().then(() => (init_scan(), scan_exports));
  await runScan2(options);
});
program.command("detect").description("Detect installed AI agents").option("-a, --agent <type>", `detect a specific agent only (${SCANNABLE_AGENTS})`).option("-f, --format <format>", "output format (terminal, json)", "terminal").option("-o, --output <file>", "write report to single file").option("--output-dir <dir>", "multi-host: write one file per host as <dir>/<hostname>.<ext>").option("--all-users", "detect across all user accounts (requires root/sudo)").option("--verbose", "show search paths checked for each adapter").option("--silent", "suppress all stdout/stderr chatter (requires -o or --output-dir)").option("--host <targets...>", "remote host(s) to detect via SSH (user@host[:port])").option("--inventory <path>", "YAML inventory file with host definitions").option("--ssh-key <path>", "SSH identity file for remote connections").option("--ssh-timeout <seconds>", "SSH connection timeout in seconds", "60").option("--ssh-retries <n>", "additional SSH attempts after the first failure (default 0)", "0").option("--parallel <n>", "max hosts to detect concurrently (default 5)", "5").option("--snapshot <path>", "detect from a local probe snapshot JSON file").option("--save-snapshot <dir>", "after fetching SSH snapshots, write each as <hostname>.json under this directory (for debugging)").action(async (options) => {
  if (!validateAgentOption(options)) return;
  const { runDetect: runDetect2 } = await Promise.resolve().then(() => (init_detect(), detect_exports));
  await runDetect2(options);
});
program.command("fix").description("Auto-fix detected security issues").option("-a, --agent <type>", "fix a specific agent").option("--dry-run", "show what would be fixed without making changes").option("-y, --yes", "apply all fixes without confirmation").option("--rollback", "rollback the last fix operation").action(async (options) => {
  if (!validateAgentOption(options)) return;
  const { runFix: runFix2 } = await Promise.resolve().then(() => (init_fix(), fix_exports));
  await runFix2(options);
});
program.command("visualize").description("Emit USecVisLib config files (TOML/JSON/YAML) for scan visualization").option("-i, --input <file>", "use existing scan result JSON instead of running a fresh scan").option("-o, --output <dir>", "output directory for the bundle", "./vaso-visualizations").option("--vis-format <format>", "config file format (toml, json, yaml)", "toml").option("--diagrams <list>", "comma-separated diagram types (attack-tree, privilege-gradient, component)").option("-a, --agent <type>", "scan a specific agent only (when running fresh scan)").option("--all-users", "scan all user accounts (requires root/sudo)").action(async (options) => {
  if (!validateAgentOption(options)) return;
  const { runVisualize: runVisualize2 } = await Promise.resolve().then(() => (init_visualize(), visualize_exports));
  await runVisualize2(options);
});
program.command("update").description("Update IOC database from remote threat feed").option("--url <url>", "custom feed URL").option("--force", "force update even if feed is not stale").action(async (options) => {
  const { runUpdate: runUpdate2 } = await Promise.resolve().then(() => (init_update(), update_exports));
  await runUpdate2(options);
});
var mcpCommand = program.command("mcp").description("MCP server security scanning");
mcpCommand.command("scan").description("Scan MCP server configurations for security issues").option("-f, --format <format>", "output format (terminal, json, sarif, markdown, html, csv, junit)", "terminal").option("-o, --output <file>", "write report to file").option("-p, --path <paths...>", "specific config file paths to scan").option("--resolve-packages", "download npm-packaged (npx) MCP servers \u2014 download-only, never executed \u2014 to analyze their source (requires network)", false).option("--no-color", "disable colored output").action(async (options) => {
  const { runMCPScan: runMCPScan2 } = await Promise.resolve().then(() => (init_mcp(), mcp_exports));
  await runMCPScan2(options);
});
mcpCommand.command("list").description("List discovered MCP server configurations").option("-f, --format <format>", "output format (terminal, json)", "terminal").option("-p, --path <paths...>", "specific config file paths to scan").action(async (options) => {
  const { runMCPList: runMCPList2 } = await Promise.resolve().then(() => (init_mcp(), mcp_exports));
  await runMCPList2(options);
});
var skillCommand = program.command("skill").description("Skill security auditing");
skillCommand.command("audit").description("Audit a local skill directory for security issues before installation").argument("<path>", "path to skill directory").option("-f, --format <format>", "output format (terminal, json, sarif, markdown, html, csv, junit)", "terminal").option("-o, --output <file>", "write report to file").option("--no-color", "disable colored output").action(async (path, options) => {
  const { runSkillAudit: runSkillAudit2 } = await Promise.resolve().then(() => (init_skill_audit(), skill_audit_exports));
  await runSkillAudit2(path, options);
});
var pluginCommand = program.command("plugin").description("Manage agent security plugins");
pluginCommand.command("install").description("Install VASO security plugin for an agent framework").requiredOption("-a, --agent <type>", "agent framework (openclaw, nanoclaw, picoclaw)").option("--force", "overwrite existing plugin").action(async (options) => {
  const { runPluginInstall: runPluginInstall2 } = await Promise.resolve().then(() => (init_plugin(), plugin_exports));
  await runPluginInstall2(options);
});
pluginCommand.command("uninstall").description("Uninstall VASO security plugin for an agent framework").requiredOption("-a, --agent <type>", "agent framework (openclaw, nanoclaw, picoclaw)").action(async (options) => {
  const { runPluginUninstall: runPluginUninstall2 } = await Promise.resolve().then(() => (init_plugin(), plugin_exports));
  await runPluginUninstall2(options);
});
pluginCommand.command("status").description("Show plugin installation status").option("-a, --agent <type>", "check a specific agent only").option("-f, --format <format>", "output format (terminal, json)", "terminal").action(async (options) => {
  const { runPluginStatus: runPluginStatus2 } = await Promise.resolve().then(() => (init_plugin(), plugin_exports));
  await runPluginStatus2(options);
});
var extCommand = program.command("ext").description("Manage user plugins");
extCommand.command("list").description("List loaded user plugins").option("-f, --format <format>", "output format (terminal, json)", "terminal").action(async (options) => {
  const { runExtList: runExtList2 } = await Promise.resolve().then(() => (init_user_plugin(), user_plugin_exports));
  await runExtList2(options);
});
extCommand.command("info").description("Show details for a user plugin").argument("<name>", "plugin name").option("-f, --format <format>", "output format (terminal, json)", "terminal").action(async (name, options) => {
  const { runExtInfo: runExtInfo2 } = await Promise.resolve().then(() => (init_user_plugin(), user_plugin_exports));
  await runExtInfo2(name, options);
});
var rulesCommand = program.command("rules").description("Manage declarative YAML rules");
rulesCommand.command("list").description("List loaded declarative rules").option("-f, --format <format>", "output format (terminal, json)", "terminal").action(async (options) => {
  const { runRulesList: runRulesList2 } = await Promise.resolve().then(() => (init_rules2(), rules_exports));
  await runRulesList2(options);
});
rulesCommand.command("validate").description("Validate a rule file").argument("<file>", "path to YAML rule file").option("-f, --format <format>", "output format (terminal, json)", "terminal").action(async (file, options) => {
  const { runRulesValidate: runRulesValidate2 } = await Promise.resolve().then(() => (init_rules2(), rules_exports));
  await runRulesValidate2(file, options);
});
rulesCommand.command("init").description("Generate a starter rule template").option("--dir <path>", "target directory (default: ~/.vaso/rules/)").action(async (options) => {
  const { runRulesInit: runRulesInit2 } = await Promise.resolve().then(() => (init_rules2(), rules_exports));
  await runRulesInit2(options);
});
var probeCmd = program.command("probe").description("Manage probe snapshots for remote scanning");
probeCmd.command("manifest").description("Generate a probe manifest for remote data collection").action(async () => {
  const { probeManifest: probeManifest2 } = await Promise.resolve().then(() => (init_probe(), probe_exports));
  await probeManifest2(adapterRegistry);
});
probeCmd.command("validate <path>").description("Validate a probe snapshot file").action(async (path) => {
  const { probeValidate: probeValidate2 } = await Promise.resolve().then(() => (init_probe(), probe_exports));
  await probeValidate2(path);
});
program.parse();
//# sourceMappingURL=cli.js.map