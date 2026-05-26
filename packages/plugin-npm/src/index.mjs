import fs from "node:fs/promises";
import path from "node:path";
import { createFinding } from "../../contracts/src/index.mjs";

const DEFAULT_HOOKS = Object.freeze([
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepublish",
  "preprepare",
  "postprepare",
  "dependencies",
  "preuninstall",
  "postuninstall"
]);

export function createNpmPlugin() {
  return {
    id: "npm",
    scan: scanNpm
  };
}

async function scanNpm({ targetPath, compiledRulePack, options }) {
  const hooks = Array.isArray(options?.hooks) && options.hooks.length > 0 ? options.hooks : DEFAULT_HOOKS;
  const scriptRules = compiledRulePack.rules.filter((r) => r.scope === "script");
  const fileRules = compiledRulePack.rules.filter((r) => r.scope === "file");
  const findings = [];
  const packageFiles = await findPackageJsonFiles(targetPath);

  for (const packagePath of packageFiles) {
    const pkg = await readJsonSafe(packagePath);
    if (!pkg || typeof pkg !== "object" || !pkg.scripts || typeof pkg.scripts !== "object") {
      continue;
    }

    const packageDir = path.dirname(packagePath);
    for (const hook of hooks) {
      const scriptText = String(pkg.scripts[hook] || "").trim();
      if (!scriptText) continue;

      applyRulesToText({
        findings,
        pluginId: "npm",
        rules: scriptRules,
        text: scriptText,
        filePath: packagePath,
        hook,
        sourceKind: "script"
      });

      const jsCandidates = extractNodeFileCandidates(scriptText);
      for (const candidate of jsCandidates) {
        if (isRemotePath(candidate) || isUncPath(candidate)) {
          continue;
        }

        const resolved = path.resolve(packageDir, candidate);
        if (!(await exists(resolved))) {
          continue;
        }
        const content = await fs.readFile(resolved, "utf8");
        applyRulesToText({
          findings,
          pluginId: "npm",
          rules: fileRules,
          text: content,
          filePath: resolved,
          hook,
          sourceKind: "file"
        });
      }
    }
  }

  return findings;
}

function applyRulesToText({ findings, pluginId, rules, text, filePath, hook, sourceKind }) {
  for (const rule of rules) {
    if (rule.scope !== sourceKind) continue;
    if (!rule.compiledPattern.test(text)) continue;
    findings.push(
      createFinding({
        plugin: pluginId,
        ruleId: rule.id,
        title: rule.title || rule.id,
        message: rule.description || `${rule.id} matched`,
        severity: rule.severity,
        confidence: rule.confidence,
        weight: rule.weight,
        path: filePath,
        hook: hook || null,
        snippet: text,
        tags: rule.tags,
        references: rule.references
      })
    );
  }
}

async function findPackageJsonFiles(rootPath) {
  const result = [];
  await walk(rootPath, result);
  return result;
}

async function walk(current, result) {
  const entries = await fs.readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === "node_modules" || entry.name === ".git") continue;
    const full = path.join(current, entry.name);
    if (entry.isDirectory()) {
      await walk(full, result);
      continue;
    }
    if (entry.isFile() && entry.name === "package.json") {
      result.push(full);
    }
  }
}

async function readJsonSafe(filePath) {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function extractNodeFileCandidates(scriptText) {
  const segments = scriptText.split(/(?:&&|\|\||;|\|)/g);
  const regexes = [
    /\bnode(?:\.exe)?\b[^\r\n]*?"([^"]+\.(?:mjs|cjs|js))"/gi,
    /\bnode(?:\.exe)?\b[^\r\n]*?'([^']+\.(?:mjs|cjs|js))'/gi,
    /\bnode(?:\.exe)?\b(?:\s+--\S+)*\s+([^\s"';&|]+\.(?:mjs|cjs|js))/gi
  ];
  const out = new Set();
  for (const segment of segments) {
    for (const re of regexes) {
      let m;
      while ((m = re.exec(segment))) {
        if (m[1]) out.add(m[1]);
      }
    }
  }
  return [...out];
}

function isRemotePath(value) {
  return /^https?:\/\//i.test(value);
}

function isUncPath(value) {
  return /^(\\\\|\/\/)/.test(value);
}

async function exists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}
