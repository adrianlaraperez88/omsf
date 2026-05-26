import fs from "node:fs/promises";
import path from "node:path";
import { createFinding } from "../../contracts/src/index.mjs";

// ─── Constants ───────────────────────────────────────────────────────────────

/** Composer lifecycle hooks scanned for malicious script content. */
const COMPOSER_SCRIPT_HOOKS = Object.freeze([
  "pre-install-cmd",
  "post-install-cmd",
  "pre-update-cmd",
  "post-update-cmd",
  "pre-autoload-dump",
  "post-autoload-dump",
  "post-root-package-install",
  "post-create-project-cmd",
  "pre-archive-cmd",
  "post-archive-cmd",
  "pre-status-cmd",
  "post-status-cmd"
]);

/**
 * A 40-character lowercase hex string is the fingerprint of an immutable Git commit SHA.
 * Version tags (v1.2.3) or branch names are mutable and unsafe.
 */
const COMMIT_SHA_RE = /^[0-9a-f]{40}$/i;

// ─── Plugin factory ───────────────────────────────────────────────────────────

export function createComposerPlugin() {
  return {
    id: "composer",
    scan: scanComposer
  };
}

// ─── Main scanner ─────────────────────────────────────────────────────────────

/**
 * Scans a directory tree for composer.json files and evaluates them against
 * the supplied rule pack. Checks:
 *
 *   1. manifest  — structural analysis of composer.json (autoload.files injection)
 *   2. lockfile  — integrity of composer.lock (missing file, mutable-tag pinning)
 *   3. script    — regex rules applied to Composer lifecycle script values
 *   4. file      — regex rules applied to PHP files listed in autoload.files
 *
 * @param {{ targetPath: string, compiledRulePack: any, options?: any }} params
 * @returns {Promise<Array>}
 */
async function scanComposer({ targetPath, compiledRulePack, options }) {
  const hooks =
    Array.isArray(options?.composerHooks) && options.composerHooks.length > 0
      ? options.composerHooks
      : COMPOSER_SCRIPT_HOOKS;

  const manifestRules = compiledRulePack.rules.filter((r) => r.scope === "manifest");
  const lockfileRules = compiledRulePack.rules.filter((r) => r.scope === "lockfile");
  const scriptRules = compiledRulePack.rules.filter((r) => r.scope === "script");
  const fileRules = compiledRulePack.rules.filter((r) => r.scope === "file");

  const findings = [];
  const composerFiles = await findComposerJsonFiles(targetPath);

  for (const composerPath of composerFiles) {
    const pkg = await readJsonSafe(composerPath);
    if (!pkg || typeof pkg !== "object") continue;

    const packageDir = path.dirname(composerPath);

    // 1. Manifest checks (autoload.files injection)
    await checkManifest({ findings, manifestRules, pkg, composerPath, packageDir, fileRules });

    // 2. Lock file checks (missing lock, mutable-tag pins)
    await checkLockfile({ findings, lockfileRules, composerPath, packageDir });

    // 3. Script hook checks
    checkScripts({ findings, scriptRules, pkg, composerPath, hooks });
  }

  return findings;
}

// ─── Manifest checks ──────────────────────────────────────────────────────────

async function checkManifest({ findings, manifestRules, pkg, composerPath, packageDir, fileRules }) {
  const autoloadFiles = extractAutoloadFiles(pkg, "autoload");
  const autoloadDevFiles = extractAutoloadFiles(pkg, "autoload-dev");

  // Rule: composer.autoload-files-entry
  if (autoloadFiles.length > 0) {
    const rule = manifestRules.find((r) => r.id === "composer.autoload-files-entry") ||
                 manifestRules.find((r) => r.id === "owasp.a03.composer-autoload-files");
    if (rule) {
      findings.push(
        createFinding({
          plugin: "composer",
          ruleId: rule.id,
          title: rule.title,
          message: `autoload.files lists ${autoloadFiles.length} file(s): ${autoloadFiles.slice(0, 5).join(", ")}${autoloadFiles.length > 5 ? " …" : ""}. PHP executes every listed file on every application boot via the Composer autoloader — the exact injection vector used in the Laravel-Lang supply chain attack.`,
          severity: rule.severity,
          confidence: rule.confidence,
          weight: rule.weight,
          path: composerPath,
          hook: "autoload.files",
          snippet: JSON.stringify({ "autoload.files": autoloadFiles }, null, 2),
          tags: rule.tags,
          references: rule.references
        })
      );
    }

    // Also scan the referenced PHP files with file-scope rules
    for (const relFile of autoloadFiles) {
      const absFile = path.resolve(packageDir, relFile);
      if (!(await fileExists(absFile))) continue;
      const content = await fs.readFile(absFile, "utf8");
      applyRulesToText({
        findings,
        pluginId: "composer",
        rules: fileRules,
        text: content,
        filePath: absFile,
        hook: "autoload.files",
        sourceKind: "file"
      });
    }
  }

  // Rule: composer.autoload-dev-files-entry
  if (autoloadDevFiles.length > 0) {
    const rule = manifestRules.find((r) => r.id === "composer.autoload-dev-files-entry");
    if (rule) {
      findings.push(
        createFinding({
          plugin: "composer",
          ruleId: rule.id,
          title: rule.title,
          message: `autoload-dev.files lists ${autoloadDevFiles.length} file(s): ${autoloadDevFiles.slice(0, 5).join(", ")}${autoloadDevFiles.length > 5 ? " …" : ""}. Auto-executed during dev/CI installs.`,
          severity: rule.severity,
          confidence: rule.confidence,
          weight: rule.weight,
          path: composerPath,
          hook: "autoload-dev.files",
          snippet: JSON.stringify({ "autoload-dev.files": autoloadDevFiles }, null, 2),
          tags: rule.tags,
          references: rule.references
        })
      );
    }
  }
}

/**
 * Extracts the files array from composer.json autoload or autoload-dev section.
 * @param {object} pkg - Parsed composer.json object
 * @param {"autoload"|"autoload-dev"} section
 * @returns {string[]}
 */
function extractAutoloadFiles(pkg, section) {
  const block = pkg[section];
  if (!block || typeof block !== "object") return [];
  const files = block.files;
  if (!Array.isArray(files)) return [];
  return files.filter((f) => typeof f === "string");
}

// ─── Lock file checks ─────────────────────────────────────────────────────────

async function checkLockfile({ findings, lockfileRules, composerPath, packageDir }) {
  const lockPath = path.join(packageDir, "composer.lock");
  const lockExists = await fileExists(lockPath);

  // Rule: composer.missing-lockfile / owasp.a03.composer-missing-lockfile
  if (!lockExists) {
    const rule = lockfileRules.find(
      (r) => r.id === "composer.missing-lockfile" || r.id === "owasp.a03.composer-missing-lockfile"
    );
    if (rule) {
      findings.push(
        createFinding({
          plugin: "composer",
          ruleId: rule.id,
          title: rule.title,
          message: `No composer.lock found alongside ${path.basename(composerPath)}. Without a committed lock file, every install re-resolves packages from registries — mutable-tag attacks like Laravel-Lang go undetected.`,
          severity: rule.severity,
          confidence: rule.confidence,
          weight: rule.weight,
          path: composerPath,
          hook: null,
          snippet: `Expected: ${lockPath}`,
          tags: rule.tags,
          references: rule.references
        })
      );
    }
    return; // No lock to inspect further
  }

  // Parse lock and check for mutable-tag pins
  const lock = await readJsonSafe(lockPath);
  if (!lock || typeof lock !== "object") return;

  const tagPinRule = lockfileRules.find(
    (r) => r.id === "composer.lock-tag-only-pin" || r.id === "owasp.a03.composer-lock-tag-pin"
  );
  if (!tagPinRule) return;

  const allPackages = [
    ...(Array.isArray(lock.packages) ? lock.packages : []),
    ...(Array.isArray(lock["packages-dev"]) ? lock["packages-dev"] : [])
  ];

  const tagPinnedPackages = allPackages.filter((pkg) => isTagOnlyPin(pkg));

  if (tagPinnedPackages.length > 0) {
    const names = tagPinnedPackages.map((p) => `${p.name}@${p.version}`);
    findings.push(
      createFinding({
        plugin: "composer",
        ruleId: tagPinRule.id,
        title: tagPinRule.title,
        message: `${tagPinnedPackages.length} package(s) in composer.lock are pinned by a mutable version tag instead of a commit SHA: ${names.slice(0, 5).join(", ")}${names.length > 5 ? " …" : ""}. The Laravel-Lang attacker force-pushed behind existing tags — SHA pinning is the only immutable control.`,
        severity: tagPinRule.severity,
        confidence: tagPinRule.confidence,
        weight: tagPinRule.weight,
        path: lockPath,
        hook: null,
        snippet: JSON.stringify(
          tagPinnedPackages.slice(0, 3).map((p) => ({
            name: p.name,
            version: p.version,
            "dist.reference": p.dist?.reference ?? "(absent)"
          })),
          null,
          2
        ),
        tags: tagPinRule.tags,
        references: tagPinRule.references
      })
    );
  }
}

/**
 * Returns true when a lock-file package entry is pinned only by a mutable tag.
 * A package is considered safely pinned when dist.reference is a 40-char commit SHA.
 * @param {object} pkg - Package entry from composer.lock packages array
 * @returns {boolean}
 */
function isTagOnlyPin(pkg) {
  if (!pkg || typeof pkg !== "object") return false;
  const ref = pkg.dist?.reference;
  // If reference is absent or is not a 40-char hex SHA → mutable
  if (!ref) return true;
  return !COMMIT_SHA_RE.test(String(ref));
}

// ─── Script checks ────────────────────────────────────────────────────────────

function checkScripts({ findings, scriptRules, pkg, composerPath, hooks }) {
  if (!pkg.scripts || typeof pkg.scripts !== "object") return;

  for (const hook of hooks) {
    const raw = pkg.scripts[hook];
    if (!raw) continue;

    // Composer script values can be a string or an array of strings
    const lines = Array.isArray(raw) ? raw : [raw];
    for (const scriptText of lines) {
      const text = String(scriptText).trim();
      if (!text) continue;
      applyRulesToText({
        findings,
        pluginId: "composer",
        rules: scriptRules,
        text,
        filePath: composerPath,
        hook,
        sourceKind: "script"
      });
    }
  }
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

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
        snippet: text.slice(0, 500),
        tags: rule.tags,
        references: rule.references
      })
    );
  }
}

async function findComposerJsonFiles(rootPath) {
  const result = [];
  await walkComposer(rootPath, result);
  return result;
}

async function walkComposer(current, result) {
  let entries;
  try {
    entries = await fs.readdir(current, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.name === "vendor" || entry.name === "node_modules" || entry.name === ".git") continue;
    const full = path.join(current, entry.name);
    if (entry.isDirectory()) {
      await walkComposer(full, result);
      continue;
    }
    if (entry.isFile() && entry.name === "composer.json") {
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

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}
