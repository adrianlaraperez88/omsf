import fs from "node:fs/promises";
import path from "node:path";

/**
 * @param {string} rulePackPath
 */
export async function loadRulePack(rulePackPath) {
  const resolved = path.resolve(rulePackPath);
  const raw = await fs.readFile(resolved, "utf8");
  const json = JSON.parse(raw);
  validateRulePack(json, resolved);
  return compileRulePack(json);
}

/**
 * @param {string[]} rulePackPaths
 */
export async function loadRulePacks(rulePackPaths) {
  if (!Array.isArray(rulePackPaths) || rulePackPaths.length === 0) {
    throw new Error("At least one rule pack path is required.");
  }

  const compiledPacks = [];
  for (const packPath of rulePackPaths) {
    compiledPacks.push(await loadRulePack(packPath));
  }

  return mergeCompiledRulePacks(compiledPacks);
}

/**
 * @param {string} policyPath
 */
export async function loadPolicy(policyPath) {
  const resolved = path.resolve(policyPath);
  const raw = await fs.readFile(resolved, "utf8");
  const json = JSON.parse(raw);
  validatePolicy(json, resolved);
  return json;
}

function validateRulePack(rulePack, sourcePath) {
  if (!rulePack || typeof rulePack !== "object") {
    throw new Error(`Rule pack is invalid: ${sourcePath}`);
  }
  if (!Array.isArray(rulePack.rules) || rulePack.rules.length === 0) {
    throw new Error(`Rule pack must define at least one rule: ${sourcePath}`);
  }
  for (const rule of rulePack.rules) {
    if (!rule.id || !rule.pattern || !rule.scope) {
      throw new Error(`Rule is missing required fields (id/pattern/scope) in ${sourcePath}`);
    }
    if (!["script", "file", "manifest", "lockfile"].includes(rule.scope)) {
      throw new Error(`Rule '${rule.id}' has invalid scope '${rule.scope}' in ${sourcePath}`);
    }
  }
}

function validatePolicy(policy, sourcePath) {
  if (!policy || typeof policy !== "object") {
    throw new Error(`Policy is invalid: ${sourcePath}`);
  }
  if (policy.failThreshold != null && !Number.isFinite(policy.failThreshold)) {
    throw new Error(`Policy failThreshold must be numeric: ${sourcePath}`);
  }
  if (policy.suppressions != null) {
    if (!Array.isArray(policy.suppressions)) {
      throw new Error(`Policy suppressions must be an array: ${sourcePath}`);
    }
    for (let i = 0; i < policy.suppressions.length; i += 1) {
      const item = policy.suppressions[i];
      if (!item || typeof item !== "object") {
        throw new Error(`Policy suppression at index ${i} is invalid in ${sourcePath}`);
      }
      if (!String(item.reason || "").trim()) {
        throw new Error(`Policy suppression at index ${i} requires non-empty reason in ${sourcePath}`);
      }
      const expiresOn = String(item.expiresOn || "").trim();
      if (!expiresOn || !Number.isFinite(Date.parse(expiresOn))) {
        throw new Error(`Policy suppression at index ${i} must include valid expiresOn in ${sourcePath}`);
      }
      if (item.pathRegex) {
        try {
          new RegExp(String(item.pathRegex), "i");
        } catch (err) {
          throw new Error(
            `Policy suppression at index ${i} has invalid pathRegex in ${sourcePath}: ${String(
              err.message || err
            )}`
          );
        }
      }
    }
  }
}

function compileRulePack(rulePack) {
  const compiledRules = rulePack.rules.map((rule) => {
    let compiledPattern;
    try {
      compiledPattern = new RegExp(rule.pattern, rule.flags || "i");
    } catch (err) {
      throw new Error(`Invalid regex for rule '${rule.id}': ${String(err.message || err)}`);
    }
    return {
      ...rule,
      compiledPattern,
      weight: Number.isFinite(rule.weight) ? Number(rule.weight) : 1,
      severity: String(rule.severity || "medium").toLowerCase(),
      confidence: String(rule.confidence || "medium").toLowerCase(),
      tags: Array.isArray(rule.tags) ? rule.tags.map(String) : [],
      references: Array.isArray(rule.references) ? rule.references.map(String) : []
    };
  });

  return {
    id: String(rulePack.id || "unnamed-rule-pack"),
    version: String(rulePack.version || "0.0.0"),
    description: String(rulePack.description || ""),
    rules: compiledRules
  };
}

/**
 * @param {Array<{id: string, version: string, description: string, rules: any[]}>} compiledPacks
 */
function mergeCompiledRulePacks(compiledPacks) {
  const rules = [];
  const seenRuleIds = new Set();

  for (const pack of compiledPacks) {
    for (const rule of pack.rules) {
      if (seenRuleIds.has(rule.id)) {
        throw new Error(`Duplicate rule id found across rule packs: '${rule.id}'.`);
      }
      seenRuleIds.add(rule.id);
      rules.push(rule);
    }
  }

  if (rules.length === 0) {
    throw new Error("Merged rule pack has no rules.");
  }

  const id = `merged:${compiledPacks.map((x) => x.id).join("+")}`;
  const version = compiledPacks.map((x) => `${x.id}@${x.version}`).join(",");
  const description = compiledPacks
    .map((x) => x.description)
    .filter(Boolean)
    .join(" | ");

  return {
    id,
    version,
    description,
    rules
  };
}
