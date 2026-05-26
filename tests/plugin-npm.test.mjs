import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { loadRulePack } from "../packages/rule-loader/src/index.mjs";
import { createNpmPlugin } from "../packages/plugin-npm/src/index.mjs";

const testRoot = path.dirname(fileURLToPath(import.meta.url));
const frameworkRoot = path.resolve(testRoot, "..");
const defaultRulePackPath = path.join(frameworkRoot, "rules", "npm-default.rules.json");

test("npm plugin detects file-scope behavior in unsafe fixture", async () => {
  const compiledRulePack = await loadRulePack(defaultRulePackPath);
  const plugin = createNpmPlugin();
  const findings = await plugin.scan({
    targetPath: path.join(frameworkRoot, "tests", "fixtures", "unsafe"),
    compiledRulePack,
    options: {}
  });

  assert.ok(findings.length > 0);
  assert.ok(findings.some((f) => f.ruleId === "npm.file.child-process-network"));
});

test("npm plugin respects hooks override", async () => {
  const compiledRulePack = await loadRulePack(defaultRulePackPath);
  const plugin = createNpmPlugin();
  const findings = await plugin.scan({
    targetPath: path.join(frameworkRoot, "tests", "fixtures", "unsafe"),
    compiledRulePack,
    options: {
      hooks: ["postinstall"]
    }
  });

  assert.equal(findings.length, 0);
});
