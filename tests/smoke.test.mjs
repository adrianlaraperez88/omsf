import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";
import { loadPolicy, loadRulePack } from "../packages/rule-loader/src/index.mjs";
import { runEngine } from "../packages/engine/src/index.mjs";
import { createNpmPlugin } from "../packages/plugin-npm/src/index.mjs";

const root = path.dirname(fileURLToPath(import.meta.url));
const frameworkRoot = path.resolve(root, "..");
const rulePackPath = path.join(frameworkRoot, "rules", "npm-default.rules.json");
const policyPath = path.join(frameworkRoot, "rules", "policy.default.json");

test("unsafe fixture should fail policy", async () => {
  const compiledRulePack = await loadRulePack(rulePackPath);
  const policy = await loadPolicy(policyPath);
  const targetPath = path.join(frameworkRoot, "tests", "fixtures", "unsafe");
  const report = await runEngine({
    toolName: "test",
    toolVersion: "0.0.0",
    targetPath,
    plugins: [createNpmPlugin()],
    compiledRulePack,
    policy
  });

  assert.equal(report.decision.status, "fail");
  assert.ok(report.findings.length > 0);
});

test("safe fixture should pass policy", async () => {
  const compiledRulePack = await loadRulePack(rulePackPath);
  const policy = await loadPolicy(policyPath);
  const targetPath = path.join(frameworkRoot, "tests", "fixtures", "safe");
  const report = await runEngine({
    toolName: "test",
    toolVersion: "0.0.0",
    targetPath,
    plugins: [createNpmPlugin()],
    compiledRulePack,
    policy
  });

  assert.equal(report.decision.status, "pass");
});
