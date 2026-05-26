import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { loadPolicy, loadRulePack, loadRulePacks } from "../packages/rule-loader/src/index.mjs";

const frameworkRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("loadRulePacks merges multiple module rule packs", async () => {
  const modules = [
    path.join(frameworkRoot, "rules", "modules", "a05-injection.rules.json"),
    path.join(frameworkRoot, "rules", "modules", "a02-security-misconfiguration.rules.json")
  ];

  const merged = await loadRulePacks(modules);
  assert.equal(merged.rules.length, 2);
  assert.ok(merged.id.startsWith("merged:"));
});

test("loadRulePacks rejects duplicate rule ids across packs", async () => {
  const samePack = path.join(frameworkRoot, "rules", "modules", "a05-injection.rules.json");
  await assert.rejects(() => loadRulePacks([samePack, samePack]), /duplicate rule id/i);
});

test("loadPolicy validates suppression reason and expiry", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "omsf-policy-test-"));
  const invalidPolicyPath = path.join(tempDir, "policy.invalid.json");
  await fs.writeFile(
    invalidPolicyPath,
    JSON.stringify(
      {
        failThreshold: 5,
        suppressions: [{ ruleId: "x", expiresOn: "2099-01-01T00:00:00.000Z" }]
      },
      null,
      2
    ),
    "utf8"
  );

  await assert.rejects(() => loadPolicy(invalidPolicyPath), /reason/i);
});

test("loadRulePack compiles the default npm pack", async () => {
  const defaultPackPath = path.join(frameworkRoot, "rules", "npm-default.rules.json");
  const pack = await loadRulePack(defaultPackPath);
  assert.ok(pack.rules.length > 0);
  assert.equal(typeof pack.rules[0].compiledPattern.test, "function");
});
