import assert from "node:assert/strict";
import test from "node:test";
import { createFinding } from "../packages/contracts/src/index.mjs";
import { runEngine } from "../packages/engine/src/index.mjs";

const compiledRulePack = {
  id: "test-pack",
  version: "1.0.0",
  rules: []
};

const policy = {
  failThreshold: 1,
  perFindingFailThreshold: 1,
  mediumRiskThreshold: 1,
  highRiskThreshold: 2,
  allowlist: [],
  blockedRuleIds: []
};

function createStaticPlugin(finding) {
  return {
    id: "npm",
    async scan() {
      return [finding];
    }
  };
}

function makeFinding(path) {
  return createFinding({
    plugin: "npm",
    ruleId: "owasp.a03.remote-stream-shell",
    title: "Remote stream to shell",
    message: "Remote content piped to shell",
    severity: "critical",
    confidence: "high",
    weight: 8,
    path,
    hook: "preinstall",
    snippet: "curl x | bash"
  });
}

test("fail-on-new mode fails when finding is not in baseline", async () => {
  const report = await runEngine({
    toolName: "omsf",
    toolVersion: "1.0.0",
    targetPath: "/repo",
    plugins: [createStaticPlugin(makeFinding("/repo/package.json"))],
    compiledRulePack,
    policy,
    failOnNew: true,
    baselineFindings: []
  });

  assert.equal(report.decision.mode, "fail-on-new");
  assert.equal(report.summary.newFindingCount, 1);
  assert.equal(report.decision.status, "fail");
});

test("fail-on-new mode passes when finding exists in baseline", async () => {
  const initialReport = await runEngine({
    toolName: "omsf",
    toolVersion: "1.0.0",
    targetPath: "/repo",
    plugins: [createStaticPlugin(makeFinding("/repo/package.json"))],
    compiledRulePack,
    policy,
    failOnNew: false,
    baselineFindings: []
  });

  const report = await runEngine({
    toolName: "omsf",
    toolVersion: "1.0.0",
    targetPath: "/repo",
    plugins: [createStaticPlugin(makeFinding("/repo/package.json"))],
    compiledRulePack,
    policy,
    failOnNew: true,
    baselineFindings: initialReport.findings
  });

  assert.equal(report.decision.mode, "fail-on-new");
  assert.equal(report.summary.newFindingCount, 0);
  assert.equal(report.decision.status, "pass");
});
