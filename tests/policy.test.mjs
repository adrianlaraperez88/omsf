import assert from "node:assert/strict";
import test from "node:test";
import { evaluatePolicy } from "../packages/policy/src/index.mjs";

function makeFinding(overrides = {}) {
  return {
    id: "f-1",
    tool: "omsf",
    plugin: "npm",
    ruleId: "npm.remote-stream-shell",
    title: "Remote stream to shell",
    message: "dangerous script pattern",
    severity: "high",
    confidence: "high",
    weight: 8,
    path: "/repo/package.json",
    hook: "preinstall",
    snippet: "curl example | bash",
    tags: [],
    references: [],
    ...overrides
  };
}

test("active suppression suppresses finding and records metadata", () => {
  const finding = makeFinding();
  const result = evaluatePolicy([finding], {
    failThreshold: 1,
    suppressions: [
      {
        ruleId: finding.ruleId,
        reason: "Approved temporary exception during migration",
        expiresOn: "2099-01-01T00:00:00.000Z"
      }
    ]
  });

  assert.equal(result.findings.length, 0);
  assert.equal(result.suppressedFindings.length, 1);
  assert.equal(result.summary.suppressedCount, 1);
  assert.equal(result.decision.status, "pass");
});

test("expired suppression does not suppress findings", () => {
  const finding = makeFinding();
  const result = evaluatePolicy([finding], {
    failThreshold: 1,
    suppressions: [
      {
        ruleId: finding.ruleId,
        reason: "Expired exception",
        expiresOn: "2000-01-01T00:00:00.000Z"
      }
    ]
  });

  assert.equal(result.findings.length, 1);
  assert.equal(result.suppressedFindings.length, 0);
  assert.equal(result.summary.expiredSuppressionCount, 1);
  assert.equal(result.decision.status, "fail");
});

test("suppression requires non-empty reason and valid expiry", () => {
  const finding = makeFinding();
  assert.throws(
    () =>
      evaluatePolicy([finding], {
        suppressions: [{ ruleId: finding.ruleId, expiresOn: "2099-01-01T00:00:00.000Z" }]
      }),
    /reason/i
  );

  assert.throws(
    () =>
      evaluatePolicy([finding], {
        suppressions: [{ ruleId: finding.ruleId, reason: "temp", expiresOn: "not-a-date" }]
      }),
    /expiresOn/i
  );
});
