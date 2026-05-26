import path from "node:path";
import { evaluatePolicy } from "../../policy/src/index.mjs";

/**
 * @param {{
 *   toolName: string,
 *   toolVersion: string,
 *   targetPath: string,
 *   plugins: Array<{id: string, scan: Function}>,
 *   compiledRulePack: any,
 *   policy: any,
 *   options?: any,
 *   baselineFindings?: Array<any>,
 *   failOnNew?: boolean
 * }} params
 */
export async function runEngine(params) {
  const targetPath = path.resolve(params.targetPath);
  const options = params.options || {};
  const allFindings = [];

  for (const plugin of params.plugins) {
    const findings = await plugin.scan({
      targetPath,
      compiledRulePack: params.compiledRulePack,
      options
    });
    for (const f of findings) {
      allFindings.push(f);
    }
  }

  const policyResult = evaluatePolicy(allFindings, params.policy);
  const baselineSet = createBaselineFingerprintSet(params.baselineFindings || [], targetPath);
  const hasBaseline = baselineSet.size > 0;
  const findings = policyResult.findings.map((finding) => {
    const fingerprint = toFindingFingerprint(finding, targetPath);
    return {
      ...finding,
      fingerprint,
      isNew: hasBaseline ? !baselineSet.has(fingerprint) : true
    };
  });

  const suppressedFindings = (policyResult.suppressedFindings || []).map((finding) => {
    const fingerprint = toFindingFingerprint(finding, targetPath);
    return {
      ...finding,
      fingerprint,
      isNew: hasBaseline ? !baselineSet.has(fingerprint) : true
    };
  });

  const newFindings = findings.filter((x) => x.isNew);
  const newFailingFindings = findings.filter(
    (x) => x.isNew && (x.blocked || x.effectiveWeight >= policyResult.policy.perFindingFailThreshold)
  );
  const decision = { ...policyResult.decision };

  if (params.failOnNew) {
    decision.status = newFindings.length > 0 ? "fail" : "pass";
    decision.mode = "fail-on-new";
    decision.newFailingFindings = newFailingFindings;
  } else if (hasBaseline) {
    decision.mode = "baseline-observe";
    decision.newFailingFindings = newFailingFindings;
  }

  const summary = {
    ...policyResult.summary,
    newFindingCount: newFindings.length,
    baselineFindingCount: baselineSet.size
  };

  return {
    meta: {
      tool: params.toolName,
      version: params.toolVersion,
      targetPath,
      generatedAt: new Date().toISOString(),
      rulePackId: params.compiledRulePack.id,
      rulePackVersion: params.compiledRulePack.version,
      baselineUsed: hasBaseline
    },
    findings,
    suppressedFindings,
    summary,
    decision,
    policy: policyResult.policy
  };
}

function createBaselineFingerprintSet(baselineFindings, targetPath) {
  const set = new Set();
  for (const finding of baselineFindings) {
    set.add(toFindingFingerprint(finding, targetPath));
  }
  return set;
}

function toFindingFingerprint(finding, targetPath) {
  const plugin = String(finding.plugin || "unknown");
  const ruleId = String(finding.ruleId || "unknown-rule");
  const hook = String(finding.hook || "");
  const normalizedPath = normalizePathForFingerprint(finding.path, targetPath);
  return `${plugin}|${ruleId}|${hook}|${normalizedPath}`;
}

function normalizePathForFingerprint(filePath, targetPath) {
  const resolved = path.resolve(String(filePath || ""));
  const rel = path.relative(targetPath, resolved);
  const normalized = rel && !rel.startsWith("..") ? rel : resolved;
  return normalized.replaceAll("\\", "/").toLowerCase();
}
