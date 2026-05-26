/**
 * @param {Array<any>} findings
 * @param {any} policy
 */
export function evaluatePolicy(findings, policy) {
  const resolvedPolicy = mergePolicy(policy);
  const suppressedFindings = [];
  const scored = [];

  for (const finding of findings) {
    const matchedSuppression = findMatchingSuppression(finding, resolvedPolicy.suppressions);
    if (matchedSuppression) {
      suppressedFindings.push({
        ...finding,
        suppression: matchedSuppression
      });
      continue;
    }
    if (isAllowlisted(finding, resolvedPolicy)) {
      continue;
    }

    scored.push({
      ...finding,
      blocked: resolvedPolicy.blockedRuleIds.includes(finding.ruleId),
      effectiveWeight: Number.isFinite(finding.weight) ? Number(finding.weight) : 1
    });
  }

  const totalScore = scored.reduce((acc, f) => acc + f.effectiveWeight, 0);
  const highestSeverity = getHighestSeverity(scored.map((x) => x.severity));
  const risk = classifyRisk(totalScore, resolvedPolicy);

  const failingFindings = scored.filter(
    (f) => f.blocked || f.effectiveWeight >= resolvedPolicy.perFindingFailThreshold
  );
  const shouldFail = totalScore >= resolvedPolicy.failThreshold || failingFindings.length > 0;

  return {
    policy: resolvedPolicy,
    findings: scored,
    suppressedFindings,
    summary: {
      findingCount: scored.length,
      suppressedCount: suppressedFindings.length,
      totalScore,
      highestSeverity,
      risk,
      activeSuppressionCount: resolvedPolicy.suppressions.length,
      expiredSuppressionCount: resolvedPolicy.expiredSuppressions.length
    },
    decision: {
      status: shouldFail ? "fail" : "pass",
      failingFindings
    }
  };
}

/**
 * @param {any} rawPolicy
 */
export function mergePolicy(rawPolicy = {}) {
  const { activeSuppressions, expiredSuppressions } = normalizeSuppressions(rawPolicy.suppressions);
  const defaults = {
    failThreshold: 8,
    perFindingFailThreshold: 6,
    mediumRiskThreshold: 5,
    highRiskThreshold: 8,
    allowlist: [],
    blockedRuleIds: [],
    suppressions: [],
    expiredSuppressions: []
  };
  return {
    ...defaults,
    ...rawPolicy,
    allowlist: Array.isArray(rawPolicy.allowlist) ? rawPolicy.allowlist : defaults.allowlist,
    blockedRuleIds: Array.isArray(rawPolicy.blockedRuleIds)
      ? rawPolicy.blockedRuleIds
      : defaults.blockedRuleIds,
    suppressions: activeSuppressions,
    expiredSuppressions
  };
}

function isAllowlisted(finding, policy) {
  for (const item of policy.allowlist) {
    const ruleMatch = !item.ruleId || item.ruleId === finding.ruleId;
    const pathMatch = !item.pathRegex || safeRegexMatch(item.pathRegex, finding.path);
    const hookMatch = !item.hook || item.hook === finding.hook;
    if (ruleMatch && pathMatch && hookMatch) {
      return true;
    }
  }
  return false;
}

function safeRegexMatch(pattern, value) {
  try {
    return new RegExp(pattern, "i").test(String(value || ""));
  } catch {
    return false;
  }
}

function classifyRisk(score, policy) {
  if (score >= policy.highRiskThreshold) return "HIGH";
  if (score >= policy.mediumRiskThreshold) return "MEDIUM";
  return "LOW";
}

function getHighestSeverity(severities) {
  const rank = { low: 1, medium: 2, high: 3, critical: 4 };
  let max = "low";
  for (const s of severities) {
    const normalized = String(s || "low").toLowerCase();
    if ((rank[normalized] || 0) > (rank[max] || 0)) {
      max = normalized;
    }
  }
  return max;
}

function findMatchingSuppression(finding, suppressions) {
  for (const item of suppressions) {
    const ruleMatch = !item.ruleId || item.ruleId === finding.ruleId;
    const pathMatch = !item.pathRegex || safeRegexMatch(item.pathRegex, finding.path);
    const hookMatch = !item.hook || item.hook === finding.hook;
    if (ruleMatch && pathMatch && hookMatch) {
      return item;
    }
  }
  return null;
}

function normalizeSuppressions(suppressions) {
  if (!Array.isArray(suppressions)) {
    return {
      activeSuppressions: [],
      expiredSuppressions: []
    };
  }

  const activeSuppressions = [];
  const expiredSuppressions = [];
  const now = Date.now();

  for (let i = 0; i < suppressions.length; i += 1) {
    const entry = suppressions[i];
    if (!entry || typeof entry !== "object") {
      throw new Error(`Invalid suppression entry at index ${i}.`);
    }

    const reason = String(entry.reason || "").trim();
    if (!reason) {
      throw new Error(`Suppression at index ${i} is missing a non-empty 'reason'.`);
    }

    const expiresOnText = String(entry.expiresOn || "").trim();
    if (!expiresOnText) {
      throw new Error(`Suppression at index ${i} is missing required 'expiresOn'.`);
    }

    const expiresAt = Date.parse(expiresOnText);
    if (!Number.isFinite(expiresAt)) {
      throw new Error(`Suppression at index ${i} has invalid expiresOn value '${expiresOnText}'.`);
    }

    const normalized = {
      ruleId: entry.ruleId ? String(entry.ruleId) : null,
      pathRegex: entry.pathRegex ? String(entry.pathRegex) : null,
      hook: entry.hook ? String(entry.hook) : null,
      reason,
      expiresOn: new Date(expiresAt).toISOString()
    };

    if (expiresAt < now) {
      expiredSuppressions.push(normalized);
      continue;
    }

    activeSuppressions.push(normalized);
  }

  return {
    activeSuppressions,
    expiredSuppressions
  };
}
