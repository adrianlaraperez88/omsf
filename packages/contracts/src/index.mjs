export const SEVERITIES = Object.freeze(["low", "medium", "high", "critical"]);
export const CONFIDENCE = Object.freeze(["low", "medium", "high"]);
export const SCOPES = Object.freeze(["script", "file", "manifest", "lockfile"]);

/**
 * @typedef {Object} Finding
 * @property {string} id
 * @property {string} tool
 * @property {string} plugin
 * @property {string} ruleId
 * @property {string} title
 * @property {string} message
 * @property {"low"|"medium"|"high"|"critical"} severity
 * @property {"low"|"medium"|"high"} confidence
 * @property {number} weight
 * @property {string} path
 * @property {string|null} hook
 * @property {string} snippet
 * @property {boolean=} blocked
 * @property {number=} effectiveWeight
 * @property {string=} fingerprint
 * @property {boolean=} isNew
 * @property {{ruleId?: string|null, pathRegex?: string|null, hook?: string|null, reason: string, expiresOn: string}=} suppression
 * @property {string[]} tags
 * @property {string[]} references
 */

/**
 * @param {Partial<Finding>} finding
 * @returns {Finding}
 */
export function createFinding(finding) {
  const normalized = {
    id: String(finding.id || cryptoRandomId()),
    tool: String(finding.tool || "supply-chain-framework"),
    plugin: String(finding.plugin || "unknown"),
    ruleId: String(finding.ruleId || "unknown-rule"),
    title: String(finding.title || "Untitled finding"),
    message: String(finding.message || "No message"),
    severity: normalizeSeverity(finding.severity),
    confidence: normalizeConfidence(finding.confidence),
    weight: Number.isFinite(finding.weight) ? Number(finding.weight) : 1,
    path: String(finding.path || ""),
    hook: finding.hook == null ? null : String(finding.hook),
    snippet: String(finding.snippet || ""),
    tags: Array.isArray(finding.tags) ? finding.tags.map(String) : [],
    references: Array.isArray(finding.references) ? finding.references.map(String) : []
  };

  if (!normalized.path) {
    throw new Error("Finding requires a non-empty 'path'.");
  }
  return normalized;
}

/**
 * @param {unknown} value
 * @returns {"low"|"medium"|"high"|"critical"}
 */
export function normalizeSeverity(value) {
  const lowered = String(value || "").toLowerCase();
  if (SEVERITIES.includes(lowered)) return lowered;
  return "medium";
}

/**
 * @param {unknown} value
 * @returns {"low"|"medium"|"high"}
 */
export function normalizeConfidence(value) {
  const lowered = String(value || "").toLowerCase();
  if (CONFIDENCE.includes(lowered)) return lowered;
  return "medium";
}

function cryptoRandomId() {
  const rand = Math.random().toString(36).slice(2, 10);
  const ts = Date.now().toString(36);
  return `fnd-${ts}-${rand}`;
}
