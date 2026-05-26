/**
 * @param {any} report
 */
export function formatHuman(report) {
  const lines = [];
  lines.push(`[INFO] Tool: ${report.meta.tool} v${report.meta.version}`);
  lines.push(`[INFO] Target: ${report.meta.targetPath}`);
  if (report.decision?.mode) {
    lines.push(`[INFO] Decision mode: ${report.decision.mode}`);
  }
  lines.push(
    `[INFO] Findings: ${report.summary.findingCount} | Suppressed: ${report.summary.suppressedCount || 0} | New: ${report.summary.newFindingCount || 0} | Score: ${report.summary.totalScore} | Risk: ${report.summary.risk} | Status: ${report.decision.status.toUpperCase()}`
  );
  lines.push("");

  for (const finding of report.findings) {
    const newPrefix = finding.isNew ? "[NEW] " : "";
    lines.push(`- ${newPrefix}[${finding.severity.toUpperCase()}] ${finding.ruleId} (${finding.path})`);
    lines.push(`  hook=${finding.hook || "n/a"} weight=${finding.effectiveWeight} confidence=${finding.confidence}`);
    if (finding.fingerprint) {
      lines.push(`  fingerprint=${finding.fingerprint}`);
    }
    lines.push(`  ${finding.message}`);
    if (finding.snippet) {
      lines.push(`  snippet: ${truncate(finding.snippet, 160)}`);
    }
  }

  if (report.findings.length === 0) {
    lines.push("[OK] No findings.");
  }

  const suppressed = Array.isArray(report.suppressedFindings) ? report.suppressedFindings : [];
  if (suppressed.length > 0) {
    lines.push("");
    lines.push("[INFO] Suppressed findings:");
    for (const finding of suppressed) {
      lines.push(
        `- [SUPPRESSED] ${finding.ruleId} (${finding.path}) reason='${finding.suppression?.reason || "n/a"}' expiresOn='${finding.suppression?.expiresOn || "n/a"}'`
      );
    }
  }
  return `${lines.join("\n")}\n`;
}

/**
 * @param {any} report
 * @param {{pretty?: boolean}} opts
 */
export function formatJson(report, opts = {}) {
  return JSON.stringify(report, null, opts.pretty === false ? 0 : 2);
}

/**
 * Minimal SARIF 2.1.0 emitter.
 * @param {any} report
 */
export function formatSarif(report) {
  const rulesMap = new Map();
  for (const f of report.findings) {
    if (!rulesMap.has(f.ruleId)) {
      rulesMap.set(f.ruleId, {
        id: f.ruleId,
        shortDescription: { text: f.title || f.ruleId },
        fullDescription: { text: f.message || f.ruleId },
        properties: { tags: f.tags || [] }
      });
    }
  }

  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: report.meta.tool,
            version: report.meta.version,
            rules: Array.from(rulesMap.values())
          }
        },
        results: report.findings.map((f) => ({
          ruleId: f.ruleId,
          level: toSarifLevel(f.severity),
          message: { text: f.message },
          partialFingerprints: f.fingerprint
            ? {
                primaryLocationLineHash: f.fingerprint
              }
            : undefined,
          properties: {
            hook: f.hook || null,
            confidence: f.confidence,
            isNew: Boolean(f.isNew),
            tags: f.tags || []
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.path }
              }
            }
          ]
        }))
      }
    ]
  };

  return JSON.stringify(sarif, null, 2);
}

function toSarifLevel(severity) {
  switch (String(severity || "").toLowerCase()) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

function truncate(input, maxLen) {
  if (!input) return "";
  const text = String(input).replace(/\s+/g, " ").trim();
  if (text.length <= maxLen) return text;
  return `${text.slice(0, maxLen - 3)}...`;
}
