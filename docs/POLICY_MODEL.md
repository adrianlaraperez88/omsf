# Policy Model

## Purpose

Rules detect behavior. Policy decides whether findings block a build.

## Policy File Fields

- `failThreshold`:
  - total score threshold that fails run.
- `perFindingFailThreshold`:
  - any single finding at/above this score fails run.
- `mediumRiskThreshold`, `highRiskThreshold`:
  - classify aggregate risk.
- `blockedRuleIds`:
  - rule IDs that always fail when matched.
- `allowlist`:
  - exceptions list.
- `suppressions`:
  - temporary risk waivers with reason + expiry.

Allowlist entry fields:
- `ruleId` (optional exact rule ID)
- `pathRegex` (optional path regex)
- `hook` (optional lifecycle hook)

Entry matches when all provided fields match the finding.

Suppression entry fields:
- `ruleId` (optional exact rule ID)
- `pathRegex` (optional path regex)
- `hook` (optional lifecycle hook)
- `reason` (required non-empty string)
- `expiresOn` (required ISO timestamp)

Expired suppressions are ignored.

## Decision Logic

Run fails when:
- aggregate score >= `failThreshold`, or
- finding score >= `perFindingFailThreshold`, or
- finding rule ID in `blockedRuleIds`.

If CLI `--fail-on-new` is used with a baseline, run fails when new findings are present.

## Policy Tuning Strategy

1. Start with `policy.default.json`.
2. Track false positives for 1-2 sprints.
3. Add narrow suppressions (path + rule + hook + reason + expiry).
4. Move to `policy.strict.json` once stable.

## Governance

- Require owner + reason for suppression changes.
- Keep suppressions time-bound and review them regularly.
- Review blocked rule IDs quarterly.
