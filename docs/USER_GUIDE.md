# User Guide

## Who This Is For

- Security engineers
- DevSecOps
- Platform teams running CI checks

## Basic Scan

```bash
omsf --path /repo
```

If status is fail, process exits with code `1`.

## OWASP Module Mode

List bundled modules:

```bash
omsf --list-modules
```

Run with selected OWASP modules:

```bash
omsf --path /repo --modules a02-security-misconfiguration,a03-software-supply-chain-failures
```

## Report Formats

Human:

```bash
omsf --path /repo --format human
```

JSON:

```bash
omsf --path /repo --format json --out ./reports/scan.json
```

SARIF:

```bash
omsf --path /repo --format sarif --out ./reports/scan.sarif.json
```

## Policy Selection

Default policy:

```bash
omsf --path /repo --policy ./rules/policy.default.json
```

Strict policy:

```bash
omsf --path /repo --policy ./rules/policy.strict.json
```

Runtime threshold override:

```bash
omsf --path /repo --fail-threshold 12
```

## Hook Scope Override

To limit scanning to specific lifecycle hooks:

```bash
omsf --path /repo --hooks preinstall,postinstall
```

## Baseline-Diff Mode

Create a baseline report:

```bash
omsf --path /repo --format json --out ./reports/baseline.json
```

Fail only when new findings appear:

```bash
omsf --path /repo --baseline ./reports/baseline.json --fail-on-new
```

## CI Integration Pattern

Minimal pipeline step:

```bash
omsf --path "$WORKSPACE" --format json --out "$WORKSPACE/reports/scan.json"
```

Use process exit code to gate builds:
- `0` pass
- `1` fail
- `2` tool/config error

## Triage Recommendations

1. Prioritize `critical` and `high` findings first.
2. Validate if finding is in first-party code or dependency script.
3. For true positives, remove risky behavior or move to approved reviewed code.
4. For safe exceptions, use policy suppressions with reason and expiry.
