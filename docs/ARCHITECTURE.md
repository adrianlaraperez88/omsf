# Architecture

## Overview

The framework follows a layered, ecosystem-agnostic model:

1. `rule-loader` — loads and compiles rule packs and OWASP module packs into memory.
2. `engine` — orchestrates all registered plugins, aggregates findings, evaluates policy,
   and computes baseline diffs.
3. **Plugins** — each plugin owns one ecosystem and emits normalized `Finding` objects:
   - `plugin-npm` — npm/`package.json` lifecycle scripts and referenced JS files.
   - `plugin-composer` — Composer/PHP `composer.json` autoload injection, lock file integrity,
     lifecycle scripts, and autoloaded PHP file content.
4. `policy` — evaluates findings with allowlist/suppression/threshold logic; produces the
   pass/fail decision independently of detection.
5. `output` — formats the final report for humans, CI JSON pipelines, or GitHub Code Scanning
   (SARIF 2.1.0).
6. `apps/cli` — wires all components together for command-line execution.

## Data Flow

```text
CLI args
  → resolve rule pack paths (npm + Composer merged)
  → load policy
  → run engine
      → plugin-npm.scan()    → npm findings
      → plugin-composer.scan() → Composer findings
      → merge all findings
      → evaluate policy (score, suppress, block)
      → optional baseline diff (isNew flags)
  → format output (human / json / sarif)
  → set exit code (0=pass, 1=fail, 2=error)
```

## Rule Scopes

Rule packs may declare rules in four scopes. Plugins consume only the scopes relevant to them:

| Scope | Description | Used by |
|-------|-------------|---------|
| `script` | Regex applied to lifecycle script text | npm, Composer |
| `file` | Regex applied to referenced file content | npm (JS), Composer (PHP) |
| `manifest` | Structural check against parsed `composer.json` | Composer |
| `lockfile` | Structural check against parsed `composer.lock` | Composer |

The `manifest` and `lockfile` scopes are matched by rule ID inside the plugin (not by
regex on raw text) so that the `pattern` field in the rule JSON serves as documentation.

## Component Contracts

- **Plugins** return `Finding[]` using `createFinding()` from `packages/contracts`.
- **Policy evaluator** consumes findings and returns scored findings, suppressed findings,
  summary, and a `pass`/`fail` decision.
- **Output formatters** consume only the final report object — no plugin or policy knowledge.

## Why This Split

- Detection and policy are fully independent — a new plugin never touches thresholds.
- New ecosystems (pip, Maven, Cargo) can be added without changing policy or output layers.
- Output can evolve for new CI platforms without touching any scanner.
- Unit and integration tests target each layer in isolation.

## Future Extension Points

- Remote signed rule registry with signature verification.
- Parallel plugin execution with Node.js worker threads.
- Baseline store and differential policy workflows.
- Rule metadata enrichment (MITRE ATT&CK, CWE, OWASP ASVS cross-references).
