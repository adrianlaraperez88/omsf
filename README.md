# OWASP Module Security Framework (OMSF)

Modular, multi-ecosystem supply-chain security scanner aligned to OWASP Top 10:2025.  
Zero runtime dependencies. Node.js built-in test runner. SARIF output for GitHub Code Scanning.

---

## What It Catches

OMSF scans **npm** (`package.json`) and **Composer/PHP** (`composer.json`) projects simultaneously,
applying two types of checks:

| Check type | npm | Composer |
|------------|:---:|:--------:|
| Lifecycle script analysis (regex) | ✅ | ✅ |
| Autoloaded file content analysis | ✅ | ✅ |
| `autoload.files` injection detection | — | ✅ |
| `composer.lock` missing or tag-only pin | — | ✅ |
| PHP dropper / eval / remote-fetch patterns | — | ✅ |
| Credential exfiltration target patterns | — | ✅ |
| OWASP module packs (A01–A10) | ✅ | ✅ |
| Policy suppressions with expiry | ✅ | ✅ |
| Baseline-diff / fail-on-new mode | ✅ | ✅ |
| SARIF output for GitHub Code Scanning | ✅ | ✅ |

### Why Composer support matters — the Laravel-Lang attack (May 2026)

On May 22 2026, an attacker with push access to the **Laravel-Lang** GitHub organization
force-rewrote every git tag across four popular Composer packages in a 15-minute window.
They inserted `src/helpers.php` into `autoload.files` in each `composer.json`. Because the
Composer autoloader executes every `autoload.files` entry on every application boot, the
dropper ran immediately — no function call needed — and fetched a ~5,900-line PHP credential
stealer that exfiltrated AWS keys, GCP credentials, GitHub PATs, SSH keys, and `.env` files.

**Why version pinning failed:** git tags are mutable. Force-pushing behind an existing tag
bypasses semver-pinned installs entirely. Only a `composer.lock` file with a 40-character
commit SHA as `dist.reference` provides immutable resolution.

OMSF now detects all stages of this attack class: `autoload.files` injection, missing lock
files, mutable-tag pinning, PHP dropper patterns, and credential exfiltration signatures.

---

## Quick Start

**Requirements:** Node.js 20+. No `npm install` needed — zero runtime dependencies.

```bash
# Scan the current directory (npm + Composer, default rules + policy)
node apps/cli/src/index.mjs

# Scan a specific path
node apps/cli/src/index.mjs --path ./my-project

# Or via npx (published package)
npx @owasp-modules/omsf --path ./my-project
```

Try the bundled examples:

```bash
# Should FAIL — unsafe npm package
node apps/cli/src/index.mjs --path ./examples/unsafe-package

# Should PASS — clean npm package
node apps/cli/src/index.mjs --path ./examples/safe-package

# Should FAIL — replicates the Laravel-Lang attack pattern
node apps/cli/src/index.mjs --path ./tests/fixtures/composer-unsafe

# Should PASS — clean Composer project, SHA-pinned lock file
node apps/cli/src/index.mjs --path ./tests/fixtures/composer-safe
```

---

## CLI Reference

```text
Usage:
  omsf [options]
  npx @owasp-modules/omsf [options]

Options:
  --path <dir>                  Target directory to scan (default: cwd)
  --rules <file[,file]>         Explicit npm rule pack JSON path(s)
  --composer-rules <file>       Explicit Composer rule pack JSON path
                                (default: rules/composer-default.rules.json)
  --modules <id[,id]>           OWASP module id(s) from ./rules/modules
  --list-modules                List bundled OWASP module ids and exit
  --policy <file>               Policy JSON (default: rules/policy.default.json)
  --baseline <file>             Baseline report JSON for differential mode
  --fail-on-new                 Fail only when new findings appear vs baseline
  --format <human|json|sarif>   Output format (default: human)
  --out <file>                  Write output to file instead of stdout
  --hooks <a,b,c>               Override npm lifecycle hooks list
  --fail-threshold <n>          Override policy failThreshold at runtime
  --help, -h                    Show help
  --version, -v                 Show version
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Pass — no findings above threshold |
| `1` | Fail — findings exceeded policy threshold |
| `2` | Error — configuration or execution problem |

---

## OWASP Modules

Run targeted scans using bundled OWASP Top 10:2025 module packs:

```bash
# List all bundled modules
node apps/cli/src/index.mjs --list-modules

# Scan with specific OWASP modules
node apps/cli/src/index.mjs \
  --path ./my-project \
  --modules a03-software-supply-chain-failures,a03-composer-supply-chain
```

Available modules under `rules/modules/`:

| Module ID | OWASP Category |
|-----------|---------------|
| `a01-broken-access-control` | A01:2025 Broken Access Control |
| `a02-security-misconfiguration` | A02:2025 Security Misconfiguration |
| `a03-software-supply-chain-failures` | A03:2025 Software Supply Chain Failures (npm) |
| `a03-composer-supply-chain` | A03:2025 Software Supply Chain Failures (Composer/PHP) |
| `a04-cryptographic-failures` | A04:2025 Cryptographic Failures |
| `a05-injection` | A05:2025 Injection |
| `a06-insecure-design` | A06:2025 Insecure Design |
| `a07-authentication-failures` | A07:2025 Authentication Failures |
| `a08-software-or-data-integrity-failures` | A08:2025 Software and Data Integrity Failures |
| `a09-security-logging-and-alerting-failures` | A09:2025 Security Logging and Alerting Failures |
| `a10-mishandling-of-exceptional-conditions` | A10:2025 Mishandling of Exceptional Conditions |

---

## Output Formats

### Human (default)

```
[INFO] Tool: omsf v1.0.2
[INFO] Target: /path/to/project
[INFO] Findings: 3 | Suppressed: 0 | New: 3 | Score: 24 | Risk: HIGH | Status: FAIL

- [NEW] [CRITICAL] composer.file.php-base64-eval (src/helpers.php)
  hook=autoload.files weight=10 confidence=high
  An autoloaded PHP file contains eval(base64_decode(...)) — canonical PHP dropper signature.
```

### JSON (`--format json`)

Full structured report with findings, suppressed findings, policy, summary, and decision.

### SARIF (`--format sarif`)

SARIF 2.1.0 format — upload directly to **GitHub Code Scanning**:

```yaml
# .github/workflows/omsf.yml
- name: Run OMSF
  run: node apps/cli/src/index.mjs --format sarif --out results.sarif

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Baseline Diff Workflow

Use baseline mode to onboard gradually — fail only on *new* findings:

```bash
# Step 1: Capture current state as baseline
node apps/cli/src/index.mjs --path ./my-project --format json --out ./reports/baseline.json

# Step 2: In CI — fail only when new findings appear beyond baseline
node apps/cli/src/index.mjs \
  --path ./my-project \
  --baseline ./reports/baseline.json \
  --fail-on-new
```

---

## Policy and Suppressions

The default policy (`rules/policy.default.json`) controls scoring thresholds and which rule IDs
immediately block a build. The strict policy (`rules/policy.strict.json`) lowers all thresholds.

### Time-limited suppressions

Suppressions require a `reason` and a mandatory `expiresOn` date — expired entries are ignored
automatically:

```json
{
  "suppressions": [
    {
      "ruleId": "composer.autoload-files-entry",
      "pathRegex": "vendor/my-legacy-package/composer\\.json$",
      "reason": "Known-good helper file, reviewed 2026-05-26, migrating away in Q3",
      "expiresOn": "2026-09-01T00:00:00.000Z"
    },
    {
      "ruleId": "npm.remote-stream-shell",
      "pathRegex": "legacy/package\\.json$",
      "hook": "preinstall",
      "reason": "Legacy package migration window",
      "expiresOn": "2026-12-31T00:00:00.000Z"
    }
  ]
}
```

Suppression match fields (all optional — omit to match all):

| Field | Description |
|-------|-------------|
| `ruleId` | Exact rule ID to suppress |
| `pathRegex` | Regex matched against the finding file path |
| `hook` | Exact lifecycle hook name |

### Blocked rule IDs

Rules in `blockedRuleIds` cause an *immediate* build failure regardless of the score threshold:

```json
{
  "blockedRuleIds": [
    "npm.remote-stream-shell",
    "composer.file.php-base64-eval",
    "composer.file.remote-fetch"
  ]
}
```

---

## Project Structure

```text
supply-chain-framework/
  apps/cli/                        # OMSF CLI entry point
  packages/
    contracts/                     # Finding schema + createFinding()
    engine/                        # Plugin orchestration + baseline diff
    plugin-npm/                    # npm/package.json scanner plugin
    plugin-composer/               # Composer/PHP scanner plugin (NEW)
    policy/                        # Policy model — suppressions, thresholds
    output/                        # Human / JSON / SARIF formatters
    rule-loader/                   # Rule pack loading + validation
  rules/
    npm-default.rules.json         # Default npm rule pack (15 rules)
    composer-default.rules.json    # Default Composer rule pack (12 rules) (NEW)
    policy.default.json            # Default policy
    policy.strict.json             # Strict policy
    modules/                       # OWASP Top 10:2025 module packs (11 modules)
  examples/
    unsafe-package/                # npm unsafe example
    safe-package/                  # npm safe example
  tests/
    fixtures/
      unsafe/                      # npm unsafe fixture
      safe/                        # npm safe fixture
      composer-unsafe/             # Composer attack-pattern fixture (NEW)
      composer-safe/               # Composer clean fixture (NEW)
    *.test.mjs                     # Node built-in test files
  docs/                            # User and developer documentation
```

---

## Improvement Opportunities

### Near-term (v1.1)

- **npm lockfile integrity checks** — detect packages pinned to `git+https://...` without a `#<sha>`
  commit hash in `package-lock.json`, mirroring the Composer mutable-tag check.
- **`package-lock.json` `resolved` URL auditing** — flag packages resolving from non-registry
  sources (GitHub tarballs, raw gist URLs) which are exempt from npm audit signing.
- **Composer `autoload.files` allowlist** — ship a curated list of known-safe `autoload.files`
  patterns (e.g. `Carbon/Mixin`, `Intervention/Image` helpers) to reduce false positives.
- **SBOM generation** — emit a CycloneDX or SPDX SBOM alongside the SARIF report so CI
  pipelines can feed downstream SCA tools.

### Mid-term (v2.0)

- **Python `pip`/`pyproject.toml` plugin** — check `[build-system]` hooks, `setup.py` exec
  patterns, and `requirements.txt` hash pinning (`--hash=sha256:...`).
- **Maven/Gradle plugin** — detect `<exec>` tasks, `<plugin>` lifecycle hooks without version pins,
  and missing checksum verification in `settings.xml`.
- **Cargo (`Cargo.toml`/`Cargo.lock`) plugin** — audit `[workspace.metadata]` scripts and
  `build.rs` files for network access patterns.
- **Signed remote rule registry** — pull module packs from a verified registry URL with
  signature verification rather than bundled files.
- **GitHub Actions workflow scanner** — flag unpinned `uses: action@tag` steps (mutable tags),
  missing `permissions:` blocks, and `env:` secrets logged to stdout.
- **Module profiles** — named bundles of modules (`web-api`, `supply-chain`, `platform`) that
  can be enabled with a single flag.

### Long-term (v3.0)

- **MITRE ATT&CK + CWE metadata** on each finding for compliance mapping.
- **OWASP ASVS control cross-reference** alongside the existing OWASP Top 10 alignment.
- **Organization-level policy packs** with inheritance (base + team-override).
- **Parallel plugin execution** via Node.js worker threads for large monorepo scanning.
- **Distributed monorepo scanning orchestration** — fan-out across packages with result
  aggregation and unified SARIF output.

---

## Documentation

**User docs:**
- [User Guide](./docs/USER_GUIDE.md)
- [Policy Model](./docs/POLICY_MODEL.md)

**Developer docs:**
- [Architecture](./docs/ARCHITECTURE.md)
- [Developer Guide](./docs/DEVELOPER_GUIDE.md)
- [Plugin API](./docs/PLUGIN_API.md)
- [Rule Authoring](./docs/RULE_AUTHORING.md)
- [Security Model](./docs/SECURITY_MODEL.md)

**Governance:**
- [Contributing](./CONTRIBUTING.md)
- [Security Policy](./SECURITY.md)
- [Support](./SUPPORT.md)
- [Roadmap](./ROADMAP.md)
- [Changelog](./CHANGELOG.md)

---

## Running Tests

```bash
# All tests (Node built-in runner)
node --test --test-reporter=spec ./tests/*.test.mjs

# Verbose (same output, explicit)
npm run test:verbose
```

Current test coverage: **27 tests** across engine, policy, output, rule-loader, npm plugin,
and Composer plugin.

---

## Relationship to ScriptAudit

`script-audit` remains supported as a PowerShell-focused scanner path.
OMSF is the cross-platform framework path for modular OWASP-aligned checks and future
ecosystem plugins (Composer, pip, Maven, Cargo).
