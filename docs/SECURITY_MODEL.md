# Security Model

## Threat Focus

OMSF detects supply-chain abuse across npm and Composer/PHP ecosystems:

- **Autoload injection** — files auto-executed via `autoload.files` without explicit call sites
  (the exact vector in the May 2026 Laravel-Lang attack)
- **Mutable-tag pinning** — packages locked to git tags rather than commit SHAs, allowing
  force-push attacks to bypass version pinning silently
- **Remote payload download/execution** — lifecycle scripts that fetch and run remote content
- **PHP dropper patterns** — `eval(base64_decode(...))`, `file_get_contents('https://...')`,
  shell execution in auto-loaded PHP files
- **Credential and metadata exfiltration** — access to AWS/GCP/Azure keys, SSH keys, `.env`
  files, and cloud instance metadata endpoints
- **Obfuscated/inlined execution** — base64-encoded payloads, inline `node -e`, `php -r`
- **Persistence through sensitive file writes** — writes to `.npmrc`, `authorized_keys`,
  shell startup scripts

## Trust Boundaries

| Input | Trust level |
|-------|------------|
| Rule packs and policy files | **Trusted** — treat like production config; verify provenance |
| Scanned repository contents | **Untrusted** — OMSF reads but never executes scanned files |
| Plugin code | **Trusted** — review plugin code like production code |
| Baseline report files | **Trusted** — a tampered baseline can hide new findings |

## Defensive Design

- **Read-only scanning** — no scanned script or file is executed; only read and pattern-matched.
- **No external network access** — the scanner makes zero outbound connections.
- **Zero runtime dependencies** — no `npm install` required; no third-party supply-chain risk
  introduced by the tool itself.
- **Scope separation** — `script`, `file`, `manifest`, `lockfile` scopes ensure rules run
  only against the surfaces they are designed for.
- **Policy decoupled from detection** — rules and policy are separate files; each team can
  tune thresholds without touching detection logic.
- **Mandatory suppression expiry** — every suppression requires a non-empty `reason` and a
  future `expiresOn` date; expired suppressions are silently ignored.

## Known Limitations

- **Regex-based detection** can miss heavily obfuscated or transformed payloads.
- **No rule signature verification** — rule packs are trusted inputs in this version; a signed
  registry is on the roadmap.
- **No network IOC feed** — the C2/exfil patterns are static regexes, not live threat intel feeds.
- **No dynamic analysis** — post-execution behavior (e.g. runtime eval of a dynamically
  constructed string) is not detected.

## Recommended Hardening for Production

1. Pin OMSF itself to a commit SHA in CI (`uses: ...@<sha>` or `npx @owasp-modules/omsf@<exact-version>`).
2. Verify OMSF's npm provenance attestation before use in sensitive pipelines.
3. Sign and verify custom rule packs if distributing them across teams.
4. Restrict suppression changes to a dedicated policy-owner review step.
5. Use `--baseline` + `--fail-on-new` for gradual rollout to avoid alert fatigue.
6. Run OMSF on pull request diff in addition to the full tree scan on merge.
7. Rotate all CI secrets immediately if a scan detects `composer.file.remote-fetch` or
   `composer.file.credential-exfil` in a dependency — treat the environment as compromised.
