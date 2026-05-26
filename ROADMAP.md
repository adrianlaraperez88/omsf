# Roadmap

## Released — v1.0.2 (May 2026)

- ✅ **Composer/PHP plugin** — `autoload.files` injection, `composer.lock` integrity,
  mutable-tag pin detection, PHP dropper patterns, credential exfiltration signatures.
- ✅ **OWASP A03 Composer module** — targeted module pack for the Laravel-Lang attack class.
- ✅ **Dual-ecosystem CLI** — npm + Composer scanned in a single pass by default.
- ✅ **Extended rule scopes** — `manifest` and `lockfile` scopes for structural checks beyond regex.

---

## Near Term — v1.1

1. **npm lockfile integrity checks** — detect `package-lock.json` packages pinned to mutable
   `git+https://` URLs without a `#<sha>` anchor; mirrors the Composer tag-pin check.
2. **`package-lock.json` resolved-URL auditing** — flag packages resolving from non-registry
   sources (GitHub tarballs, raw gist URLs) that bypass npm audit signing.
3. **Composer `autoload.files` known-safe allowlist** — ship a curated list of known-safe
   patterns to reduce false positives on popular legitimate helpers.
4. **SBOM generation** — emit a CycloneDX or SPDX SBOM alongside the SARIF report so CI
   pipelines can feed downstream SCA tools.
5. **Publish/release automation** — signed artifacts and automated npm publish pipeline.

## Mid Term — v2.0

1. **Python `pip`/`pyproject.toml` plugin** — check `[build-system]` hooks, `setup.py` exec
   patterns, and `requirements.txt` hash pinning (`--hash=sha256:...`).
2. **Maven/Gradle plugin** — detect `<exec>` lifecycle hooks, plugins without version pins,
   and missing checksum verification.
3. **Cargo (`Cargo.toml`/`Cargo.lock`) plugin** — audit `build.rs` for network access
   and workspace metadata scripts.
4. **GitHub Actions workflow scanner** — flag unpinned `uses: action@tag` steps (mutable tags),
   missing `permissions:` blocks, secrets logged to stdout.
5. **Signed remote rule registry** — pull module packs from a verified registry URL with
   signature verification; no bundled files required.
6. **Module profiles** — named bundles (`web-api`, `supply-chain`, `platform`) enabling a
   curated set of modules with a single flag.
7. **Policy simulation mode** — preview which findings a policy change would suppress/expose
   before committing it.

## Long Term — v3.0

1. **MITRE ATT&CK + CWE metadata** on each finding for compliance mapping.
2. **OWASP ASVS control cross-reference** alongside the existing OWASP Top 10 alignment.
3. **Organization-level policy packs** with inheritance (base policy + team overrides).
4. **Parallel plugin execution** via Node.js worker threads for large monorepo scanning.
5. **Distributed monorepo scanning orchestration** — fan-out across packages with result
   aggregation and unified SARIF output.
