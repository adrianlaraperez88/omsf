# Changelog

## 1.0.2 - 2026-05-26

### Added — Composer/PHP Supply Chain Plugin (Laravel-Lang attack hardening)

Directly addresses the May 22, 2026 Laravel-Lang supply chain attack in which an attacker
force-rewrote every git tag across four Composer packages and injected `src/helpers.php` into
`autoload.files`, achieving automatic credential exfiltration on every application boot.

- **New `packages/plugin-composer/`** — Composer/PHP ecosystem scanner plugin with four check
  passes: `manifest` (structural), `lockfile` (integrity), `script` (regex on lifecycle hooks),
  and `file` (regex on PHP files listed in `autoload.files`).
- **New `rules/composer-default.rules.json`** — 12 rules covering the full Laravel-Lang attack
  chain:
  - `composer.autoload-files-entry` — detects `autoload.files` injection (exact attack vector)
  - `composer.autoload-dev-files-entry` — detects `autoload-dev.files` injection
  - `composer.missing-lockfile` — detects absent `composer.lock`
  - `composer.lock-tag-only-pin` — detects packages pinned by mutable version tag not commit SHA
  - `composer.script-remote-exec` — detects `curl|bash` and similar in Composer lifecycle hooks
  - `composer.script-network-download` — detects `curl`/`wget` in lifecycle hooks
  - `composer.script-inline-php-exec` — detects `php -r` in lifecycle hooks
  - `composer.file.php-system-exec` — detects `system()`, `shell_exec()`, backtick in autoloaded PHP
  - `composer.file.php-base64-eval` — detects `eval(base64_decode(...))` dropper pattern
  - `composer.file.remote-fetch` — detects `file_get_contents('https://...')`, `curl_exec` in autoloaded PHP
  - `composer.file.credential-exfil` — detects AWS/GCP/Azure env vars, SSH key paths in autoloaded PHP
  - `composer.file.c2-endpoint` — detects known C2/exfil endpoint patterns in autoloaded PHP
- **New `rules/modules/a03-composer-supply-chain.rules.json`** — OWASP A03:2025 module targeting
  the five highest-impact Composer supply-chain detections.
- **New `tests/fixtures/composer-unsafe/`** — Attack-pattern fixture replicating the Laravel-Lang
  compromise: compromised `composer.json` with `autoload.files` + malicious lifecycle scripts,
  `src/helpers.php` PHP dropper, and `composer.lock` with mutable tag-only pins.
- **New `tests/fixtures/composer-safe/`** — Clean Composer fixture with SHA-pinned `composer.lock`
  and no `autoload.files`; produces zero findings.
- **New `tests/plugin-composer.test.mjs`** — 12 new tests covering all Composer detection categories.
- **Extended `packages/contracts/`** — `SCOPES` now includes `"manifest"` and `"lockfile"` for
  structural checks beyond regex scanning.
- **Extended `packages/rule-loader/`** — scope validation accepts `manifest` and `lockfile`.
- **Extended `apps/cli/`** — Composer plugin is now registered alongside the npm plugin by default;
  `--composer-rules` flag added for custom rule pack override.

---

## 1.0.1 - 2026-03-26

- Aligned OWASP module taxonomy to **OWASP Top 10:2025** category ordering and names.
- Renamed module files and rule-pack IDs to 2025 categories (`A01` through `A10`).
- Updated OWASP references from 2021 category pages to 2025 category pages.
- Replaced deprecated `A10 SSRF` module mapping with `A10 Mishandling of Exceptional Conditions`.
- Updated docs, tests, and CI examples to use 2025 module IDs.

## 1.0.0 - 2026-03-25

- Renamed product to **OWASP Module Security Framework (OMSF)**.
- Added publish-ready CLI identity (`@owasp-modules/omsf`, `omsf` bin).
- Added OWASP Top 10 starter module packs under `rules/modules/`.
- Added policy suppressions with required `reason` + `expiresOn`.
- Added baseline-diff mode with `--baseline` + `--fail-on-new`.
- Added richer output metadata (`fingerprint`, `isNew`, suppressed findings).
- Added governance files:
  - `LICENSE`
  - `CONTRIBUTING.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
  - `SUPPORT.md`
  - `ROADMAP.md`
- Added CI workflows for Node framework and PowerShell ScriptAudit.
- Expanded automated test coverage across policy, engine, output, loader, and plugin behavior.

## 0.1.0 - 2026-03-25

- Initial framework scaffold created.
- Added modular architecture:
  - `contracts`, `engine`, `plugin-npm`, `policy`, `output`, `rule-loader`.
- Added CLI app with human/json/sarif outputs and policy-aware exit codes.
- Added default npm rule pack and default/strict policy files.
- Added examples and automated smoke tests.
- Added user and developer documentation set.
