# Developer Guide

## Prerequisites

- Node.js 20+

## Run Tests

```bash
npm test
```

## Local Development Flow

1. Update/add base rules under `rules/` or OWASP modules under `rules/modules/`.
2. Update plugin logic only when rule-based matching is insufficient.
3. Add fixture(s) in `tests/fixtures/`.
4. Add test coverage in `tests/*.test.mjs`.
5. Run full tests before committing.

## Coding Conventions

- Keep modules focused and side-effect free.
- Avoid plugin-specific behavior in `engine`.
- Keep output formatters read-only (no policy logic).
- Prefer JSON rule changes before code changes when possible.

## Adding a New Plugin

1. Create `packages/plugin-<ecosystem>/src/index.mjs`.
2. Implement `createXPlugin()` returning:
   - `id`
   - `scan({ targetPath, compiledRulePack, options })`
3. Return normalized `Finding` objects only.
4. Wire plugin into CLI composition.
5. Add integration fixture and test.

See [Plugin API](./PLUGIN_API.md).

## Adding New Rules

1. Edit `rules/*.rules.json`.
2. Validate regex correctness.
3. Add fixture and expected test.
4. Keep rule IDs stable once published.

See [Rule Authoring](./RULE_AUTHORING.md).

## Adding or Updating OWASP Modules

1. Create or edit `rules/modules/<module-id>.rules.json`.
2. Keep module IDs aligned to OWASP naming (`a01-...`, `a02-...`).
3. Keep rule IDs globally unique across all packs.
4. Add tests proving module behavior and non-regression.
5. Verify module discoverability via `omsf --list-modules`.

## Differential Rollout

- Use `--baseline` + `--fail-on-new` for gradual adoption.
- Keep suppressions in policy files with explicit reason + expiry.
- Remove expired suppressions as part of regular security debt reviews.

## Breaking Change Policy

- Increment minor version when adding backward-compatible features.
- Increment major version for schema/contract-breaking changes.
- Record all changes in `CHANGELOG.md`.
