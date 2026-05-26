# Contributing

Thank you for contributing to OMSF!

## What We Accept

- New detection rules and OWASP module packs
- New ecosystem plugins (pip, Maven, Cargo, GitHub Actions…)
- Policy model improvements (new fields, smarter defaults)
- Output formatter enhancements and CI platform integrations
- Test coverage, fixtures, and documentation improvements
- Bug fixes and false-positive reductions

## Development Setup

Requirements: **Node.js 20+** — no other dependencies needed.

```bash
# Clone and run tests immediately — no npm install required
git clone https://github.com/your-org/supply-chain-framework
cd supply-chain-framework
npm run test:verbose
```

## Contribution Workflow

1. **Fork** the repository and create a feature branch from `main`.
2. **Make your change** following the coding conventions below.
3. **Run tests** and confirm all pass: `npm run test:verbose`
4. **Open a Pull Request** — the PR template will guide you through the checklist.

## Pull Request Checklist

- [ ] Tests added or updated for every behaviour change
- [ ] Fixtures provided for new rules — both a **positive** (detects) and **negative** (clean) case
- [ ] All tests pass: `npm run test:verbose`
- [ ] Rule IDs are **stable and globally unique** across all packs
- [ ] `CHANGELOG.md` has a user-facing entry under the relevant version heading
- [ ] Docs updated when adding CLI options, rule fields, scopes, or policy fields
- [ ] No generated files, `node_modules`, or secrets committed

## Rule Authoring Requirements

1. Prefer narrow, high-signal patterns — minimize false positives.
2. Include `severity`, `confidence`, `weight`, and at least one `references` URL.
3. Test both a fixture that triggers the rule and one that does not.
4. Never change a rule ID once it has been published — IDs are used in fingerprints
   and baseline files; changing one silently invalidates downstream baselines.

See [Rule Authoring](./docs/RULE_AUTHORING.md) for the full field reference and examples.

## Adding a Plugin

1. Create `packages/plugin-<ecosystem>/src/index.mjs`.
2. Implement `createXPlugin()` returning `{ id, scan }`.
3. Wire the plugin into `apps/cli/src/index.mjs`.
4. Add a default rule pack at `rules/<ecosystem>-default.rules.json`.
5. Add safe and unsafe test fixtures with full test coverage.

See [Plugin API](./docs/PLUGIN_API.md).

## Security-Sensitive Changes

Changes that modify **policy semantics**, **suppression behaviour**, **exit-code behaviour**, or
**finding fingerprinting** must:

- Include a migration note in the relevant doc
- Include a backward-compatibility test
- Be approved by a project maintainer before merging

## Coding Conventions

- Modules are side-effect free — no top-level I/O outside of their `scan()` / formatter functions.
- Plugin code must not make network requests.
- Keep `engine`, `policy`, and `output` layers free of ecosystem-specific knowledge.
- Prefer extending JSON rule packs before changing plugin code.
- Use ESM (`import`/`export`) throughout; no CommonJS.

## Versioning

We follow [Semantic Versioning](https://semver.org/):

| Change | Version bump |
|--------|-------------|
| New rules, plugins, CLI flags, or options | Minor (`1.x.0`) |
| Bug fixes, false-positive reductions | Patch (`1.0.x`) |
| Breaking changes to schema, contracts, or fingerprinting | Major (`x.0.0`) |

## Licensing

By contributing you agree that your changes will be licensed under the project's MIT license.
