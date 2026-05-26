# Plugin API

## Contract

A plugin is a plain object returned by a factory function:

```js
export function createMyPlugin() {
  return {
    id: "my-plugin",           // unique short identifier
    scan: scanMyEcosystem      // async function
  };
}

async function scanMyEcosystem({ targetPath, compiledRulePack, options }) {
  // discover files, apply rules, return findings
  return [];
}
```

## Responsibilities

**Plugin must:**
- discover ecosystem-specific manifest files (e.g., `composer.json`, `package.json`),
- extract candidate execution surfaces (scripts, autoloaded files, lock entries),
- apply relevant rules filtered by scope,
- emit normalized `Finding` objects via `createFinding()`.

**Plugin must not:**
- decide pass/fail (that is the policy layer's job),
- format output,
- mutate policy or rule packs.

## Rule Scopes

Plugins filter the compiled rule pack by scope before applying rules:

| Scope | Applied how |
|-------|-------------|
| `script` | `compiledPattern.test(scriptText)` |
| `file` | `compiledPattern.test(fileContent)` |
| `manifest` | Matched by rule ID in plugin structural logic |
| `lockfile` | Matched by rule ID in plugin structural logic |

For `manifest` and `lockfile` scopes, the plugin performs its own structural analysis
(e.g., checking whether `autoload.files` is populated, or whether `dist.reference` is a
40-char commit SHA) and looks up the matching rule by ID to populate the finding metadata.

## Finding Fields

Use `createFinding()` from `packages/contracts/src/index.mjs`:

```js
import { createFinding } from "../../contracts/src/index.mjs";

createFinding({
  plugin:     "composer",         // plugin id
  ruleId:     rule.id,            // rule id from rule pack
  title:      rule.title,
  message:    "Detailed explanation of what was found and why it matters.",
  severity:   rule.severity,      // low | medium | high | critical
  confidence: rule.confidence,    // low | medium | high
  weight:     rule.weight,        // numeric score contribution
  path:       "/abs/path/to/file", // file where the finding was located
  hook:       "autoload.files",   // lifecycle hook or null
  snippet:    textOrJson,         // excerpt of the matched content
  tags:       rule.tags,
  references: rule.references
});
```

`path` is **required** — `createFinding()` throws if it is empty.

## Example Skeleton — Composer-style plugin

```js
import fs from "node:fs/promises";
import path from "node:path";
import { createFinding } from "../../contracts/src/index.mjs";

export function createMyPlugin() {
  return { id: "my-plugin", scan };
}

async function scan({ targetPath, compiledRulePack, options }) {
  const manifestRules  = compiledRulePack.rules.filter(r => r.scope === "manifest");
  const lockfileRules  = compiledRulePack.rules.filter(r => r.scope === "lockfile");
  const scriptRules    = compiledRulePack.rules.filter(r => r.scope === "script");
  const fileRules      = compiledRulePack.rules.filter(r => r.scope === "file");

  const findings = [];
  // ... discover files, check each scope, push createFinding() results
  return findings;
}
```

## Performance Guidance

- Skip directories named `vendor`, `node_modules`, and `.git` during file walks.
- Pre-filter rule lists by scope once at the start of `scan()`, not per-file.
- Short-circuit if no relevant manifest file is found in the target directory.
- Read file content only for files explicitly referenced in manifests — avoid full-tree scanning.

## Registering a Plugin

Plugins are passed to the engine via the `plugins` array:

```js
import { runEngine } from "./packages/engine/src/index.mjs";
import { createNpmPlugin } from "./packages/plugin-npm/src/index.mjs";
import { createComposerPlugin } from "./packages/plugin-composer/src/index.mjs";

await runEngine({
  plugins: [createNpmPlugin(), createComposerPlugin()],
  compiledRulePack,
  // ...
});
```

All plugins share the same merged rule pack — rule IDs must be unique across all packs
loaded in a single run.
