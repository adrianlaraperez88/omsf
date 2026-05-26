# Rule Authoring

## Rule Pack Format

Each rule pack JSON file contains:

```json
{
  "id": "pack-id",
  "version": "1.0.0",
  "description": "Human-readable description.",
  "rules": [ ... ]
}
```

Rule fields:

| Field | Required | Description |
|-------|:--------:|-------------|
| `id` | ✅ | Stable, unique identifier (`plugin.category.name`) |
| `scope` | ✅ | `script`, `file`, `manifest`, or `lockfile` |
| `title` | ✅ | Short human-readable title |
| `description` | ✅ | Explains what is detected and why it matters |
| `pattern` | ✅ | Regex source string (used for `script`/`file` scopes; documentation for `manifest`/`lockfile`) |
| `flags` | — | Regex flags (default `"i"`; case-insensitive) |
| `severity` | ✅ | `low`, `medium`, `high`, or `critical` |
| `confidence` | ✅ | `low`, `medium`, or `high` |
| `weight` | ✅ | Numeric score contribution (1–10 recommended) |
| `tags` | — | Array of lowercase string labels |
| `references` | — | Array of URLs explaining context or remediation |

OWASP module packs use the same format and live under `rules/modules/`. Their rule IDs must
use the `owasp.aXX.` prefix (e.g., `owasp.a03.composer-autoload-files`).

## Rule Scopes

### `script` and `file`

Pattern is compiled as a `RegExp` and tested against the text content:

- `script` — applied to lifecycle hook script text (e.g., `postinstall` script values)
- `file` — applied to the full text content of files referenced from lifecycle hooks
  (JS files for npm, PHP files in `autoload.files` for Composer)

### `manifest`

The Composer plugin matches `manifest`-scope rules by **rule ID** (not by regex) when
performing structural analysis of `composer.json`. The `pattern` field is still required
by the rule loader for schema validation, but is used for documentation purposes only.

### `lockfile`

The Composer plugin matches `lockfile`-scope rules by **rule ID** when inspecting
`composer.lock`. The `pattern` field follows the same documentation convention as `manifest`.

## Authoring Principles

1. Prefer high-signal patterns over broad generic ones — minimize false positives.
2. Keep rule IDs immutable once published; append a suffix to create a new variant.
3. Always include at least one `references` URL explaining why the rule exists.
4. Add a fixture and a test assertion for every new rule.
5. Avoid duplicate rules that match identical behaviour across different packs.
6. Use `flags: "i"` instead of inline `(?i)` modifiers for cross-engine compatibility.
7. For `manifest`/`lockfile` scope rules, set `pattern` to a descriptive slug (e.g., `"missing"`,
   `"tag-pin"`) so the rule validates and documents intent clearly.

## Example — `script` scope rule

```json
{
  "id": "composer.script-remote-exec",
  "scope": "script",
  "title": "Composer script pipes remote content to interpreter",
  "description": "A Composer lifecycle script streams remote content into php/bash — critical RCE risk.",
  "pattern": "\\b(?:curl|wget)\\b.*\\|\\s*(?:php(?:\\.exe)?|bash|sh)\\b",
  "flags": "i",
  "severity": "critical",
  "confidence": "high",
  "weight": 9,
  "tags": ["composer", "script", "rce", "supply-chain"],
  "references": ["https://getcomposer.org/doc/articles/scripts.md"]
}
```

## Example — `manifest` scope rule

```json
{
  "id": "composer.autoload-files-entry",
  "scope": "manifest",
  "title": "autoload.files entry detected",
  "description": "PHP executes every autoload.files entry on every boot — the Laravel-Lang attack vector.",
  "pattern": "autoload\\.files",
  "flags": "i",
  "severity": "high",
  "confidence": "high",
  "weight": 6,
  "tags": ["composer", "autoload", "supply-chain"],
  "references": ["https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack"]
}
```

## Anti-Patterns

- Catch-all patterns that fire on most benign scripts.
- Rules without tests.
- Rules without `references` or remediation context.
- Mutable rule IDs — changing an ID breaks baseline fingerprints.
- Regex without anchors that match inside longer tokens unintentionally.
