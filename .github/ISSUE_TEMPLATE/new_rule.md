---
name: New Rule / Detection Request
about: Propose a new detection rule or improve an existing one
labels: rule, enhancement, triage
---

## What should be detected?

<!-- Describe the malicious or risky behaviour the rule should catch -->

## Real-world example or reference

<!-- Link to CVE, supply-chain incident, advisory, or blog post -->

## Proposed rule

```json
{
  "id": "plugin.category.name",
  "scope": "script",
  "title": "Short title",
  "description": "What does this detect and why is it dangerous?",
  "pattern": "\\bregex-here\\b",
  "flags": "i",
  "severity": "high",
  "confidence": "medium",
  "weight": 5,
  "tags": ["supply-chain"],
  "references": ["https://link-to-reference"]
}
```

## False positive risk

<!-- How likely is this to fire on benign code? What would reduce that? -->

## Ecosystem

- [ ] npm (`package.json`)
- [ ] Composer (`composer.json`)
- [ ] Other (please specify)
