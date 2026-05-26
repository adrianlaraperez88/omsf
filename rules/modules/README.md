# OWASP Module Packs

Each file in this directory is a standalone rule pack aligned to one OWASP Top 10:2025 category.

Use one or many modules in a scan:

```bash
omsf --path . --modules a03-software-supply-chain-failures
omsf --path . --modules a02-security-misconfiguration,a03-software-supply-chain-failures
```

List bundled module ids:

```bash
omsf --list-modules
```

Included starter modules:

- `a01-broken-access-control`
- `a02-security-misconfiguration`
- `a03-software-supply-chain-failures`
- `a04-cryptographic-failures`
- `a05-injection`
- `a06-insecure-design`
- `a07-authentication-failures`
- `a08-software-or-data-integrity-failures`
- `a09-security-logging-and-alerting-failures`
- `a10-mishandling-of-exceptional-conditions`
