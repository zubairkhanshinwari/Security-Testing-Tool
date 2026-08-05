# CI packaging

Wire SecureAssess into GitHub Actions as a non-destructive DAST gate.

## What ships

| Piece | Path |
|-------|------|
| Workflow | `.github/workflows/secureassess.yml` |
| Gate script | `scripts/ci-gate.js` (`npm run ci:gate`) |
| Reports | SARIF + JUnit + JSON (from scan) |

## Unit job (always)

On push / PR:

1. `npm ci`
2. `npm run typecheck`
3. `npm test`
4. Gate self-check

## Security scan job (optional)

Runs when a target URL is available from:

- `workflow_dispatch` input `target_url`, or
- repository variable `SECUREASSESS_TARGET_URL`, or
- secret `SECUREASSESS_TARGET_URL`

Optional auth secrets (Account A / Account B):

- `SECUREASSESS_USERNAME` / `SECUREASSESS_PASSWORD` (Account A)
- `SECUREASSESS_USERNAME2` / `SECUREASSESS_PASSWORD2` (Account B, IDOR/BOLA)

Uses **Quick** profile by default (`--profile quick`).

## Quality gate

```bash
npm run ci:gate -- --json reports/<scan>.json
# or
npm run ci:gate -- --sarif reports/<scan>.sarif.json
```

**Fails** when any finding is **Confirmed** and **High** or **Critical**.

Flags:

- `--severity Critical,High` — severities that block (default)
- `--allow-likely` — also block Likely (not only Confirmed)

## Local example

```bash
npm run scan -- --url https://dev.example.com --profile quick --yes --out reports
npm run ci:gate -- --json reports/$(ls -t reports/*.json | head -1)
```

## Authorization

Only scan systems you own or are explicitly authorized to test. The CLI requires `--yes`.
