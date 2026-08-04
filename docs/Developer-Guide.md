# Developer Guide

## Prerequisites

- Node.js 18+
- npm
- Playwright Chromium (`postinstall`)

## Local development

```bash
npm install
npm start
npm test
npm run lint
```

## Adding a security check

1. Create `modules/<id>/` with manifest + scanner
2. Map findings with `src/platform/core/standards/mappings.js`
3. Add unit tests under `tests/`
4. Restart server (auto-register)

## Reusing v1 probes

Prefer adapting `src/scanner/probes.js` and `recon.js` inside plugins instead of rewriting HTTP logic. This preserves proven detection quality (e.g. Falaya NoSQLi regex).

## Coding standards

- TypeScript for platform engines
- SOLID: engines have single responsibility; plugins are open for extension
- No secrets in repo; credentials only via UI/CLI at runtime
- Keep safety invariants in `config/safety.json`

## Debugging a scan

- Watch orchestrator logs (`[stage] message`)
- Inspect `data/scans/*.result.json`
- Open HTML report under `reports/`
