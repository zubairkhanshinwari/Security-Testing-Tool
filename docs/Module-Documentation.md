# Module Documentation

## Engine modules

| Module | Path | Responsibility |
|--------|------|----------------|
| ReconEngine | `src/platform/engines/recon` | Crawl, XHR/fetch capture, JS routes, robots/sitemap/OpenAPI |
| AuthEngine | `src/platform/engines/auth` | Password/JWT/API key; OAuth providers planned |
| AttackSurfaceEngine | `src/platform/engines/attack-surface` | Normalize inventory |
| PluginManager | `src/platform/plugins` | Auto-register plugins |
| VerificationEngine | `src/platform/engines/verification` | Evidence + confidence |
| RiskEngine | `src/platform/engines/risk` | Weighted CVSS-aware score |
| ReportingEngine | `src/platform/engines/reporting` | HTML/PDF/JSON/SARIF/CSV/JUnit |
| ScanOrchestrator | `src/platform/engines/orchestrator` | End-to-end pipeline |
| ProjectStore | `src/platform/dashboard` | Projects, history, trends |

## Security plugins

See each `modules/*/README.md`.

## Legacy modules (preserved)

| Module | Path |
|--------|------|
| probes | `src/scanner/probes.js` |
| recon | `src/scanner/recon.js` |
| login | `src/scanner/login.js` |
| securityTypes | `src/scanner/securityTypes.js` |
| html/pdf report | `src/report/*` |
