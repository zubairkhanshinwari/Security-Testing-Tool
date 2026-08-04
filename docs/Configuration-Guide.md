# Configuration Guide

## Files

| File | Role |
|------|------|
| `config/default.json` | Base platform config |
| `config/safety.json` | Safety modes & forbidden behaviors |
| `config/<env>.json` | Optional overlay (`SECUREASSESS_ENV`) |

## Important keys

### safety

- `requireAuthorization` — block unauthorized scans
- `maxConcurrentProbes` / `rateLimitPerHostPerMinute` — abuse prevention
- `maxPagesCrawl`, `maxParameters` — scope caps
- `allowDestructive`, `allowDoS` — must remain `false`

### plugins

- `directory` — default `modules`
- `autoRegister` — load on boot
- `disabled` — list of plugin ids

### scan

- `browserLaneConcurrency` — browser-lane plugin parallelism (default `1`)
- `incremental.enabled` — default incremental mode when request omits flag
- `incremental.retestConfirmed` — boost plugins that previously confirmed issues

### reporting

- `formats` — `html`, `pdf`, `json`, `sarif`, `csv`, `junit`
- `includeScreenshots` — enable EvidenceEngine capture
- `evidence.onlyVerified` — screenshots only for verified C/H/M/L (default `true`)
- `evidence.severities` — severity allow-list for evidence

### storage

- `reportsDir`, `projectsDir`, `scansDir`
- Baselines: `data/projects/{projectId}.baseline.json` (auto-written on save)

## Scan modes

| Mode | Behavior |
|------|----------|
| `passive` | No injection payloads |
| `active-safe` | Default non-destructive verification |
| `authenticated` | Uses credentials/tokens for protected APIs |
