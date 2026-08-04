# Plugin Development Guide

## Layout

```
modules/my-plugin/
  manifest.json
  scanner.js          # or scanner.ts
  payloads.json       # optional
  README.md
```

## manifest.json

```json
{
  "id": "my-plugin",
  "name": "My Plugin",
  "version": "1.0.0",
  "description": "What it checks",
  "category": "Injection",
  "enabledByDefault": true,
  "recommended": false,
  "securityTypeIds": ["sqli"],
  "owasp": ["A03:2021-Injection"],
  "cwe": ["CWE-89"],
  "modes": ["active-safe"]
}
```

## Required API

Export `createPlugin(manifest)` returning:

| Method | Responsibility |
|--------|----------------|
| `discover(ctx)` | Select targets from attack surface |
| `scan(ctx, discovery)` | Collect candidates / probe results |
| `verify(ctx, candidates)` | Emit `Finding[]` with evidence only |
| `report(findings)` | Plugin summary object |
| `score(findings)` | Local risk delta metadata |

## Context (`ctx`)

- `request` — scan request
- `attackSurface` — inventory
- `auth` — session/token
- `page` — Playwright page (use `page.context().request` for HTTP)
- `selectedTypes` — expanded security type ids
- `logger`, `config`

## Safety rules

- No destructive SQL (`DROP`, mass `DELETE`)
- No malware / webshell upload
- No unbounded floods
- Prefer confirmation differentials over exploitation
- Set `testMode` to `passive` | `active-safe` | `authenticated`

## Registration

Drop the folder under `modules/`. `PluginManager.autoRegister()` loads it on startup.

Disable via `config/default.json`:

```json
"plugins": { "disabled": ["my-plugin"] }
```

## Testing

Add `tests/my-plugin.test.ts` covering verify() with mock candidates.
