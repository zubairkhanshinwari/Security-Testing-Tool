# Auth Adapters

SecureAssess uses an **adaptive auth layer** so login is not a single fill-and-click path.

## Adapters

| Adapter | When used | Success proof |
|---------|-----------|---------------|
| **api-token** | JSON login APIs (`/api/auth/login`, …) | JWT / access_token in body or header |
| **cookie-session** | Frappe `/api/method/login`, cookie apps | Non-Guest `sid` / session cookie |
| **spa-form** | UI login pages (Bump Coach, SPAs) | Left `/login` and/or storage token / session cookie |

Strategy order is chosen from the target URL + discovered API bases (`detectAuthStrategies`).

## Session-ready gate

A login is **not** treated as success until `assertSessionReady` passes:

1. Page settle (domcontentloaded / networkidle best-effort)
2. Token in storage **or** session cookie **or** navigated away from `/login`
3. Only then does authenticated rediscovery run (`session.ready !== false`)

This prevents the Playwright race:

`page.evaluate: Execution context was destroyed, most likely because of a navigation`

## Flow

```text
Credentials
  → detect strategy order
  → try adapters in order
  → settle + assertSessionReady
  → SessionEngine stabilizes browser
  → auth-recrawl from post-login URL
```

## Code

- `src/scanner/auth/` — adapters + orchestrator
- `src/scanner/login.js` — backward-compatible entry
- `AuthEngine` / `SessionEngine` — platform wiring
