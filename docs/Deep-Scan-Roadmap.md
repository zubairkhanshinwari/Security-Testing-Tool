# Deep Scan / Strong Scanner Roadmap

Builds on Architecture v2. Goal: **more confirmed findings with evidence**.

| Phase | Focus | Status |
|-------|--------|--------|
| **A** | Deeper discovery | ✅ Done |
| **B** | Full plugins (XSS → IDOR → JWT → CSRF → redirect → SSRF) | ✅ Done |
| **C** | Stronger injection (SQLi/NoSQLi/SSTI/LFI) | ✅ Done |
| **D** | Auth & session depth | ✅ Done |
| **E** | Smart targeting (fingerprint + focusEndpoints) | ✅ Done |
| **F** | Scale (concurrency knobs, CI reports) | ✅ Done |

---

## Phase A — Discovery
Sitemap/OpenAPI/forms/auth-recrawl · `scan.discovery.*`

## Phase B — Plugins
`xss`, `idor-bac`, `jwt`, `csrf`, `open-redirect`, `ssrf`

## Phase C — Injection
Expanded SQLi/NoSQLi · `ssti` · `lfi`

## Phase D — Auth
`cookie-security` · `session-mgmt`

## Phase E — Smart targeting
- `fingerprint` on `PluginContext`
- Planner relevance skips (NoSQLi vs SQL-only FP, LFI without file sinks)
- `prioritizeByFocus()` for incremental/focus endpoints

## Phase F — Scale
- `scan.httpLaneConcurrency` (default 4; WAF halves via planner)
- `scan.browserLaneConcurrency`
- Report formats already include `junit` / `sarif` for CI gates (`reporting.formats`)

Restart the server after pulling these changes (`npm start`).
