# Coverage vs Time — Profiles & Focus

Discovery is **capped by design** so scans stay usable. Use profiles + focus routes to spend time where risk matters.

## Preflight (before recon)

Every scan runs **preflight before browser launch / recon** (firewall-aware):

1. **Target reachable** — HTTP HEAD/GET first; if filtered, TCP connect to the URL port. **ICMP ping is not used** (usually blocked behind firewalls). Timeouts / host-unreachable are reported as `FIREWALL_FILTERED`.
2. **Security plugins available** — at least one registered plugin must match the selected types (checked even when the node is down, so you see plugin status separately).

401/403 still count as alive (auth/WAF path). UI calls `POST /api/preflight` first; the orchestrator repeats the same gate. Failed preflight never starts discovery.

## Profiles

| Profile | ETA | Crawl | OpenAPI paths | Best for |
|---------|-----|-------|---------------|----------|
| **Quick** | ~2–4 min | 4 pages | 12 | Smoke / CI |
| **Standard** | ~4–10 min | 8 pages | 30 | Default assessments |
| **Deep** | ~15–35 min | 16 pages | 60 | Broader coverage (still not exhaustive) |
| **OpenAPI-first** | ~8–25 min | 4 pages | 120 | API-heavy apps — prioritize Swagger/OpenAPI |
| **Focused** | ~3–12 min | 3 pages | 80 | Operator-supplied routes / OpenAPI |

Deep does **not** mean “full app.” Obscure admin/API corners still need **Focus routes**.  
If **Deep** is selected **and** an OpenAPI URL is provided, discovery auto-adopts OpenAPI-first knobs.

## Focus routes

Seed discovery and prioritize probes:

- UI: **Focus routes** textarea  
- API: `"focusEndpoints": ["/api/users", "/admin"]`  
- CLI: `--focus /api/users,/admin`

Paths are resolved against the target origin. Off-domain URLs are dropped (related API hosts on the same root domain are kept).

## OpenAPI URL

- UI: **OpenAPI / Swagger URL**  
- API: `"openApiUrl": "https://dev.example.com/openapi.json"`  
- CLI: `--openapi https://dev.example.com/openapi.json`

Parsed endpoints merge into the attack surface (still capped by profile).

## Injection checks (incl. LFI)

**LFI / Path Traversal** is a recommended active-safe plugin. It probes file-like parameters for traversal and known-file signatures (baseline compare). It is **not** run in passive mode — use Standard/Deep (or Select recommended) with active-safe.

## Access control (IDOR / BOLA)

**IDOR / BAC** is recommended. It probes object URLs and id-like params (GET-only), mutates neighbor IDs, and optionally confirms with **Account B** (strongest BOLA proof). Add Account B in the UI or `--username2` / `--password2`.

## Clickjacking

Dedicated **Clickjacking** plugin (recommended) checks `X-Frame-Options` and CSP `frame-ancestors` on the homepage and sensitive UI routes. Passive only — no iframe exploit PoCs.

## Recommended workflow

1. **Quick** — validate auth + plumbing  
2. **Standard** — main report  
3. **OpenAPI-first** (or Deep + OpenAPI URL) — API-heavy targets  
4. **Focused** / Deep + focus list — critical modules  
5. Dashboard **Re-run vs last scan** — regression (New / Fixed / Unchanged)  

## Report meta

```json
{
  "coveragePack": "coverage-focus-v1",
  "scanProfile": "focused",
  "focusEndpointCount": 12,
  "openApiUrl": "https://…"
}
```
