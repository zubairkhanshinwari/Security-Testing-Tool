# Coverage vs Time — Profiles & Focus

Discovery is **capped by design** so scans stay usable. Use profiles + focus routes to spend time where risk matters.

## Profiles

| Profile | ETA | Crawl | OpenAPI paths | Best for |
|---------|-----|-------|---------------|----------|
| **Quick** | ~2–4 min | 4 pages | 12 | Smoke / CI |
| **Standard** | ~4–10 min | 8 pages | 30 | Default assessments |
| **Deep** | ~15–35 min | 16 pages | 60 | Broader coverage (still not exhaustive) |
| **Focused** | ~3–12 min | 3 pages | 80 | Operator-supplied routes / OpenAPI |

Deep does **not** mean “full app.” Obscure admin/API corners still need **Focus routes**.

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

## Recommended workflow

1. **Quick** — validate auth + plumbing  
2. **Standard** — main report  
3. **Focused** or **Deep** + focus list — critical modules  

## Report meta

```json
{
  "coveragePack": "coverage-focus-v1",
  "scanProfile": "focused",
  "focusEndpointCount": 12,
  "openApiUrl": "https://…"
}
```
