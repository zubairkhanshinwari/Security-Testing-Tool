# Demo targets

Use these **authorized lab / public smoke** targets to verify SecureAssess. Do **not** scan production systems you do not own.

| Path | Target | Purpose |
|------|--------|---------|
| **A — Smoke** | [httpbin.org](https://httpbin.org) | Prove install + scan completes in minutes |
| **B — Lab** | [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) (Docker) | Human demo against an intentional vulnerable app |

Later (optional): an in-repo fixture for deterministic CI assertions. DVWA is not required if Juice Shop covers your lab needs.

---

## A. Smoke — httpbin

**Expect:** scan finishes; reports written under `reports/`. Findings are often Informational / Pass (headers, info disclosure style checks). This is a **pipeline smoke**, not a vuln showcase.

```bash
npm install
npm run scan -- --url https://httpbin.org --profile quick --project "Demo httpbin" --yes --out reports
```

Optional quality gate (usually passes on httpbin):

```bash
npm run ci:gate -- --json "$(ls -t reports/*.json 2>/dev/null | head -n1)"
```

On Windows PowerShell:

```powershell
npm run scan -- --url https://httpbin.org --profile quick --project "Demo httpbin" --yes --out reports
$report = Get-ChildItem reports\*.json | Sort-Object LastWriteTime -Descending | Select-Object -First 1
npm run ci:gate -- --json $report.FullName
```

UI alternative: start the server (`npm run start:dev`), open http://localhost:3847, set URL to `https://httpbin.org`, profile **Quick**, check authorization, run.

---

## B. Lab — OWASP Juice Shop

**Expect:** richer surface (SPA + APIs). With Quick/Focused you may see headers, cookie, info, or access-control related signals depending on depth and auth. **Confirmed High/Critical is environment-dependent** — do not treat a clean gate as “Juice Shop is secure.”

### 1. Start Juice Shop

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Open http://localhost:3000 and confirm the shop loads.

### 2. Scan (Quick)

```bash
npm run scan -- --url http://localhost:3000 --profile quick --project "Demo Juice Shop" --yes --out reports
```

### 3. Optional focused routes

Spend time on high-value paths instead of a wide crawl:

```bash
npm run scan -- --url http://localhost:3000 --profile focused \
  --focus "/api/Users,/rest/products/search,/rest/user/login" \
  --project "Demo Juice Shop focused" --yes --out reports
```

### 4. Optional dual-account (IDOR/BOLA)

Register two Juice Shop users in the UI, then:

```bash
npm run scan -- --url http://localhost:3000 --profile quick \
  --username account-a@example.com --password '...' \
  --username2 account-b@example.com --password2 '...' \
  --yes --out reports
```

Use throwaway lab passwords only. Never commit credentials or real `reports/`.

### 5. UI

Same as smoke: Assessment UI → `http://localhost:3000` → Quick or Focused → authorize → run. Compare runs on `/dashboard.html` (New / Fixed / Unchanged after two scans).

---

## What not to do

- Do not commit `reports/` or scan JSON that may contain cookies/tokens  
- Do not point default CI at Juice Shop on every PR (slow/flaky); use `workflow_dispatch` or a configured lab URL — see [CI-Packaging.md](./CI-Packaging.md)  
- Do not present demo findings as a certified pentest of Juice Shop  

---

## Related

- [CI packaging](./CI-Packaging.md)  
- [Coverage profiles](./Coverage-Profiles.md)  
- [Security policy](../SECURITY.md) (tool vulns only — not lab app findings)
