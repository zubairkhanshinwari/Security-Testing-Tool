# Precision Pack — What Improved

**Pack id:** `verification-baseline-v1`  
**Goal:** fewer false High/Criticals, clearer Confirmed vs Possible, faster useful scans.

---

## Areas improved

| Area | Before | After |
|------|--------|--------|
| **Verification** | Single evidence item could stay High | High/Critical need **≥2 independent signals**; else severity tempered + `[Precision]` note |
| **Injection gate** | XSS/SQLi/etc. could be High on one probe | Without baseline/differential/cross-request → **Medium / Possible** |
| **Baseline compare** | Rare | XSS (and shared helper) compares **clean vs payload** response |
| **IDOR precision** | Any 200 + sensitive-looking body | Prefers **JSON content-type**; anonymous strong → High, weak → Possible |
| **Finding dedupe** | Title-ish key only | **Family key**: plugin + CWE + normalized endpoint (`/{id}`) + title; **merges evidence** |
| **Param targeting** | Mostly first-N params | **Ranked**: `id`/`q`/`search` first; skip csrf/token/password |
| **Scan profiles** | One speed for everyone | **Quick / Standard / Deep** (UI + `profile` on `POST /api/scan`) |
| **Score noise** | Many duplicate IDOR paths → 0/100 | Family diminishing (earlier) + fewer duplicate findings |

---

## How results improve (what you’ll see)

1. **Fewer inflated Highs** — Weak “maybe XSS/IDOR” show as **Medium / Possible** until confirmed with a second signal.  
2. **Cleaner reports** — Duplicate `/users/1` + `/users/2` style IDOR collapse into **one family finding** with more evidence rows.  
3. **More trustworthy Confirmed** — Confirmed stays for multi-signal cases (error + differential, or baseline + reflection + HTTP pair).  
4. **Better use of time** — Quick profile for smoke; Standard default; Deep when you need breadth.  
5. **Meta transparency** — Reports include `meta.precisionPack` and `meta.scanProfile`.

---

## Example (conceptual)

| Finding type | Old outcome | New outcome |
|--------------|-------------|-------------|
| XSS marker reflected, no baseline diff | High / Likely | Medium / Possible (+ precision note) |
| XSS reflected + baseline body change + 2 HTTP | High / Likely | Stays High path; can reach Confirmed with enough signals |
| IDOR HTML soft-404 with `"email"` in page | High | Demoted / weaker confidence without JSON type |
| 6 IDOR paths same API shape | 6 High findings, score crash | 1 family finding, stable score |

---

## How to use

1. Restart server (`npm run build` then `npm start` if using dist).  
2. On home page choose **Scan profile**.  
3. Or API: `"profile": "quick" | "standard" | "deep"`.  
4. In JSON report check:
   - `meta.precisionPack === "verification-baseline-v1"`
   - `meta.scanProfile`
   - finding `verification.signals` (look for `precision-injection-gate`, `baseline-diff`, etc.)

---

## Still non-destructive

No DROP/DELETE/flooding. Precision comes from **better confirmation**, not riskier payloads.
