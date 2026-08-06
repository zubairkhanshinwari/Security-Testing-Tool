# Clickjacking / Frame Protection

Safe, **passive** checks for UI redressing / clickjacking (CWE-1021).

## What it does

- Reviews `X-Frame-Options` (`DENY` / `SAMEORIGIN`)
- Reviews CSP `frame-ancestors` (`'none'`, `'self'`, allowlist)
- Flags missing protection and weak policies (`ALLOW-FROM`, `frame-ancestors *`)
- Prioritizes homepage, auth/checkout/admin-like pages, and focus routes

Does **not** load attacker iframes or perform interaction exploits.

## Types

Select **Clickjacking**, or use **Select recommended** / **OWASP Top 10** (also covered via security headers).
