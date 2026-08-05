# Confirmation Depth Pack (`confirmation-depth-v1`)

Raises finding certainty without destructive exploitation.

## Confidence ladder

| Level | Rule |
|-------|------|
| **Possible** | Weak / single signal |
| **Likely** | Proof signal **or** ≥3 support signals |
| **Confirmed** | ≥1 **proof** signal **and** (≥3 total signals **or** ≥2 proof signals) |

### Proof signals

`boolean-diff` · `cross-user` · `reflection-unencoded` · `error-marker` · `negative-control` · `reproducible` · `timing-diff` · `context-probe`

## What changed

| Area | Behavior |
|------|----------|
| **SQLi** | Error markers must differ from baseline; boolean gaps must reproduce (2 rounds); timing needs 2 delayed hits |
| **XSS** | Unencoded reflection detection; baseline diff; context second probe |
| **IDOR** | Negative-control ID; optional **User B** (`username2` / `password2`) cross-user session |
| **Verification** | Confirmed requires proof; end-of-scan `retestConfirmed` demotes fake Confirmed |

## Dual-account IDOR

UI fields **Second user** / password, or API:

```json
{
  "username": "user-a@example.com",
  "password": "***",
  "username2": "user-b@example.com",
  "password2": "***",
  "authorized": true
}
```

CLI: `--username2` / `--password2`

User B logs in on an **ephemeral browser context** so User A cookies stay intact.

## Report meta

```json
{
  "precisionPack": "verification-baseline-v1",
  "confirmationPack": "confirmation-depth-v1"
}
```

Findings expose `verification.signals` for analyst review.
