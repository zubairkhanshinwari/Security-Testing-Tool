# ADR-001: Phase 1 Hardening & Accuracy

## Status
Accepted

## Context
Architecture audit identified SSRF risk, unused safety config, duplicate checks, and weak verification as the highest ROI issues.

## Decision
1. Enforce target policy before browser launch.
2. Redact secrets from persisted scan results.
3. Add in-process job controller (concurrency + cancel).
4. Gate injection plugins by `mode`.
5. Run surfaceChecks only for types not owned by active plugins.
6. Enrich findings via Knowledge Engine after verification.
7. Expose baseline compare + OpenAPI without breaking `POST /api/scan`.

## Consequences
- Slightly stricter default (private IPs blocked unless `SECUREASSESS_ALLOW_PRIVATE=1`).
- Fewer duplicate Medium findings from headers/CORS/info plugins.
- Cancel is cooperative (best-effort AbortSignal).
