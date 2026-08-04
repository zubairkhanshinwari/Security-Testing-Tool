# Architecture Audit — SecureAssess Platform

**Date:** 2026-08-03  
**Role:** Principal Security / Enterprise Architecture review  
**Scope:** Existing codebase only (no greenfield redesign)

## Executive verdict

SecureAssess is a **competent dual-stack platform**: a TypeScript enterprise facade over a proven Playwright v1 scanner. It is suitable as a foundation for security teams, but not yet production-hardened for multi-tenant or internet-exposed deployment.

**Strategy:** Harden and deepen — do not rewrite.

---

## Critical findings

| ID | Issue | Impact |
|----|--------|--------|
| C1 | API unauthenticated | Open scanner / credential abuse |
| C2 | No target allowlist / private-IP block | SSRF-as-a-service via Playwright |
| C3 | Tokens/auth headers can persist in reports/`data/` | Secret leakage |

## High findings

| ID | Issue |
|----|--------|
| H1 | In-memory jobs; no cancel/concurrency durability |
| H2 | `mode` stored but not enforced |
| H3 | Plugins + `surfaceChecks` double-run → FP inflation |
| H4 | Plugin `report()`/`score()` never called |
| H5 | Catalog breadth >> deep scanner coverage |

## Medium / Low

Coarse dedupe, heuristic confidence, Falaya-specific templates, unused `config.safety` knobs, thin tests, console-only logging, no browser pool.

---

## Prioritized backlog (impact order)

1. API bind defaults + optional API key (ops hardening)
2. Target policy (block private/metadata IPs; optional allowlist)
3. Secret redaction in recon/results/reports
4. Job concurrency + cancel (AbortSignal)
5. Enforce scan `mode` (passive / active-safe / authenticated)
6. Eliminate duplicate plugin/surface ownership
7. Honor `config.safety` rate/probe limits
8. Multi-evidence verification + confidence model
9. Knowledge enrichment on findings
10. Baseline scan comparison API
11. Tech fingerprinting (passive)
12. OpenAPI for API-first consumers
13. Browser pool / optional PDF (perf)
14. Deeper plugins (XSS/JWT/IDOR) — quality over quantity

---

## Keep vs refactor

**Keep:** Orchestrator pipeline, proven `probes.js`/`recon.js`/`login.js`, plugin manifests, Verification + Risk engines, SARIF/JUnit, ProjectStore trends.

**Refactor:** Dual check paths, unused safety config, in-memory jobs, cwd-based requires, over-broad host matching.

**Defer:** Full distributed workers, OAuth social login automation, AI-as-oracle (AI assist only after evidence).

---

## Phase 1 (this iteration)

Implements items **2–6, 8–12** incrementally with backward-compatible APIs.
