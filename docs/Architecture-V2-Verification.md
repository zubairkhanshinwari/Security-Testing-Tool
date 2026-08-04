# Architecture v2 — Completion Verification

**Verified:** 2026-08-04  
**Result:** All 6 phases **COMPLETE** and wired into the live scan pipeline.  
**Tests:** 24/24 architecture-related unit tests passing.

---

## Live pipeline (matches Architecture.md)

```
UI → API → ScanOrchestrator
  → BrowserEngine
  → DiscoveryEngine → KnowledgeRepository
  → FingerprintEngine
  → SessionEngine
  → AttackSurfaceEngine
  → ProjectStore.diffBaseline (optional incremental)
  → ScanPlanningEngine
  → PluginExecutionEngine (HTTP + browser lanes + surfaceChecks)
  → VerificationEngine.process()
  → EvidenceEngine (verified C/H/M/L only)
  → RiskEngine.evaluateVerified()
  → ReportingEngine
  → ProjectStore.saveScan (+ baseline sidecar)
```

Bootstrap wires every engine in `src/platform/bootstrap.ts`.

---

## Phase checklist

| Phase | Done criterion | Code proof | Status |
|-------|----------------|------------|--------|
| **1** Browser / Session / Discovery | Orchestrator has no Playwright import | `ScanOrchestrator.ts` imports engines only; `chromium.launch` only in `BrowserEngine` (+ evidence standalone) | ✅ |
| **2** Knowledge Repository | Result from `repo.toScanResult()` | Orchestrator creates `KnowledgeRepository`; ends with `repo.toScanResult()` | ✅ |
| **3** Scan Planning | Orchestrator does not select plugins | `planner.plan(...)`; no `resolveForTypes` in orchestrator | ✅ |
| **4** Plugin Execution | Orchestrator does not loop plugins/surfaceChecks | Single call `executor.execute({ plan, ... })` | ✅ |
| **5** Verify → Evidence → Risk | Evidence after verify; no Pass/Informational shots by default | `verification.process` → `evidence.collect` → `risk.evaluateVerified`; `reporting.evidence.onlyVerified: true` | ✅ |
| **6** Incremental baselines | `incremental: true` uses baseline | `store.diffBaseline`; planner retest boost; UI checkbox; `GET /api/projects/:id/baseline`; baseline JSON on save | ✅ |

---

## Files that define the new architecture

| Layer | Path |
|-------|------|
| Browser | `engines/browser/BrowserEngine.ts` |
| Session | `engines/session/SessionEngine.ts` |
| Discovery | `engines/discovery/DiscoveryEngine.ts` |
| Knowledge | `core/knowledge/KnowledgeRepository.ts`, `ScanEventBus.ts` |
| Planning | `engines/planning/ScanPlanningEngine.ts` |
| Execution | `engines/execution/PluginExecutionEngine.ts` |
| Verification | `engines/verification/VerificationEngine.ts` |
| Evidence | `engines/evidence/EvidenceEngine.ts` |
| Risk | `engines/risk/RiskEngine.ts` |
| Reporting | `engines/reporting/ReportingEngine.ts` |
| Baseline | `dashboard/baseline.ts`, `ProjectStore` |
| Coordinator | `engines/orchestrator/ScanOrchestrator.ts` |
| DI | `bootstrap.ts`, `core/di/container.ts` |

Legacy wrappers still used behind facades (by design):
- `ReconEngine` ← DiscoveryEngine  
- `AuthEngine` ← SessionEngine  
- `ScreenshotEvidence` ← EvidenceEngine  
- `src/scanner/*` ← plugins / surfaceChecks  

---

## Unit test coverage (architecture)

| Suite | Focus |
|-------|--------|
| `knowledgeRepository.test.ts` | Repo + event bus |
| `scanPlanningEngine.test.ts` | Plan, lanes, incremental retest |
| `pluginExecutionEngine.test.ts` | Dual lane + failure isolation |
| `evidenceEngine.test.ts` | Verified-only eligibility |
| `verificationEngine.test.ts` | `process()` / confidence |
| `baseline.test.ts` | Baseline build + diff |
| `riskEngine.test.ts` / `reportingEngine.test.ts` | Risk + report path |

---

## Minor notes (not blockers)

1. Orchestrator still owns coverage-matrix helpers and progress — acceptable for a thin coordinator.  
2. Plugins may ignore `focusEndpoints` today; planner still records them for incremental focus / future targeting.  
3. `Architecture.md` roadmap still lists some future items (OAuth, job queue, browser pool) beyond v2 phases.

---

## Verdict

**Architecture v2 phases 1–6 are implemented, wired, and verified against the documented design.**  
The scanner runs on the new engine-based architecture, not the old monolithic orchestrator path.
