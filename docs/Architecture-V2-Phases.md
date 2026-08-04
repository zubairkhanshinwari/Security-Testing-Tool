# SecureAssess Architecture v2 — Phased Plan

Evolutionary refactor (not a big-bang rewrite). Each phase keeps `POST /api/scan`, UI, and report formats working.

```
Phase 1  → Browser / Session / Discovery extraction          ✅ done
Phase 2  → Knowledge Repository + event bus                  ✅ done
Phase 3  → Scan Planning Engine                              ✅ done
Phase 4  → Plugin Execution Engine (dual lanes)              ✅ done
Phase 5  → Verification / Evidence / Risk separation         ✅ done
Phase 6  → Persistence + incremental baselines               ✅ done
```

**Verification status (2026-08-04):** All phases confirmed complete in code + tests.  
Full audit: [Architecture-V2-Verification.md](./Architecture-V2-Verification.md).

---

## Phase 1 — Extract scarce resources

**Goal:** Orchestrator only coordinates; Playwright and auth live in dedicated engines.

| Deliverable | Path | Responsibility |
|-------------|------|----------------|
| BrowserEngine | `engines/browser/BrowserEngine.ts` | Launch Chromium, context, page, headers, close |
| SessionEngine | `engines/session/SessionEngine.ts` | Login, token recovery, session headers |
| DiscoveryEngine | `engines/discovery/DiscoveryEngine.ts` | Pages/forms/APIs/docs — no vuln probing |
| Thin orchestrator | `engines/orchestrator/ScanOrchestrator.ts` | Call engines in order; no `chromium.launch` |

**Done when:** Scans behave the same; orchestrator has no direct Playwright import.

---

## Phase 2 — Knowledge Repository ✅

**Goal:** Shared scan state; engines stop passing giant objects around.

| Deliverable | Path | Responsibility |
|-------------|------|----------------|
| `ScanEventBus` | `core/knowledge/ScanEventBus.ts` | stage / page / endpoint / finding events |
| `KnowledgeRepository` | `core/knowledge/KnowledgeRepository.ts` | discovery, session, surface, findings, coverage, risk |
| Orchestrator wiring | `engines/orchestrator/ScanOrchestrator.ts` | creates repo per scan; stages read/write via repo |
| Discovery / Session adapters | `discovery/`, `session/` | optional `repo` write-through |

**Done when:** Orchestrator uses `KnowledgeRepository` as the scan source of truth and builds `ScanResult` from `repo.toScanResult()`.

---

## Phase 3 — Scan Planning Engine ✅

**Goal:** Run only relevant work.

| Deliverable | Path | Responsibility |
|-------------|------|----------------|
| `ScanPlanningEngine` | `engines/planning/ScanPlanningEngine.ts` | types × fingerprint × surface → `ScanPlan` |
| Task queue | `ScanTask[]` | priority + lane (`http` \| `browser`) |
| Mode / relevance | planner | passive gating, GraphQL/WS skip, WAF concurrency hint |
| Repo integration | `plan.created` event + `meta.scanPlan` | plan snapshot on scan result |

**Done when:** Orchestrator executes `plan.tasks` / `plan.surfaceTypes` and does not select plugins itself.

---

## Phase 4 — Plugin Execution Engine ✅

**Goal:** Parallel, isolated plugin runs; HTTP lane for most probes.

| Deliverable | Path | Responsibility |
|-------------|------|----------------|
| `PluginExecutionEngine` | `engines/execution/PluginExecutionEngine.ts` | init → discover → scan → verify → cleanup |
| HTTP lane | concurrency = `plan.httpConcurrencyHint` | Parallel header/CORS/info-style plugins |
| Browser lane | `scan.browserLaneConcurrency` (default 1) | Injection / DOM-bound plugins |
| Surface residual | same executor | `surface-check` tasks after plugins |
| Failure isolation | per-task try/catch | One plugin failure does not kill the scan |

**Done when:** Orchestrator calls `executor.execute(plan)` and does not loop plugins or surfaceChecks itself.

---

## Phase 5 — Verification / Evidence / Risk ✅

**Goal:** Confirm first, capture evidence second.

| Deliverable | Path | Responsibility |
|-------------|------|----------------|
| `VerificationEngine.process()` | `engines/verification/` | normalize ids → dedupe → confidence / FP tempering |
| `EvidenceEngine` | `engines/evidence/EvidenceEngine.ts` | screenshots only for verified C/H/M/L |
| `RiskEngine.evaluateVerified()` | `engines/risk/` | score after verification |
| `ReportingEngine` | uses EvidenceEngine | no screenshots for Pass / Informational noise |

Config: `reporting.evidence.onlyVerified` (default `true`), `reporting.evidence.severities`.

**Done when:** Screenshots are never taken for unverified / Informational-only noise by default.

---

## Phase 6 — Persistence + incremental scans ✅

**Goal:** Faster re-scans; history as a first-class baseline.

| Deliverable | Path | Responsibility |
|-------------|------|----------------|
| Baseline model | `dashboard/baseline.ts` | endpoints, tech, confirmed findings |
| Persist on save | `ProjectStore.saveBaseline` | `{projectId}.baseline.json` beside project |
| Diff | `ProjectStore.diffBaseline` | new / removed / focus endpoints + retest plugins |
| Planner | incremental boost | prior-issue plugins first; `focusEndpoints` on plan/ctx |
| API / UI | `incremental: true` | checkbox + `GET /api/projects/:id/baseline` |

Config: `scan.incremental.enabled` (default false), `scan.incremental.retestConfirmed` (default true).

**Done when:** Optional `incremental: true` reuses last baseline and focuses the planner.

---

## Efficiency principles (all phases)

1. Browser is scarce — prefer HTTP probes when possible  
2. Plan before spray — skip irrelevant plugins/targets  
3. Verify before evidence  
4. Budget pages, time, and probes  
5. New plugin = register only; no orchestrator edits  

## Compatibility

- Legacy names (`ReconEngine`, `AuthEngine`) remain as implementations behind Discovery/Session in Phase 1  
- API contract and report JSON stay stable unless a phase explicitly versions them  
