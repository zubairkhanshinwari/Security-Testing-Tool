# Architecture

## Goals

- Enterprise modularity without breaking the working v1 scanner
- Safe-by-design authorized assessments
- Extensibility via plugins
- Standards-aligned findings (OWASP, CWE, CAPEC, CVSS v4, NIST)

## Layered design (v2 Phase 6 — complete)

```
UI (public/)
    ↓
API Server (src/platform/api/server.ts)
    ↓
Scan Orchestrator (thin coordinator)
    ↓
Knowledge Repository  ←── Scan Event Bus
    ↑         ↑         ↑
Browser → Discovery → Fingerprint → Session → Attack Surface
    ↓
ProjectStore baseline ←── incremental diff (optional)
    ↓
Scan Planning Engine → task queue (priority + lane + retest boost)
    ↓
Plugin Execution Engine
    ├─ HTTP lane (parallel)
    └─ Browser lane (limited) + residual surfaceChecks
    ↓
VerificationEngine.process()
    ↓
EvidenceEngine (verified C/H/M/L only)
    ↓
RiskEngine.evaluateVerified()
    ↓
ReportingEngine
    ↓
Project Store (+ baseline sidecar for next incremental scan)
```

Phased migration plan: [Architecture-V2-Phases.md](./Architecture-V2-Phases.md).  
Completion audit: [Architecture-V2-Verification.md](./Architecture-V2-Verification.md) — **all 6 phases verified complete**.

Each layer is independently testable and injected through a lightweight DI container (`src/platform/core/di/container.ts`).

## Folder structure (current v2)

```
config/                 # default + environment profiles + safety policy
docs/                   # architecture & guides (+ session.md, V2 verification)
modules/                # security plugins (auto-register)
public/                 # UI + dashboard
src/
  platform/
    api/
    bootstrap.ts        # DI wiring for all v2 engines
    core/
      knowledge/        # KnowledgeRepository + ScanEventBus (Phase 2)
      types/ di/ logging/ config/ standards/ safety/
    engines/
      browser/          # Phase 1
      session/          # Phase 1
      discovery/        # Phase 1
      planning/         # Phase 3
      execution/        # Phase 4
      verification/     # Phase 5
      evidence/         # Phase 5 (EvidenceEngine + ScreenshotEvidence)
      risk/ reporting/ fingerprint/ attack-surface/
      recon/ auth/      # legacy implementations behind Discovery/Session
      orchestrator/     # thin coordinator
      jobs/ knowledge/
    plugins/
    dashboard/          # ProjectStore + baseline (Phase 6)
  scanner/              # proven Playwright recon/probes (reused)
  report/               # HTML/PDF builders
tests/
data/                   # projects, scans, baselines
reports/
```

## Design patterns

| Pattern | Where |
|---------|--------|
| Dependency Injection | `bootstrap.ts` + `Container` |
| Plugin / Strategy | `SecurityPlugin` lifecycle (+ ExecutionEngine) |
| Facade | Thin `ScanOrchestrator` |
| Adapter | Discovery→Recon, Session→Auth, Evidence→Screenshots |
| Repository | `KnowledgeRepository` (in-scan) + `ProjectStore` / baseline |
| Pipeline | plan → execute → verify → evidence → risk → report |
| Event bus | `ScanEventBus` for stage / surface / finding events |

## Finding schema

Every finding includes title, description, severity, confidence, CVSS, OWASP/CWE/CAPEC mappings, affected URL/endpoint, evidence, optional HTTP request/response, impact, remediation, references, and test mode.

## Compatibility strategy

- v1 UI continues to call `POST /api/scan`
- Proven recon/probes remain in `src/scanner` and are reused (not discarded)
- Legacy `npm run start:legacy` still works
- New platform is default via `npm start` (tsx)

## Performance notes / bottlenecks

1. **Playwright launch** — dominant startup cost; consider browser reuse pool later
2. **Per-parameter probes** — capped by `safety.maxParameters`
3. **PDF generation** — second Chromium pass; can be made optional
4. **Duplicate plugin overlap** — orchestrator dedupes by CWE+severity+title
5. **Future**: worker threads / job queue (BullMQ/Redis) for multi-tenant scale

## False-positive reduction

- VerificationEngine requires evidence
- Confidence: Confirmed / Likely / Possible / Informational
- High/Critical with weak confidence are tempered
- Deduplication across plugins
- Passive vs active-safe clearly labeled

## Phase 1 hardening (implemented)

- Target policy (SSRF/private IP block)
- Secret redaction
- Job concurrency + cancel
- Mode enforcement
- Plugin vs surfaceChecks de-duplication
- Multi-signal verification confidence model
- Knowledge enrichment
- Tech fingerprinting
- Baseline compare API
- OpenAPI document

See [Architecture-Audit.md](Architecture-Audit.md).

## Roadmap (beyond v2 — optional)

OAuth/SAML adapters, durable job queue, browser pool, deeper GraphQL/WebSocket plugins, SSRF/XXE/SSTI modules, executive report templates, CI quality gates.  
*(Screenshot evidence pipeline and incremental baselines are already delivered in Phases 5–6.)*
