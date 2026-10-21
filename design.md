# SecureAssess Platform — UI Design Specification

> **Theme:** Deep black cyber/terminal interface based on reference layout (black theme, top URL input bar, and 3-column operational layout).
> **Rule:** Only real tool features and data defined in SecureAssess. No dummy text, no fake browser nodes, and no mock probe lists.

---

## 1. Visual Theme & Styling

- **Background:** Deep black (`#08090b` base, `#0f1115` panels, `#16181f` elevated inputs).
- **Borders & Dividers:** Dark slate (`#1e2229` subtle, `#2a303a` active).
- **Typography:** Monospace (`JetBrains Mono`, `Consolas`) for inputs, telemetry, and paths; clean Sans (`Inter`, system-ui) for labels and controls.
- **Accents:**
  - Blue (`#3b82f6` / `#38bdf8`) for primary triggers, links, and selections.
  - Green (`#22c55e`) for active status, recommended badges, and completed scans.
  - Amber (`#eab308`) for running stages, warnings, and medium risk.
  - Red (`#ef4444`) for errors, high/critical findings, and missing authorization.

---

## 2. Layout Structure

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ TOP BAR: [ Target URL Input ] [ Profile Select ] [ Authorized Checkbox ] [ START BTN ] │
├────────────────────────────┬─────────────────────────────┬─────────────────────────────┤
│ COLUMN 1                   │ COLUMN 2                    │ COLUMN 3                    │
│ SCOPE & AUTHENTICATION     │ SECURITY TESTING MODULES    │ EXECUTION, KPIS & REPORTS   │
├────────────────────────────┼─────────────────────────────┼─────────────────────────────┤
│ • Project Name             │ • Module Filters:           │ • Live Execution Stage      │
│ • Environment Select       │   - Recommended             │   (Stage name & message)    │
│ • OpenAPI / Swagger URL    │   - Available Scanners (19) │ • Background Scan Hint      │
│ • Focus Routes Textarea    │   - All Catalog (41)        │ • Error Box (if any)        │
│ • Scan Profile Hint        │   - Clear                   │ • Scan KPI Summary:         │
│ • Account A (Crawl Auth):  │ • Module Counter            │   - Findings Count          │
│   - Username & Password    │ • Dynamic Modules Catalog:  │   - Overall Risk            │
│ • Account B (IDOR Check):  │   - Injection Modules       │   - Security Score          │
│   - Username & Password    │   - Auth & Session Modules  │   - Tested Types Count      │
│ • Auth Guidance Notice     │   - API Security Modules    │ • Generated Reports:        │
│ • Incremental Scan Toggle  │   - Configuration Modules   │   - PDF, HTML, JSON,        │
│                            │   - Other & Bundle Modules  │     SARIF, CSV              │
│                            │   (Real /api/security-types)│ • Safety Policy Notice      │
└────────────────────────────┴─────────────────────────────┴─────────────────────────────┘
```

> **Flex & Height Architecture:** The 3 columns use CSS Grid with `align-items: stretch` and `height: 100%` on each column container (`.hud-column`) with internal vertical scrolling (`overflow-y: auto`), ensuring all three columns maintain strictly equal height across desktop viewports.
> **Dashboard Parity:** The dashboard interface (`dashboard.html`) shares the identical dark HUD design system, color tokens, and table/card architecture.

---

## 3. Top Command Bar

Contains the primary scan target input and action trigger:
1. **Tool Identity**: `SecureAssess // Web Security Assessment`
2. **Target URL Input (`#targetUrl`)**: URL input with protocol check (`http://` or `https://`).
3. **Scan Profile Dropdown (`#scanProfile`)**: Quick, Standard, Deep, OpenAPI-first, Focused.
4. **Authorization Toggle (`#authorized`)**: Mandatory written authorization confirmation.
5. **Start Action Button (`#startBtn`)**: `Start Assessment & Generate Report`.
6. **Navigation**: Links to `Dashboard` (`/dashboard.html`) and `CIS Linux Benchmark` (`/compliance.html`).

---

## 4. Column 1: Target Scope & Authentication

Contains the actual input parameters required by `src/platform/api/server.ts` (`POST /api/scan`):
1. **Target Scope**:
   - **Project Name (`#projectName`)**: e.g., "Web Security Assessment"
   - **Environment (`#environment`)**: Development, Staging, QA, Production (authorized only)
   - **OpenAPI / Swagger URL (`#openApiUrl`)**: URL to API specification for route discovery
   - **Focus Routes (`#focusEndpoints`)**: Seed routes for prioritized testing
   - **Profile Description (`#profileHint`)**: Dynamic explanation of active profile
2. **Authentication (Dual-Account BOLA/IDOR)**:
   - **Account A Credentials (`#username`, `#password`, `#togglePassword`)**: Primary session for crawl and authenticated probes.
   - **Account B Credentials (`#username2`, `#password2`)**: Secondary session for cross-user permission validation.
   - **Session Verification Notice**: Informs tester that cookies/tokens are validated before authenticated tests proceed.
3. **Scan Settings**:
   - **Incremental Baseline Checkbox (`#incremental`)**: Reuses project baseline and prioritizes newly detected endpoints and regressions.

---

## 5. Column 2: Security Testing Modules Catalog

Contains the full security catalog populated dynamically from the backend endpoint `/api/security-types`:
1. **Filter Controls**:
   - `Select recommended` (`#btnRecommended`): Pre-selected OWASP-aligned defaults.
   - `Select available scanners` (`#btnAvailable`): Active scanners with implemented plugins.
   - `Select all catalog` (`#btnAll`): Entire catalog.
   - `Clear` (`#btnNone`): Deselect all.
2. **Selection Counter (`#selectedCount`)**:
   - Displays real-time count: e.g., `23 of 41 selected · 26 types have scanners`.
3. **Dynamic Testing Types Container (`#typesBox`)**:
   - Categorized by groups defined in `src/scanner/securityTypes.js`:
     - **Injection**: SQLi, NoSQLi, XSS, Command Injection, SSTI, LDAP, XPath, XXE.
     - **Auth**: Broken Auth, BAC, IDOR, CSRF, JWT, OAuth, Session Mgmt, Cookie Security, Weak Password.
     - **API**: API Security, SSRF, RCE, File Upload, Path Traversal, LFI, RFI.
     - **Config**: Security Misconfig, Sensitive Data, HTTP Headers, CORS, Info Disclosure, Crypto.
     - **Other**: Open Redirect, Clickjacking, Rate Limiting, Business Logic, Race Condition, DoS, Subdomain Takeover, HTTP Smuggling, Cache Poisoning.
     - **Bundle**: OWASP Top 10 (2021) Bundle.
   - Real indicators: `Recommended`, `Available scanner`, `No scanner yet (tracking only)`.

---

## 6. Column 3: Execution, Live Progress, KPIs & Reports

Directly connects to scan execution, status polling (`GET /api/scan/:id`), and final report exports:
1. **Live Progress Box (`#statusBox`)**:
   - Stage Badge (`#stageText`): `STARTING`, `PREFLIGHT`, `CRAWL`, `PROBE`, `VERIFY`, `REPORT`, `DONE`.
   - Progress Message (`#msgText`): Live message from the orchestrator.
   - Background Link (`#bgHint`): Link to Dashboard while job continues in background.
2. **Error Box (`#errorBox`)**:
   - Displays preflight or scan execution errors from the API.
3. **Results & KPIs (`#resultBox`)**:
   - **Total Findings (`#kpiFindings`)**: Count of verified vulnerabilities.
   - **Overall Risk (`#kpiRisk`)**: Risk level (Critical, High, Medium, Low).
   - **Security Score (`#kpiScore`)**: Normalized score out of 100.
   - **Tested Types (`#kpiTypes`)**: Number of security types evaluated.
4. **Generated Reports**:
   - **PDF Report (`#pdfLink`)**: Executive shareable document.
   - **Interactive HTML (`#htmlLink`)**: Detailed technical assessment.
   - **Raw JSON (`#jsonLink`)**: Full machine-readable scan result.
   - **SARIF CI (`#sarifLink`)**: Static/dynamic analysis CI integration.
   - **CSV Export (`#csvLink`)**: Spreadsheet-friendly vulnerability list.
5. **Safety Principle Notice**:
   - Explicit confirmation of authorized testing and non-destructive methodologies.

---

## 7. Technical Documentation Report Design

The HTML report follows modern developer documentation site architecture (e.g. Stripe, MDN, GitBook) with full Cyber HUD dark theme parity:

1. **Sticky Left Navigation Sidebar**:
   - **Fixed Width**: 320px sticky navigation panel (`.doc-sidebar`).
   - **Search / Filter Bar**: Real-time interactive filter input (`#docSearch`) to instantly filter report sections and findings.
   - **Collapsible Topics (`<details class="doc-topic">`)**:
     - `01 Executive Summary` (collapsible subheadings: Overview, Parameters, Score Rationale)
     - `02 Assessment Scope` (collapsible subheadings: Target & Recon, Safety Controls, Coverage Honesty)
     - `03 Methodology` (collapsible subheadings: 5-Stage Pipeline, Playwright Automation)
     - `04 Overall Results` (collapsible subheadings: Severity Distribution)
     - `05 Summary Table` (Tested Modules Matrix)
     - `06 Finding Table` (Evaluated Checks Index)
     - `07 Charts & Visuals` (Severity Pie, Status Distribution, Module Coverage)
     - `08 Risk Matrix` (Likelihood &times; Impact Grid)
     - `09 Detailed Findings` (**Collapsible tree of individual findings** with severity badge chips)
     - `10 Recommendations` (Immediate Actions, High Priority Fixes, Coding Best Practices, Checklist)
     - `11 Appendix` (OWASP Standards, CWE References, Glossary)
   - **Active Scroll Tracking**: Highlights the active section/finding in the left sidebar as the user scrolls.

2. **Main Documentation Content Area**:
   - **Top Command Header**: Target URL, Environment badge, Risk rating, Score pill, and Print/Export trigger.
   - **Dark Theme Components**: Pitch-black background (`#08090b`), dark elevated cards (`#0f1115`), high-contrast dark tables, dark SVG charts, dark vulnerability finding cards with evidence tables and screenshot attachments.

---

## 8. Theme System (Light / Dark Mode Toggle)

The platform supports dynamic theme switching between a high-contrast Cyber Dark HUD and a clean Technical Light mode:

1. **Default State**:
   - **Dark Mode by Default**: Both first-time visits and unconfigured sessions default strictly to the dark theme (`data-theme="dark"`).
   - **Zero-Flicker Pre-loader**: An inline `<script>` in the `<head>` queries `localStorage.getItem('secureassess.theme')` before layout rendering to prevent any theme flash.

2. **Floating Toggle Button (`.theme-toggle-floating`)**:
   - **Position**: Floating fixed at the bottom-right corner of the screen (`position: fixed; bottom: 24px; right: 24px; z-index: 99999`).
   - **Aesthetics**: Circular glassmorphic FAB (44px &times; 44px) with subtle elevation shadow, 1px theme border, and hover lift/glow effects.
   - **Dynamic Iconography**: Displays a sun icon (`sunSvg`) when in dark mode (inviting switch to light), and a crescent moon icon (`moonSvg`) when in light mode (inviting switch to dark).

3. **Persistent Preference**:
   - Choice saved to browser `localStorage` under the key `'secureassess.theme'` (`'dark'` or `'light'`).

4. **Universal Coverage**:
   - Main Command Interface (`public/index.html`)
   - Real-time Assessment Dashboard (`public/dashboard.html`)
   - Documentation Security Reports (`src/report/htmlReport.js` & `reports/*.html`)

