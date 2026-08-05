# Regression dashboard

Compare the latest scan to the previous one and show **New / Fixed / Unchanged** findings.

## Where

- UI: `/dashboard.html` → open a project → **Regression (latest vs previous)**
- API: `GET /api/projects/:id` includes `baselineCompare`
- API: `GET /api/scans/compare?projectId=` or `?baselineId=&currentId=`

## Response shape

```json
{
  "ok": true,
  "newFindings": [],
  "fixed": [],
  "unchanged": [],
  "resolved": [],
  "persistent": [],
  "changedSeverity": [],
  "rows": [{ "delta": "New|Fixed|Unchanged|SeverityChanged", "title": "", "severity": "", "endpoint": "" }],
  "summary": { "newCount": 0, "fixedCount": 0, "unchangedCount": 0, "severityChangedCount": 0, "net": 0 }
}
```

`fixed` / `unchanged` are the team-ready names; `resolved` / `persistent` remain as legacy aliases.

## Matching

Findings are matched by a stable family key (plugin + CWE + normalized endpoint + title), so the same issue across scans is Unchanged even when internal ids differ.
