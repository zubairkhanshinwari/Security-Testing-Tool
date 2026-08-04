# API Documentation

Base URL: `http://localhost:3847`

## Health

`GET /api/health`

## Security types (v1 compatible)

`GET /api/security-types`

## Plugins

`GET /api/plugins`

## Start scan (v1 compatible + extensions)

`POST /api/scan`

```json
{
  "targetUrl": "https://dev.example.com",
  "projectName": "Dev Assessment",
  "projectId": "optional-uuid",
  "environment": "Development",
  "testerName": "Analyst",
  "username": "optional",
  "password": "optional",
  "apiKey": "optional",
  "authHeader": "optional",
  "securityTypes": ["sqli", "nosqli", "http_headers"],
  "pluginIds": ["sql-injection"],
  "mode": "active-safe",
  "authorized": true
}
```

Response:

```json
{ "jobId": "job-…", "status": "running", "projectId": "…" }
```

## Job status

`GET /api/scan/:jobId`

Completed payload includes `stats`, `meta`, `risk`, and `files` (`html`, `pdf`, `json`, `sarif`, `csv`, `junit`).

## Projects dashboard

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/projects` | List projects |
| POST | `/api/projects` | Create `{ name, targetUrl }` |
| GET | `/api/projects/:id` | Detail + trends + regression |
| DELETE | `/api/projects/:id` | Delete project + its scan history |
| GET | `/api/scans` | List scans (`?projectId=`) |
| GET | `/api/scans/:id` | Scan meta + result |

## Authorization

All scan operations require `authorized: true`. Requests without it return HTTP 400.
