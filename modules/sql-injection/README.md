# SQL Injection Plugin

## Purpose
Detect SQL injection vulnerabilities using safe, non-destructive probes.

## Lifecycle
- `discover()` — select query/path parameters from attack surface
- `scan()` — send error/boolean/time payloads
- `verify()` — require SQL error markers or consistent boolean/time differentials
- `report()` — summary block for reporting engine
- `score()` — risk delta contribution

## Safety
No `DROP`, `DELETE`, or stacked destructive statements.
