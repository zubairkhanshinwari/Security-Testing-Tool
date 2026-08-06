# Local File Inclusion / Path Traversal

Safe, read-only checks for LFI and path traversal (CWE-22 / CWE-98).

## What it does

- Discovers file-like parameters (`file`, `path`, `page`, `include`, `download`, …) from the attack surface and common query shapes
- Sends non-destructive traversal / known-file probes (Unix `passwd`/`hosts`, Windows `win.ini`, URL-encoded variants, PHP `php://filter` read-only)
- Compares responses to a baseline; reports only when strong file signatures appear (soft markers alone are not enough)

## Modes

Requires **active-safe** (or authenticated). Skipped in passive mode.

## Types

Select **Local File Inclusion (LFI)** and/or **Path Traversal**, or use **Select recommended** / **OWASP Top 10** bundle.
