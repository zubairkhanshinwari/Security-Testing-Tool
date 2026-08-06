# IDOR / Broken Access Control (BOLA)

Safe, **GET-only** Broken Object Level Authorization checks (CWE-639).

## What it does

- Discovers object-style paths (`/users/{id}`, `/orders/{id}`, …) and id-like query params
- Mutates numeric IDs to neighbors (`id±1`, `+10`, …) and uses a negative-control ID
- Flags:
  - **Anonymous** sensitive JSON (no auth)
  - **Cross-user**: Account B session reads Account A’s object (strongest)
  - **Horizontal**: same session, different IDs, different identity fields in JSON
- Never creates, updates, or deletes resources

## Best results

Provide **Account A** + **Account B** (same role) in the UI or CLI (`--username2` / `--password2`). Cross-user confirmation is the gold standard for BOLA.

## Types

Select **Insecure Direct Object Reference (IDOR)** and/or **Broken Access Control (BAC)**, or use **Select recommended** / **OWASP Top 10**.
