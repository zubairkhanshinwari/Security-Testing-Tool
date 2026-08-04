# IDOR / BAC plugin

Safe, **GET-only** Broken Object Level Authorization (BOLA/IDOR) checks.

- Probes object-style paths and `id`-like query parameters
- Looks for sensitive JSON fields on HTTP 200 without authorization failure
- Never creates, updates, or deletes resources
