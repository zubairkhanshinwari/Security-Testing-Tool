# XSS plugin

Safe, non-destructive **reflected XSS** checks using alert-free markers.

- Probes query parameters from the attack surface, forms, and focus endpoints
- Does not execute `alert()` / browser XSS payloads that mutate state
- Owned security type: `xss` (residual surfaceChecks skip when this plugin runs)
