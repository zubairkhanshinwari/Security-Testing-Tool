# Security Policy

SecureAssess is a DAST tool. This policy covers **vulnerabilities in SecureAssess itself** (the platform, CLI, dashboard, reporters, and plugins), not findings produced when scanning a third-party application.

## Supported versions

| Version | Supported |
|---------|-----------|
| `2.x` (latest on the default branch) | Yes |
| Older / untagged forks | Best effort |

## How to report a vulnerability

**Preferred:** use [GitHub Private Vulnerability Reporting](https://github.com/zubairkhanshinwari/Security-Testing-Tool/security/advisories/new) on this repository (Security → Report a vulnerability).

**Also accepted:** email **zubairkhanlkl8338@gmail.com** with subject `[SecureAssess Security]`.

Please include:

- Affected version / commit (if known)
- Steps to reproduce
- Impact (e.g. secret leakage, unauthorized scan start, path traversal in reports)
- Whether a fix or workaround is already known

**Do not** open a public GitHub Issue for security-sensitive reports.  
**Do not** attach real customer scan reports, credentials, or session tokens.

## Out of scope

- Vulnerability findings against apps you scanned with SecureAssess (report those to the app owner)
- Issues that require destructive payloads, DoS, or exploit weaponization in this repository
- Support / feature requests (use normal Issues)

## Response expectations

- Acknowledgement within **72 hours** when possible
- Coordinated disclosure: please allow time to patch before public discussion
- Credit: we are happy to acknowledge reporters who want credit once a fix is released

## Authorized use reminder

SecureAssess must only be used against systems you own or are explicitly authorized to test. Misuse of the tool against third parties is not covered by this policy and may be illegal.
