/**
 * Security testing catalog.
 * `recommended: true` = pre-selected defaults for typical web apps (OWASP-aligned).
 */
const SECURITY_TYPES = [
  { id: 'sqli', name: 'SQL Injection (SQLi)', description: 'Inject SQL into inputs to access or modify database data.', example: "' OR 1=1 --", recommended: true, group: 'Injection' },
  { id: 'nosqli', name: 'NoSQL Injection', description: 'Attack MongoDB/CouchDB/Firebase-style query operators.', example: '{"$ne": null}', recommended: true, group: 'Injection' },
  { id: 'xss', name: 'Cross-Site Scripting (XSS)', description: 'Inject malicious JavaScript into a web page.', example: '<script>alert(1)</script>', recommended: true, group: 'Injection' },
  { id: 'command_injection', name: 'Command Injection', description: 'Execute OS commands through application input.', example: '; ls -la', recommended: false, group: 'Injection' },
  { id: 'ssti', name: 'Template Injection (SSTI)', description: 'Inject code into server-side templates.', example: '{{7*7}}', recommended: false, group: 'Injection' },
  { id: 'ldap', name: 'LDAP Injection', description: 'Manipulate LDAP queries.', example: 'Login bypass', recommended: false, group: 'Injection' },
  { id: 'xpath', name: 'XPath Injection', description: 'Manipulate XPath queries.', example: 'Authentication bypass', recommended: false, group: 'Injection' },
  { id: 'xxe', name: 'XML External Entity (XXE)', description: 'Exploit insecure XML parsers.', example: 'Read local files', recommended: false, group: 'Injection' },

  { id: 'broken_auth', name: 'Broken Authentication', description: 'Test login, session, password reset, MFA.', example: 'Session fixation, weak passwords', recommended: true, group: 'Auth' },
  { id: 'bac', name: 'Broken Access Control (BAC)', description: 'Users must not access unauthorized resources.', example: "Access another user's order", recommended: true, group: 'Auth' },
  { id: 'idor', name: 'Insecure Direct Object Reference (IDOR)', description: 'Access objects by modifying IDs.', example: '/api/users/1002', recommended: true, group: 'Auth' },
  { id: 'csrf', name: 'Cross-Site Request Forgery (CSRF)', description: 'Force authenticated users into unwanted actions.', example: 'Password change without consent', recommended: true, group: 'Auth' },
  { id: 'jwt', name: 'JWT Security Testing', description: 'Validate JSON Web Tokens.', example: 'Weak signing algorithm', recommended: true, group: 'Auth' },
  { id: 'oauth', name: 'OAuth/OpenID Testing', description: 'Verify authentication flows.', example: 'Auth code manipulation', recommended: false, group: 'Auth' },
  { id: 'session_mgmt', name: 'Session Management Testing', description: 'Validate session expiration and cookies.', example: 'Session valid after logout', recommended: true, group: 'Auth' },
  { id: 'cookie_security', name: 'Cookie Security Testing', description: 'Verify HttpOnly, Secure, SameSite flags.', example: 'Missing Secure flag', recommended: true, group: 'Auth' },
  { id: 'weak_password', name: 'Weak Password Policy', description: 'Test password complexity and lockout.', example: 'Password: 123456', recommended: false, group: 'Auth' },

  { id: 'api_security', name: 'API Security Testing', description: 'REST/GraphQL auth and validation issues.', example: 'Broken object-level authorization', recommended: true, group: 'API' },
  { id: 'ssrf', name: 'Server-Side Request Forgery (SSRF)', description: 'Force server to make internal requests.', example: 'Cloud metadata access', recommended: true, group: 'API' },
  { id: 'rce', name: 'Remote Code Execution (RCE)', description: 'Execute arbitrary code on the server.', example: 'Malicious upload', recommended: false, group: 'API' },
  { id: 'file_upload', name: 'File Upload Vulnerability', description: 'Upload malicious files.', example: 'PHP web shell', recommended: false, group: 'API' },
  { id: 'path_traversal', name: 'Path Traversal', description: 'Access restricted files/directories.', example: '../../../etc/passwd', recommended: true, group: 'API' },
  { id: 'lfi', name: 'Local File Inclusion (LFI)', description: 'Include local files on the server.', example: 'Read config files', recommended: true, group: 'API' },
  { id: 'rfi', name: 'Remote File Inclusion (RFI)', description: 'Include remote malicious files.', example: 'Execute external code', recommended: false, group: 'API' },

  { id: 'security_misconfig', name: 'Security Misconfiguration', description: 'Insecure server/app settings.', example: 'Directory listing enabled', recommended: true, group: 'Config' },
  { id: 'sensitive_data', name: 'Sensitive Data Exposure', description: 'Encryption and secure storage checks.', example: 'Plain-text passwords', recommended: true, group: 'Config' },
  { id: 'http_headers', name: 'HTTP Header Security', description: 'Verify security headers.', example: 'Missing CSP or HSTS', recommended: true, group: 'Config' },
  { id: 'cors', name: 'CORS Misconfiguration', description: 'Test cross-origin resource sharing.', example: 'Access-Control-Allow-Origin: *', recommended: true, group: 'Config' },
  { id: 'info_disclosure', name: 'Information Disclosure', description: 'Exposed secrets or debug information.', example: '.env accessible', recommended: true, group: 'Config' },
  { id: 'crypto', name: 'Cryptographic Testing', description: 'Encryption algorithms and key management.', example: 'MD5 password hashing', recommended: false, group: 'Config' },

  { id: 'open_redirect', name: 'Open Redirect', description: 'Redirect users to malicious sites.', example: 'redirect=https://evil.com', recommended: true, group: 'Other' },
  { id: 'clickjacking', name: 'Clickjacking', description: 'Detect missing X-Frame-Options / CSP frame-ancestors (UI redressing).', example: 'Page embeddable in iframe', recommended: true, group: 'Other' },
  { id: 'rate_limiting', name: 'Rate Limiting Testing', description: 'Brute-force / abuse protection.', example: 'Unlimited login attempts', recommended: true, group: 'Other' },
  { id: 'business_logic', name: 'Business Logic Testing', description: 'Flaws in workflows.', example: 'Reuse coupon', recommended: false, group: 'Other' },
  { id: 'race', name: 'Race Condition Testing', description: 'Simultaneous requests.', example: 'Double payment', recommended: false, group: 'Other' },
  { id: 'dos', name: 'Denial of Service (DoS)', description: 'Resilience under load (safe checks only).', example: 'Flood requests', recommended: false, group: 'Other' },
  { id: 'subdomain_takeover', name: 'Subdomain Takeover', description: 'Dangling DNS records.', example: 'Unclaimed cloud resource', recommended: false, group: 'Other' },
  { id: 'http_smuggling', name: 'HTTP Request Smuggling', description: 'Proxy/server parsing differences.', example: 'CL.TE attack', recommended: false, group: 'Other' },
  { id: 'response_splitting', name: 'HTTP Response Splitting', description: 'Inject malicious headers.', example: 'CRLF injection', recommended: false, group: 'Other' },
  { id: 'cache_poisoning', name: 'Cache Poisoning', description: 'Manipulate cached responses.', example: 'Malicious cached content', recommended: false, group: 'Other' },
  { id: 'owasp_top10', name: 'OWASP Top 10 (2021) Bundle', description: 'Run the highest-priority OWASP Top 10 coverage set.', example: 'BAC, Injection, SSRF, Misconfig…', recommended: true, group: 'Bundle' },
];

const DEFAULT_SELECTED = SECURITY_TYPES.filter((t) => t.recommended).map((t) => t.id);

/** Expand bundles into concrete module ids */
function expandSecurityTypes(selected = []) {
  const set = new Set(selected);
  if (set.has('owasp_top10')) {
    [
      'bac',
      'sensitive_data',
      'sqli',
      'nosqli',
      'command_injection',
      'lfi',
      'path_traversal',
      'security_misconfig',
      'broken_auth',
      'ssrf',
      'info_disclosure',
      'http_headers',
      'cors',
      'jwt',
      'api_security',
      'idor',
      'xss',
      'csrf',
      'clickjacking',
    ].forEach((id) => set.add(id));
  }
  return [...set];
}

function isSelected(selected, id) {
  const expanded = expandSecurityTypes(selected);
  return expanded.includes(id);
}

module.exports = {
  SECURITY_TYPES,
  DEFAULT_SELECTED,
  expandSecurityTypes,
  isSelected,
};
