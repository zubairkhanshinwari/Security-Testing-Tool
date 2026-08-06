/**
 * Short (2–3 sentence) attacker / business impact blurbs for report consumers.
 * Explains effect on data, users, and operations — not exploit steps.
 */

const NARRATIVES = {
  sqli:
    'An attacker who can change SQL logic may read, change, or delete database records your application trusts. That can expose customer or business data, bypass login, and create fraudulent activity. Downstream effects include regulatory exposure, trust loss, and costly incident response.',
  nosqli:
    'An attacker who controls NoSQL operators or regex filters can broaden queries beyond the intended record set and pull large volumes of listings or user-linked data. That enables mass scraping, competitive intelligence theft, and privacy exposure without needing a normal search workflow. It can also stress the database and increase infrastructure cost.',
  xss:
    'An attacker who runs script in a victim’s browser can steal session tokens or trick users into actions they did not intend. That leads to account takeover, unauthorized changes to listings or profiles, and malware or phishing overlays on your brand. Customer trust and support load are hit even when the database itself is not directly dumped.',
  ssti:
    'If server-side templates evaluate attacker input, the attacker may execute code in the application process. That can expose secrets, databases, and internal services, or take the site offline. Treat confirmed SSTI as a full-compromise risk to data and operations until proven otherwise.',
  headers:
    'Missing browser security headers do not dump your database by themselves, but they make other attacks easier to succeed. Without CSP or frame protections, stolen sessions and clickjacking become more likely; without HSTS, users on hostile networks face higher token-theft risk. The business cost is higher breach likelihood and weaker defense-in-depth.',
  cors:
    'Over-permissive CORS lets a malicious website read API responses using a victim’s browser session. That can leak account, listing, or payment-related JSON that should stay same-origin. The result is silent data theft and possible account abuse without the user noticing a classic “hacked website” defacement.',
  'info-disclosure':
    'Exposed source maps, config files, or verbose errors help attackers map your APIs, libraries, and internal paths faster. That shortens time-to-exploit for the next real vulnerability and may leak credentials or keys if mis-hosted. Business impact is higher breach probability and harder-to-hide architecture details.',
  idor:
    'Broken object-level access lets one user read or change another user’s objects by swapping identifiers. For a marketplace this can mean leaking private listings, contact details, messages, or deal data across accounts. That damages trust, creates privacy incidents, and can enable fraud between parties on the platform.',
  csrf:
    'Without anti-CSRF controls, a victim who is already logged in can be tricked into submitting state-changing requests from another site. Attackers may change profile settings, trigger ownership-like actions, or alter listings under the victim’s identity. The business impact is unauthorized actions attributed to real users.',
  jwt:
    'Weak or very long-lived JWTs mean a stolen token can keep working long after a password change or suspicious login. Attackers can keep acting as that user—viewing data, changing records, or impersonating staff—until expiry or revocation. Incident response becomes slower and account takeover windows grow.',
  cookie:
    'Cookies missing Secure/HttpOnly/SameSite flags are easier to steal or misuse on mixed-content or cross-site scenarios. If those cookies are session-related, attackers can hijack accounts; if only analytics, impact is lower but still weakens transport hygiene. Prioritize fixing authentication cookies first to protect customer accounts.',
  session:
    'Weak session handling (no rotation, long idle lifetime, or sessions surviving logout) lets stolen cookies remain useful. Attackers can reuse a captured session to access the account and its data after the user thinks they are safe. That increases account takeover risk and complicates containment after a phishing or malware event.',
  ssrf:
    'Server-side request forgery can make your servers call internal URLs or cloud metadata on the attacker’s behalf. That may expose internal services, credentials, or private network data that are never meant to be internet-facing. Business impact includes secret leakage and a foothold into infrastructure.',
  lfi:
    'Local file inclusion or path traversal can let attackers read files from the server filesystem. That may expose source code, configuration, and secrets that unlock broader access to data stores. The business risk is credential theft and a path to larger breaches.',
  'open-redirect':
    'Open redirects let attackers bounce users through your trusted domain to a phishing site. Victims are more likely to enter passwords or payment details because the first click looked legitimate. Business impact is credential theft, brand abuse, and support/fraud costs.',
  clickjacking:
    'Without frame protections, attackers can overlay your real pages inside a hidden iframe and trick users into clicking actions they cannot see. That can change settings, approve transfers, or perform other authenticated actions under the victim’s session. Business impact is unauthorized user actions, fraud, and eroded trust in your UI.',
  generic:
    'This weakness can increase the chance that attackers access data, abuse accounts, or disrupt normal operations, depending on where it sits in the app. Even “supporting” issues often make a later breach cheaper and faster. Remediate according to severity and whether authenticated or sensitive data is in reach.',
};

function isGenericBoilerplate(text) {
  const t = String(text || '').toLowerCase();
  return (
    t.includes('successful injection or information leakage can expose data') ||
    t.includes('may increase application risk depending on exploitability') ||
    t.includes('depends on exploitability and data sensitivity') ||
    t === 'unauthorized data access, mass enumeration, auth bypass.' ||
    t === 'data breach, authentication bypass, fraud, regulatory exposure.'
  );
}

function inferImpactKey(finding) {
  const blob = `${finding.pluginId || ''} ${finding.module || ''} ${finding.title || ''} ${(finding.mappings?.cwe || finding.cwe || []).join(' ')}`.toLowerCase();
  if (blob.includes('nosql') || (finding.mappings?.cwe || []).includes('CWE-943')) return 'nosqli';
  if (blob.includes('ssti') || blob.includes('template') || (finding.mappings?.cwe || []).includes('CWE-1336')) return 'ssti';
  if (blob.includes('sql') || (finding.mappings?.cwe || []).includes('CWE-89')) return 'sqli';
  if (blob.includes('xss') || (finding.mappings?.cwe || []).includes('CWE-79')) return 'xss';
  if (blob.includes('cors')) return 'cors';
  if (blob.includes('clickjack') || blob.includes('frame-ancestors') || blob.includes('x-frame')) return 'clickjacking';
  if (blob.includes('header')) return 'headers';
  if (blob.includes('jwt')) return 'jwt';
  if (blob.includes('csrf')) return 'csrf';
  if (blob.includes('idor') || blob.includes('bola') || blob.includes('access control')) return 'idor';
  if (blob.includes('cookie')) return 'cookie';
  if (blob.includes('session')) return 'session';
  if (blob.includes('ssrf')) return 'ssrf';
  if (blob.includes('lfi') || blob.includes('path traversal') || blob.includes('traversal')) return 'lfi';
  if (blob.includes('redirect')) return 'open-redirect';
  if (blob.includes('password') || blob.includes('weak-password')) return 'generic';
  if (blob.includes('upload') || blob.includes('file-upload')) return 'generic';
  if (blob.includes('rate')) return 'generic';
  if (blob.includes('disclosure') || blob.includes('sensitive') || blob.includes('.map')) return 'info-disclosure';
  return 'generic';
}

function refineBusinessImpact(key, finding) {
  const title = `${finding.title || ''} ${finding.description || ''}`.toLowerCase();
  let base = NARRATIVES[key] || NARRATIVES.generic;

  if (key === 'nosqli' && (title.includes('regex') || title.includes('postal'))) {
    base =
      'Attackers can turn a postal-code (or similar) filter into a broad database query and pull large sets of listing and address data. That enables bulk scraping and competitive or privacy-sensitive data exposure without using the product as intended. Public or weakly protected APIs amplify the blast radius because no insider account is required.';
  }
  if (key === 'jwt' && (title.includes('long-lived') || title.includes('exp') || title.includes('1 year'))) {
    base =
      'A stolen login token can remain valid for an extremely long time, so one leak keeps giving access to that user’s data and actions. Password resets may not end the session if tokens are not revoked. For a brokerage platform this means prolonged impersonation risk for agents and customers.';
  }
  if (key === 'info-disclosure' && (title.includes('.map') || title.includes('source map'))) {
    base =
      'Public JavaScript source maps reveal original frontend code, API shapes, and internal naming that attackers use to find the next flaw faster. This is rarely a direct customer-data dump, but it lowers the cost of targeting your product. Blocking maps in production reduces that reconnaissance advantage.';
  }
  if (key === 'cookie' && (title.includes('_ga') || title.includes('analytics') || title.includes('_fbp') || title.includes('_gid'))) {
    base =
      'These cookies appear to be analytics/marketing tags missing the Secure flag, so impact is usually lower than a stolen session cookie. The main risk is weaker transport hygiene and possible leakage of tracking identifiers on non-HTTPS contexts. Still fix session cookies first if any auth cookie shares the same weakness.';
  }
  if (key === 'ssti' && (title.includes('possible') || title.includes('tempered') || title.includes('precision'))) {
    base =
      'If confirmed, template injection can let attackers run code on the server and reach secrets or data stores—an extreme business outage and breach scenario. This finding is only Possible until stronger evidence is collected, so verify quickly to avoid either a missed RCE or unnecessary panic. Until cleared, treat login/signup input paths as high-priority review items.';
  }

  const existing = String(finding.impact || '').trim();
  if (existing.length >= 120 && !isGenericBoilerplate(existing)) {
    return existing;
  }
  return base;
}

function resolveBusinessImpact(finding) {
  if (!finding?.issueFound) return 'N/A — no issue confirmed for this check.';
  const key = inferImpactKey(finding);
  return refineBusinessImpact(key, finding);
}

module.exports = {
  NARRATIVES,
  inferImpactKey,
  refineBusinessImpact,
  resolveBusinessImpact,
  isGenericBoilerplate,
};
