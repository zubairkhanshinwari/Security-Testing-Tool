import type { Finding } from '../../core/types/finding';
import { mappingsFor, cvssFor, STANDARD_LIBRARY } from '../../core/standards/mappings';

export type KnowledgeKey =
  | 'sqli'
  | 'nosqli'
  | 'xss'
  | 'headers'
  | 'cors'
  | 'info-disclosure'
  | 'idor'
  | 'csrf'
  | 'jwt'
  | 'generic';

const KNOWLEDGE: Record<
  KnowledgeKey,
  {
    technical: string;
    businessImpact: string;
    prerequisites: string[];
    remediation: string;
    secureCoding: string[];
    verificationSteps: string[];
    references: string[];
  }
> = {
  sqli: {
    technical:
      'Untrusted input is interpreted as SQL, allowing query logic manipulation.',
    businessImpact: 'Data breach, authentication bypass, fraud, regulatory exposure.',
    prerequisites: ['Injectable parameter reaches SQL query', 'Insufficient parameterization'],
    remediation: 'Use parameterized queries/ORM bind variables; least-privilege DB accounts.',
    secureCoding: [
      "db.query('SELECT * FROM users WHERE id = ?', [userId])",
      'Never concatenate user input into SQL strings.',
    ],
    verificationSteps: [
      'Replay with baseline vs true/false payloads',
      'Confirm differential or SQL error evidence',
      'Retest after parameterization fix',
    ],
    references: [
      'https://owasp.org/www-community/attacks/SQL_Injection',
      'https://cwe.mitre.org/data/definitions/89.html',
    ],
  },
  nosqli: {
    technical: 'NoSQL operators or regex are attacker-controlled in query objects.',
    businessImpact: 'Unauthorized data access, mass enumeration, auth bypass.',
    prerequisites: ['User input merged into Mongo/NoSQL query operators'],
    remediation: 'Allow-list fields; cast types; ban raw operator objects from clients.',
    secureCoding: [
      'Validate postal codes as strict strings/regex before query',
      'Use schema validation (Joi/Zod) to reject objects for string fields',
    ],
    verificationSteps: [
      'Compare .* vs ^x vs invalid regex responses',
      'Confirm authz still required after fix',
    ],
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection',
      'https://cwe.mitre.org/data/definitions/943.html',
    ],
  },
  xss: {
    technical: 'Untrusted data rendered into HTML/JS without context-aware encoding.',
    businessImpact: 'Session theft, account takeover, malware distribution.',
    prerequisites: ['Reflection or storage of attacker HTML/JS', 'Missing CSP'],
    remediation: 'Context-aware encoding; strict CSP; sanitize only when necessary.',
    secureCoding: ['Use framework auto-escaping; avoid innerHTML with untrusted data'],
    verificationSteps: ['Confirm payload reflection encoding', 'Validate CSP blocks inline script'],
    references: ['https://owasp.org/www-community/attacks/xss/', 'https://cwe.mitre.org/data/definitions/79.html'],
  },
  headers: {
    technical: 'Missing browser security headers reduce defense-in-depth.',
    businessImpact: 'Easier clickjacking/XSS impact and transport downgrade risk.',
    prerequisites: ['Responses omit CSP/HSTS/XFO/etc.'],
    remediation: 'Set CSP, HSTS, X-Content-Type-Options, frame protections, Referrer-Policy.',
    secureCoding: ["res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')"],
    verificationSteps: ['curl -I target and verify headers', 'Retest after reverse-proxy change'],
    references: ['https://owasp.org/www-project-secure-headers/'],
  },
  cors: {
    technical: 'Over-permissive CORS allows untrusted origins to read responses.',
    businessImpact: 'Cross-site data theft for authenticated APIs.',
    prerequisites: ['ACAO reflects arbitrary Origin or * with credentials'],
    remediation: 'Explicit origin allow-list; never combine * with credentials.',
    secureCoding: ['Validate Origin against allow-list before setting ACAO'],
    verificationSteps: ['Send evil Origin and confirm non-reflection'],
    references: ['https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'],
  },
  'info-disclosure': {
    technical: 'Sensitive files or verbose errors expose internals.',
    businessImpact: 'Accelerates further attacks; may leak credentials.',
    prerequisites: ['Misconfigured static hosting or verbose error middleware'],
    remediation: 'Block .env/.git/source maps in prod; generic error responses.',
    secureCoding: ['Never send stack traces to clients in production'],
    verificationSteps: ['Confirm sensitive paths return 404', 'Confirm errors are generic'],
    references: ['https://cwe.mitre.org/data/definitions/209.html'],
  },
  idor: {
    technical: 'Object references lack authorization checks.',
    businessImpact: 'Horizontal/vertical privilege escalation and data exposure.',
    prerequisites: ['Predictable IDs', 'Missing object-level authz'],
    remediation: 'Authorize every object access server-side (BOLA controls).',
    secureCoding: ['if (resource.ownerId !== req.user.id) return 403'],
    verificationSteps: ['Access neighbor IDs with victim token', 'Confirm 403'],
    references: ['https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'],
  },
  csrf: {
    technical: 'State-changing requests trust cookies without anti-CSRF controls.',
    businessImpact: 'Unauthorized actions as the victim user.',
    prerequisites: ['Cookie session auth', 'Missing SameSite/CSRF token'],
    remediation: 'Anti-CSRF tokens + SameSite=Lax/Strict + prefer Authorization headers.',
    secureCoding: ['Validate CSRF token on POST/PUT/DELETE'],
    verificationSteps: ['Cross-site form post without token should fail'],
    references: ['https://owasp.org/www-community/attacks/csrf'],
  },
  jwt: {
    technical: 'Weak JWT validation/algorithm/secret handling.',
    businessImpact: 'Impersonation and privilege escalation.',
    prerequisites: ['Accepts alg=none or weak secrets', 'No exp/aud checks'],
    remediation: 'Enforce algorithm allow-list, short TTL, audience/issuer checks.',
    secureCoding: ['jwt.verify(token, key, { algorithms: ["RS256"], audience, issuer })'],
    verificationSteps: ['Reject alg none', 'Reject expired tokens'],
    references: ['https://cwe.mitre.org/data/definitions/347.html'],
  },
  generic: {
    technical: 'Security control weakness identified during authorized testing.',
    businessImpact: 'Depends on exploitability and data sensitivity.',
    prerequisites: ['Application exposes affected control'],
    remediation: 'Follow OWASP ASVS guidance for the mapped control family.',
    secureCoding: ['Prefer secure defaults and deny-by-default authorization'],
    verificationSteps: ['Reproduce with recorded evidence', 'Retest after fix'],
    references: ['https://owasp.org/www-project-application-security-verification-standard/'],
  },
};

function inferKey(f: Finding): KnowledgeKey {
  const blob = `${f.pluginId} ${f.module} ${f.title} ${(f.mappings?.cwe || []).join(' ')}`.toLowerCase();
  if (blob.includes('nosql') || (f.mappings?.cwe || []).includes('CWE-943')) return 'nosqli';
  if (blob.includes('sql') || (f.mappings?.cwe || []).includes('CWE-89')) return 'sqli';
  if (blob.includes('xss') || (f.mappings?.cwe || []).includes('CWE-79')) return 'xss';
  if (blob.includes('cors')) return 'cors';
  if (blob.includes('header')) return 'headers';
  if (blob.includes('jwt')) return 'jwt';
  if (blob.includes('csrf')) return 'csrf';
  if (blob.includes('idor') || blob.includes('bola')) return 'idor';
  if (blob.includes('disclosure') || blob.includes('sensitive')) return 'info-disclosure';
  return 'generic';
}

/**
 * Knowledge Engine — enriches verified findings with standards + remediation guidance.
 * Does not decide vulnerability existence.
 */
export class KnowledgeEngine {
  enrich(findings: Finding[]): Finding[] {
    return findings.map((f) => {
      const key = inferKey(f);
      const kn = KNOWLEDGE[key];
      const mapped = mappingsFor(key === 'generic' ? 'headers' : key);
      const std = STANDARD_LIBRARY[key === 'generic' ? 'headers' : key];

      const mappings = {
        cwe: f.mappings?.cwe?.length ? f.mappings.cwe : mapped.cwe || [],
        owaspTop10: f.mappings?.owaspTop10?.length ? f.mappings.owaspTop10 : mapped.owaspTop10 || [],
        owaspApiTop10: f.mappings?.owaspApiTop10 || mapped.owaspApiTop10 || [],
        owaspAsvs: f.mappings?.owaspAsvs || mapped.owaspAsvs || [],
        capec: f.mappings?.capec || mapped.capec || [],
        mitreAttack: f.mappings?.mitreAttack || mapped.mitreAttack || [],
        nist80053: f.mappings?.nist80053 || mapped.nist80053 || [],
      };

      return {
        ...f,
        mappings,
        cvss: f.cvss || cvssFor(key === 'generic' ? 'headers' : key, f.severity) || std?.defaultCvss || null,
        impact: f.issueFound ? kn.businessImpact : f.impact,
        remediation: f.issueFound ? kn.remediation : f.remediation,
        references: [...new Set([...(f.references || []), ...kn.references])],
        knowledge: {
          technicalExplanation: kn.technical,
          businessImpact: kn.businessImpact,
          attackPrerequisites: kn.prerequisites,
          secureCodingExamples: kn.secureCoding,
          verificationSteps: kn.verificationSteps,
          riskExplanation: f.issueFound
            ? `${f.severity} severity with ${f.confidence} confidence based on collected evidence.`
            : 'No issue confirmed for this check.',
        },
      };
    });
  }
}
