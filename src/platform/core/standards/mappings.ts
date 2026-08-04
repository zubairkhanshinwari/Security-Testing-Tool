import type { CvssV4, Severity, StandardMappings } from '../types/finding';

/** Map common issue classes to international standards. */
export const STANDARD_LIBRARY: Record<string, StandardMappings & { defaultCvss?: CvssV4 }> = {
  'sqli': {
    cwe: ['CWE-89'],
    capec: ['CAPEC-66'],
    owaspTop10: ['A03:2021-Injection'],
    owaspApiTop10: ['API8:2023-Security Misconfiguration'],
    owaspAsvs: ['V5.3.4'],
    mitreAttack: ['T1190'],
    nist80053: ['SI-10', 'SI-15'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N',
      score: 9.3,
      severity: 'Critical',
    },
  },
  'nosqli': {
    cwe: ['CWE-943'],
    capec: ['CAPEC-66'],
    owaspTop10: ['A03:2021-Injection'],
    owaspApiTop10: ['API8:2023-Security Misconfiguration'],
    owaspAsvs: ['V5.3.4'],
    mitreAttack: ['T1190'],
    nist80053: ['SI-10'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N',
      score: 8.3,
      severity: 'High',
    },
  },
  'xss': {
    cwe: ['CWE-79'],
    capec: ['CAPEC-63'],
    owaspTop10: ['A03:2021-Injection'],
    owaspAsvs: ['V5.3.3'],
    mitreAttack: ['T1059.007'],
    nist80053: ['SI-10'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
      score: 5.1,
      severity: 'Medium',
    },
  },
  'headers': {
    cwe: ['CWE-693'],
    capec: ['CAPEC-116'],
    owaspTop10: ['A05:2021-Security Misconfiguration'],
    owaspAsvs: ['V14.4.1'],
    nist80053: ['SC-7', 'SC-8'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 6.9,
      severity: 'Medium',
    },
  },
  'cors': {
    cwe: ['CWE-942'],
    owaspTop10: ['A05:2021-Security Misconfiguration'],
    owaspApiTop10: ['API8:2023-Security Misconfiguration'],
    nist80053: ['AC-4'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
      score: 6.9,
      severity: 'Medium',
    },
  },
  'info-disclosure': {
    cwe: ['CWE-209'],
    owaspTop10: ['A01:2021-Broken Access Control', 'A04:2021-Insecure Design'],
    owaspAsvs: ['V14.3.2'],
    nist80053: ['SI-11'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 6.9,
      severity: 'Medium',
    },
  },
  'idor': {
    cwe: ['CWE-639'],
    capec: ['CAPEC-87'],
    owaspTop10: ['A01:2021-Broken Access Control'],
    owaspApiTop10: ['API1:2023-Broken Object Level Authorization'],
    owaspAsvs: ['V4.1.1'],
    nist80053: ['AC-3', 'AC-6'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 7.1,
      severity: 'High',
    },
  },
  'jwt': {
    cwe: ['CWE-347'],
    owaspTop10: ['A02:2021-Cryptographic Failures'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 8.7,
      severity: 'High',
    },
  },
  'csrf': {
    cwe: ['CWE-352'],
    owaspTop10: ['A01:2021-Broken Access Control'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N',
      score: 5.1,
      severity: 'Medium',
    },
  },
  'open-redirect': {
    cwe: ['CWE-601'],
    owaspTop10: ['A01:2021-Broken Access Control'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N',
      score: 5.1,
      severity: 'Medium',
    },
  },
  'ssrf': {
    cwe: ['CWE-918'],
    owaspTop10: ['A10:2021-Server-Side Request Forgery'],
    owaspApiTop10: ['API7:2023-Server Side Request Forgery'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 8.7,
      severity: 'High',
    },
  },
};

export function mappingsFor(key: string): StandardMappings {
  const m = STANDARD_LIBRARY[key];
  if (!m) return { cwe: [] };
  const { defaultCvss: _d, ...rest } = m as any;
  return rest;
}

export function cvssFor(key: string, severity?: Severity): CvssV4 | null {
  const m = STANDARD_LIBRARY[key];
  if (!m?.defaultCvss) return null;
  if (severity && m.defaultCvss.severity !== severity) {
    return { ...m.defaultCvss, severity };
  }
  return m.defaultCvss;
}
