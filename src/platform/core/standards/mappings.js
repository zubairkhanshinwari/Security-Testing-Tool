/** CommonJS mirror for runtime require from bridges/plugins. */
const STANDARD_LIBRARY = {
  sqli: {
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
  nosqli: {
    cwe: ['CWE-943'],
    capec: ['CAPEC-66'],
    owaspTop10: ['A03:2021-Injection'],
    owaspAsvs: ['V5.3.4'],
    mitreAttack: ['T1190'],
    nist80053: ['SI-10'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N',
      score: 8.3,
      severity: 'High',
    },
  },
  xss: {
    cwe: ['CWE-79'],
    capec: ['CAPEC-63'],
    owaspTop10: ['A03:2021-Injection'],
    owaspAsvs: ['V5.3.3'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
      score: 5.1,
      severity: 'Medium',
    },
  },
  headers: {
    cwe: ['CWE-693'],
    owaspTop10: ['A05:2021-Security Misconfiguration'],
    owaspAsvs: ['V14.4.1'],
    nist80053: ['SC-7', 'SC-8'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 6.9,
      severity: 'Medium',
    },
  },
  cors: {
    cwe: ['CWE-942'],
    owaspTop10: ['A05:2021-Security Misconfiguration'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
      score: 6.9,
      severity: 'Medium',
    },
  },
  'info-disclosure': {
    cwe: ['CWE-209'],
    owaspTop10: ['A04:2021-Insecure Design'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 6.9,
      severity: 'Medium',
    },
  },
  idor: {
    cwe: ['CWE-639'],
    owaspTop10: ['A01:2021-Broken Access Control'],
    owaspApiTop10: ['API1:2023-Broken Object Level Authorization'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 7.1,
      severity: 'High',
    },
  },
  jwt: {
    cwe: ['CWE-347'],
    owaspTop10: ['A02:2021-Cryptographic Failures'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 8.7,
      severity: 'High',
    },
  },
  csrf: {
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
  ssrf: {
    cwe: ['CWE-918'],
    owaspTop10: ['A10:2021-Server-Side Request Forgery'],
    owaspApiTop10: ['API7:2023-Server Side Request Forgery'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 8.7,
      severity: 'High',
    },
  },
  ssti: {
    cwe: ['CWE-1336', 'CWE-94'],
    owaspTop10: ['A03:2021-Injection'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N',
      score: 9.3,
      severity: 'Critical',
    },
  },
  lfi: {
    cwe: ['CWE-22', 'CWE-98'],
    owaspTop10: ['A01:2021-Broken Access Control'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 8.7,
      severity: 'High',
    },
  },
  'cookie-security': {
    cwe: ['CWE-614', 'CWE-1004'],
    owaspTop10: ['A05:2021-Security Misconfiguration'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 6.9,
      severity: 'Medium',
    },
  },
  'session-mgmt': {
    cwe: ['CWE-384', 'CWE-613'],
    owaspTop10: ['A07:2021-Identification and Authentication Failures'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 6.9,
      severity: 'Medium',
    },
  },
  'weak-password': {
    cwe: ['CWE-521'],
    owaspTop10: ['A07:2021-Identification and Authentication Failures'],
    owaspAsvs: ['V2.1.1'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 5.3,
      severity: 'Medium',
    },
  },
  'file-upload': {
    cwe: ['CWE-434'],
    owaspTop10: ['A04:2021-Insecure Design'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
      score: 5.3,
      severity: 'Medium',
    },
  },
  'rate-limiting': {
    cwe: ['CWE-307'],
    owaspTop10: ['A07:2021-Identification and Authentication Failures'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
      score: 5.3,
      severity: 'Medium',
    },
  },
  clickjacking: {
    cwe: ['CWE-1021', 'CWE-693'],
    owaspTop10: ['A05:2021-Security Misconfiguration'],
    owaspAsvs: ['V14.4.3'],
    defaultCvss: {
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N',
      score: 5.1,
      severity: 'Medium',
    },
  },
};

function mappingsFor(key) {
  const m = STANDARD_LIBRARY[key];
  if (!m) return { cwe: [] };
  const { defaultCvss, ...rest } = m;
  return rest;
}

function cvssFor(key, severity) {
  const m = STANDARD_LIBRARY[key];
  if (!m?.defaultCvss) return null;
  if (severity && m.defaultCvss.severity !== severity) {
    return { ...m.defaultCvss, severity };
  }
  return m.defaultCvss;
}

module.exports = { STANDARD_LIBRARY, mappingsFor, cvssFor };
