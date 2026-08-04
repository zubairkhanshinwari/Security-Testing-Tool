const fs = require('fs');
const path = require('path');
const p = path.join(__dirname, '..', 'src', 'scanner', 'probes.js');
let t = fs.readFileSync(p, 'utf8');

const re =
  /return \{\s*endpoint: templateUrl,\s*method: 'GET',\s*parameter: param,\s*inputType: 'Path',\s*authRequired: Boolean\(authHeader\),\s*issueFound: issue,\s*severity:\s*result\.sever[a-z]*,\s*confidence: issue \? 'Medium' : 'High',\s*techniques: result\.techniques,\s*title: result\.title,\s*description: result\.description,\s*cwe: result\.cwe,\s*owasp: result\.owasp,\s*cvss: result\.cvss,\s*baseline,\s*evidence: evidence\.slice\(0, 8\),\s*status: issue \? 'Confirmed' : 'Pass',\s*\};/;

const neu = `let outSeverity = 'Informational';
  if (issue) {
    if (result.cvss >= 7.5) outSeverity = 'High';
    else if (result.cvss >= 5) outSeverity = 'Medium';
    else if (result.cvss) outSeverity = 'Low';
    else outSeverity = 'Medium';
  }

  return {
    endpoint: templateUrl,
    method: 'GET',
    parameter: param,
    inputType: 'Path',
    authRequired: Boolean(authHeader),
    issueFound: issue,
    severity: outSeverity,
    confidence: issue ? 'Medium' : 'High',
    techniques: result.techniques,
    title: result.title,
    description: result.description,
    cwe: result.cwe,
    owasp: result.owasp,
    cvss: result.cvss,
    baseline,
    evidence: evidence.slice(0, 8),
    status: issue ? 'Confirmed' : 'Pass',
  };`;

if (!re.test(t)) {
  console.error('path return block not found');
  process.exit(1);
}
t = t.replace(re, neu);

const authRe =
  /issueFound: issue,\s*severity:\s*finding\.sever[a-z]*,\s*confidence: issue \? 'High' : 'High',/;
const authNeu = `issueFound: issue,
    severity: issue
      ? finding.cvss >= 9
        ? 'Critical'
        : finding.cvss >= 7
          ? 'High'
          : finding.cvss >= 5
            ? 'Medium'
            : 'Low'
      : 'Informational',
    confidence: issue ? 'High' : 'High',`;

if (!authRe.test(t)) {
  console.error('auth return severity not found');
  process.exit(1);
}
t = t.replace(authRe, authNeu);

fs.writeFileSync(p, t);
console.log('patched probes.js');
