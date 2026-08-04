const fs = require('fs');
const path = require('path');
const p = path.join(__dirname, '..', 'src', 'scanner', 'probes.js');
let t = fs.readFileSync(p, 'utf8');

// Ensure path-param return uses bracket prop + string severity
const SEV = 'sev' + 'erity'; // split to avoid editor corruption
if (!t.includes("const SEV_KEY = 'severityity'")) {
  t = t.replace(
    'async function probePathParam(page, templateUrl, authHeader) {',
    `async function probePathParam(page, templateUrl, authHeader) {\n  const SEV_KEY = '${SEV}';`
  );
}

t = t.replace(
  /severity:\s*outSeverity,/,
  `[SEV_KEY]: outSeverity,`
);

// Auth return already uses cvss ternary; leave it.
fs.writeFileSync(p, t);
console.log('updated', t.includes('[SEV_KEY]: outSeverity'));
