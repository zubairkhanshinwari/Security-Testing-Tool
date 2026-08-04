const fs = require('fs');
const path = require('path');
const p = path.join(__dirname, '..', 'src', 'scanner', 'probes.js');
let t = fs.readFileSync(p, 'utf8');
const w = String.fromCharCode(115, 101, 118, 101, 114, 105, 116, 121); // severity
t = t.replace(/const SEV_KEY = '[^']*'/g, `const SEV_KEY = '${w}'`);
fs.writeFileSync(p, t);
const line = t.split(/\n/).find((l) => l.includes('SEV_KEY ='));
console.log(line);
console.log(
  'codes',
  [...line.match(/'([^']+)'/)[1]].map((c) => c.charCodeAt(0)).join(',')
);
