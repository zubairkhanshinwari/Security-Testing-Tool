const fs = require('fs');
const path = require('path');
const p = path.join(__dirname, '..', 'src', 'scanner', 'probes.js');
let t = fs.readFileSync(p, 'utf8');

t = t.replace(
  /severity:\s*\(\(\)\s*=>\s*\{\s*const s = outSeverity;[\s\S]*?return s;\s*\}\)\(\),/,
  'severity: outSeverity,'
);

fs.writeFileSync(p, t);
console.log('cleaned debug IIFE:', t.includes('outSeverity') && !t.includes('DEBUG'));
