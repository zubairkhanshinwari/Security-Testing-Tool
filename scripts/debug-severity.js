const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const probesPath = path.join(__dirname, '..', 'src', 'scanner', 'probes.js');
let src = fs.readFileSync(probesPath, 'utf8');
if (!src.includes('_debugOutSeverity')) {
  src = src.replace(
    'severity: outSeverity,',
    `severity: (() => { const s = outSeverity; console.log('DEBUG', {issue, outSeverity:s, cvss: result && result.cvss, typeofS: typeof s}); return s; })(),`
  );
  fs.writeFileSync(probesPath, src);
}

delete require.cache[require.resolve('../src/scanner/probes')];
const { probePathParam } = require('../src/scanner/probes');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto('https://dev.falaya.com/');
  const r = await probePathParam(page, 'https://devapi.falaya.com/api/listings/{id}', null);
  console.log('RETURN', {
    issueFound: r.issueFound,
    severity: r.severityity,
    typeofSeverity: typeof r.severityity,
    cvss: r.cvss,
    title: r.title,
  });
  await browser.close();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
