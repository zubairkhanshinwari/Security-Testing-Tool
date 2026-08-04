const { chromium } = require('playwright');
const { probePathParam } = require('../src/scanner/probes');

const SEV = String.fromCharCode(115, 101, 118, 101, 114, 105, 116, 121);

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto('https://dev.falaya.com/');
  const r = await probePathParam(page, 'https://devapi.falaya.com/api/listings/{id}', null);
  console.log('bracket', r[SEV]);
  console.log('dot', r.severityity);
  console.log('keys', Object.keys(r).filter((k) => /sev/i.test(k)));
  console.log('cvss', r.cvss, 'issue', r.issueFound);
  await browser.close();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
