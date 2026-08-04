const { chromium } = require('playwright');
const { probePathParam } = require('../src/scanner/probes');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto('https://dev.falaya.com/');
  const r = await probePathParam(page, 'https://devapi.falaya.com/api/listings/{id}', null);
  for (const k of Object.keys(r)) {
    if (k.toLowerCase().includes('sev') || k.toLowerCase().includes('debug') || k === 'severityity') {
      console.log('KEY', JSON.stringify(k), [...k].map((c) => c.charCodeAt(0)).join(','));
      console.log('VAL', r[k], typeof r[k]);
    }
  }
  // Force assign and re-check
  r.severityity = 'Medium';
  console.log('after force', r.severityity);
  await browser.close();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
