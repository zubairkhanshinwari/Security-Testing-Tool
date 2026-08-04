const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');
const { buildHtmlReport } = require('./htmlReport');
const { attachScreenshots } = require('./attachScreenshots');

async function generateReports(data, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const base = `sqli-report-${stamp}`;
  const htmlPath = path.join(outDir, `${base}.html`);
  const pdfPath = path.join(outDir, `${base}.pdf`);
  const jsonPath = path.join(outDir, `${base}.json`);

  // Last-mile guarantee: embed Critical/High/Medium/Low screenshots into findings
  // before HTML/PDF are written (loads from disk or captures fresh).
  await attachScreenshots(data, outDir);

  const html = buildHtmlReport(data);
  fs.writeFileSync(htmlPath, html, 'utf8');
  fs.writeFileSync(jsonPath, JSON.stringify(data, null, 2), 'utf8');

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto('file:///' + htmlPath.replace(/\\/g, '/'), { waitUntil: 'networkidle' });
  await page.pdf({
    path: pdfPath,
    format: 'A4',
    printBackground: true,
    displayHeaderFooter: true,
    headerTemplate: `
      <div style="font-size:8px;width:100%;padding:0 14mm;color:#64748b;display:flex;justify-content:space-between;font-family:Segoe UI,Arial,sans-serif;">
        <span>${String(data.meta.projectName || 'SQL Injection Assessment').replace(/</g, '')}</span>
        <span>Confidential</span>
      </div>`,
    footerTemplate: `
      <div style="font-size:8px;width:100%;padding:0 14mm;color:#64748b;display:flex;justify-content:space-between;font-family:Segoe UI,Arial,sans-serif;">
        <span>OWASP WSTG-INPV-05 | Authorized Assessment</span>
        <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
      </div>`,
    margin: { top: '16mm', bottom: '16mm', left: '12mm', right: '12mm' },
    outline: true,
    tagged: true,
  });
  await browser.close();

  return { htmlPath, pdfPath, jsonPath, base };
}

module.exports = { generateReports };
