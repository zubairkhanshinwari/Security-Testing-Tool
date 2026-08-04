const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const REPORT_SEVERITIES = new Set(['Critical', 'High', 'Medium', 'Low']);

function slug(s, max = 48) {
  return (
    String(s || 'issue')
      .replace(/[^a-zA-Z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, max) || 'issue'
  );
}

function issueType(f) {
  const cwe = ((f.mappings && f.mappings.cwe) || f.cwe || [])[0] || '';
  const mod = f.module || f.pluginId || 'Finding';
  return cwe ? `${mod} (${cwe})` : String(mod);
}

function fileNameFor(f, index) {
  const sev = f.severity || 'Info';
  const type = slug(String(f.module || f.pluginId || 'Issue'), 28);
  const title = slug(f.title || f.id || 'finding', 40);
  return `${String(index + 1).padStart(2, '0')}-${sev}-${type}-${title}.png`;
}

function isEligible(f) {
  return Boolean(f && f.issueFound && REPORT_SEVERITIES.has(f.severity));
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function buildEvidenceHtml(f, caption, targetUrl, liveThumbBase64) {
  const sev = f.severity || 'Informational';
  const sevColor =
    sev === 'Critical'
      ? '#7f1d1d'
      : sev === 'High'
        ? '#dc2626'
        : sev === 'Medium'
          ? '#ea580c'
          : sev === 'Low'
            ? '#ca8a04'
            : '#2563eb';
  const evidenceText = JSON.stringify(f.evidence || [], null, 2).slice(0, 1400);
  const live = liveThumbBase64
    ? `<div class="live"><div class="sub">Live page capture</div><img src="data:image/png;base64,${liveThumbBase64}" /></div>`
    : '';
  return `<!DOCTYPE html><html><head><meta charset="utf-8" />
<style>
  body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#0b1f3a;color:#0f172a}
  .wrap{padding:18px}
  .card{background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.25)}
  .banner{background:${sevColor};color:#fff;padding:14px 18px}
  .banner .sev{font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase}
  .banner h1{margin:6px 0 0;font-size:20px}
  .banner .type{margin-top:6px;opacity:.92;font-size:13px}
  .body{padding:16px 18px}
  .row{display:grid;grid-template-columns:140px 1fr;gap:8px;font-size:13px;margin:0 0 8px}
  .k{color:#64748b;font-weight:700}
  .v{word-break:break-word}
  pre{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px;font-size:11px;overflow:auto;max-height:200px;white-space:pre-wrap}
  .live{margin-top:12px}
  .live img{width:100%;border:1px solid #e2e8f0;border-radius:8px}
  .sub{font-size:11px;color:#64748b;font-weight:700;margin-bottom:6px;text-transform:uppercase}
  .foot{padding:10px 18px;background:#f1f5f9;font-size:11px;color:#475569}
</style></head><body><div class="wrap"><div class="card">
  <div class="banner">
    <div class="sev">${escapeHtml(sev)} severity</div>
    <h1>${escapeHtml(f.title || 'Security Finding')}</h1>
    <div class="type">Issue type: ${escapeHtml(issueType(f))} · ${escapeHtml(f.id || '')}</div>
  </div>
  <div class="body">
    <div class="row"><div class="k">Finding ID</div><div class="v">${escapeHtml(f.id || '')}</div></div>
    <div class="row"><div class="k">Caption</div><div class="v">${escapeHtml(caption)}</div></div>
    <div class="row"><div class="k">Endpoint</div><div class="v">${escapeHtml(String(f.affectedEndpoint || f.endpoint || ''))}</div></div>
    <div class="row"><div class="k">Parameter</div><div class="v">${escapeHtml(String(f.parameter || 'n/a'))}</div></div>
    <div class="row"><div class="k">Target</div><div class="v">${escapeHtml(targetUrl)}</div></div>
    <div class="row"><div class="k">Confidence</div><div class="v">${escapeHtml(String(f.confidence || ''))}</div></div>
    <div class="sub">Evidence</div>
    <pre>${escapeHtml(evidenceText)}</pre>
    ${live}
  </div>
  <div class="foot">SecureAssess evidence screenshot · Authorized assessment only</div>
</div></div></body></html>`;
}

/**
 * Ensure Critical/High/Medium/Low findings have screenshotBase64 before HTML/PDF build.
 * Also reloads from screenshotPath / reports/screenshots if PNG already exists on disk.
 */
async function attachScreenshots(data, outDir) {
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const eligible = findings.filter(isEligible);
  if (!eligible.length) return data;

  // Index existing PNGs under reports/screenshots for reuse
  const shotIndex = [];
  const shotRoot = path.join(outDir, 'screenshots');
  if (fs.existsSync(shotRoot)) {
    for (const dir of fs.readdirSync(shotRoot)) {
      const absDir = path.join(shotRoot, dir);
      try {
        if (!fs.statSync(absDir).isDirectory()) continue;
        for (const name of fs.readdirSync(absDir)) {
          if (!/\.png$/i.test(name)) continue;
          shotIndex.push({ name, abs: path.join(absDir, name) });
        }
      } catch {
        /* ignore */
      }
    }
  }

  let hydrated = 0;
  for (const f of eligible) {
    if (f.screenshotBase64) continue;
    const candidates = [];
    if (f.screenshotPath) candidates.push(f.screenshotPath);
    if (f.screenshotFileName) {
      candidates.push(path.join(outDir, 'screenshots', f.screenshotFileName));
      for (const item of shotIndex) {
        if (item.name === f.screenshotFileName) candidates.push(item.abs);
      }
    }
    // Fuzzy match by severity + title slug (e.g. Medium-...-JWT-weaknesses...)
    const titleSlug = slug(f.title || '', 40).toLowerCase();
    const sev = String(f.severity || '');
    if (titleSlug) {
      for (const item of shotIndex) {
        const n = item.name.toLowerCase();
        if (n.includes(sev.toLowerCase()) && n.includes(titleSlug.slice(0, 24))) {
          candidates.push(item.abs);
        }
      }
    }

    for (const p of candidates) {
      try {
        if (p && fs.existsSync(p) && fs.statSync(p).isFile()) {
          f.screenshotBase64 = fs.readFileSync(p).toString('base64');
          f.screenshotPath = p;
          f.screenshotFileName = f.screenshotFileName || path.basename(p);
          f.screenshotCaption =
            f.screenshotCaption || `${f.severity} · ${issueType(f)} · ${f.title}`;
          hydrated += 1;
          break;
        }
      } catch {
        /* ignore */
      }
    }
  }

  const missing = eligible.filter((f) => !f.screenshotBase64);
  if (!missing.length) {
    console.log(`[screenshots] hydrated ${hydrated} from disk; all findings have images`);
    return data;
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const shotDir = path.join(outDir, 'screenshots', `sqli-report-${stamp}`);
  fs.mkdirSync(shotDir, { recursive: true });
  const targetUrl = String((data.meta && data.meta.targetUrl) || '');

  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      viewport: { width: 1280, height: 800 },
    });
    const page = await context.newPage();

    for (let i = 0; i < missing.length; i++) {
      const f = missing[i];
      try {
        const name = fileNameFor(f, eligible.indexOf(f));
        const filePath = path.join(shotDir, name);
        const caption = `${f.severity} · ${issueType(f)} · ${f.title}`;
        let liveBase64 = null;
        const url = f.affectedUrl || f.fullUrl || f.affectedEndpoint || f.endpoint || targetUrl;
        if (url && /^https?:\/\//i.test(String(url)) && !/[{\}]/.test(String(url))) {
          try {
            await page.goto(String(url), { waitUntil: 'domcontentloaded', timeout: 15000 });
            liveBase64 = Buffer.from(await page.screenshot({ fullPage: false, type: 'png' })).toString(
              'base64',
            );
          } catch {
            /* card only */
          }
        }
        await page.setContent(buildEvidenceHtml(f, caption, targetUrl, liveBase64), {
          waitUntil: 'domcontentloaded',
        });
        const buf = await page.screenshot({ fullPage: true, type: 'png' });
        fs.writeFileSync(filePath, buf);
        f.screenshotPath = filePath;
        f.screenshotFileName = name;
        f.screenshotCaption = caption;
        f.screenshotBase64 = Buffer.from(buf).toString('base64');
        console.log(`[screenshots] attached ${f.id} -> ${name}`);
      } catch (err) {
        console.warn(`[screenshots] failed ${f.id}:`, err && err.message ? err.message : err);
      }
    }
  } finally {
    await browser.close();
  }

  const attached = findings.filter((f) => f.screenshotBase64).length;
  console.log(`[screenshots] ready: ${attached} finding(s) with embedded images`);
  return data;
}

module.exports = { attachScreenshots, isEligible };
