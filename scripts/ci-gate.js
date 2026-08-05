#!/usr/bin/env node
/**
 * CI quality gate for SecureAssess reports.
 * Fails (exit 1) when Confirmed High/Critical findings are present.
 *
 * Usage:
 *   node scripts/ci-gate.js --json reports/scan.result.json
 *   node scripts/ci-gate.js --sarif reports/scan.sarif.json
 *   node scripts/ci-gate.js   (auto-detect newest result/sarif under reports/)
 */

const fs = require('fs');
const path = require('path');

const SEVERE = new Set(['Critical', 'High']);
const CONFIRMED = new Set(['Confirmed']);

function parseArgs(argv) {
  const args = { files: [], requireConfirmed: true, severities: ['Critical', 'High'] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json' || a === '--sarif') args.files.push(argv[++i]);
    else if (a === '--allow-likely') args.requireConfirmed = false;
    else if (a === '--severity') {
      args.severities = String(argv[++i] || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    } else if (a === '--help' || a === '-h') args.help = true;
    else if (!a.startsWith('-')) args.files.push(a);
  }
  return args;
}

function loadJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function findingsFromScanResult(doc) {
  const list = Array.isArray(doc?.findings) ? doc.findings : Array.isArray(doc) ? doc : [];
  return list
    .filter((f) => f && (f.issueFound === true || f.status === 'Confirmed' || f.status === 'Likely' || f.status === 'Possible'))
    .map((f) => ({
      title: f.title || f.id || 'finding',
      severity: f.severity || 'Unknown',
      confidence: f.confidence || f.status || 'Unknown',
      endpoint: f.affectedEndpoint || f.affectedUrl || f.endpoint || '',
      source: 'json',
    }));
}

function findingsFromSarif(doc) {
  const run = doc?.runs?.[0];
  if (!run) return [];
  const rules = new Map((run.tool?.driver?.rules || []).map((r) => [r.id, r]));
  return (run.results || []).map((r) => {
    const rule = rules.get(r.ruleId) || {};
    const props = rule.properties || r.properties || {};
    return {
      title: r.message?.text || rule.name || r.ruleId || 'finding',
      severity: props.severity || (r.level === 'error' ? 'High' : 'Medium'),
      confidence: props.confidence || 'Unknown',
      endpoint: r.locations?.[0]?.physicalLocation?.artifactLocation?.uri || '',
      source: 'sarif',
    };
  });
}

function extractFindings(doc) {
  if (doc?.$schema || doc?.version === '2.1.0' || doc?.runs) return findingsFromSarif(doc);
  return findingsFromScanResult(doc);
}

function evaluateGate(findings, options = {}) {
  const requireConfirmed = options.requireConfirmed !== false;
  const severities = new Set(options.severities || ['Critical', 'High']);
  const blockers = findings.filter((f) => {
    const sevOk = severities.has(f.severity);
    const confOk = requireConfirmed ? CONFIRMED.has(f.confidence) : true;
    return sevOk && confOk;
  });
  return {
    ok: blockers.length === 0,
    blockers,
    scanned: findings.length,
    requireConfirmed,
    severities: [...severities],
  };
}

function resolveInputs(files) {
  if (files.length) return files.filter((f) => f && fs.existsSync(f));
  const reportsDir = path.join(process.cwd(), 'reports');
  if (!fs.existsSync(reportsDir)) return [];
  const candidates = fs
    .readdirSync(reportsDir)
    .filter((f) => f.endsWith('.json') || f.endsWith('.sarif.json'))
    .map((f) => path.join(reportsDir, f))
    .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
  // Prefer explicit result / sarif names
  const preferred = candidates.filter((f) => /\.sarif\.json$/i.test(f) || /\.result\.json$/i.test(f) || /scan-result/i.test(f));
  return (preferred[0] ? [preferred[0]] : candidates.slice(0, 1));
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(`SecureAssess CI gate

Fail the job when Confirmed High/Critical findings are present.

  node scripts/ci-gate.js --json <scan-result.json>
  node scripts/ci-gate.js --sarif <report.sarif.json>
  node scripts/ci-gate.js --severity Critical,High --json <file>
  node scripts/ci-gate.js --allow-likely --json <file>   # also fail Likely High/Critical
`);
    process.exit(0);
  }

  const inputs = resolveInputs(args.files);
  if (!inputs.length) {
    console.error('ci-gate: no report file found. Pass --json or --sarif path.');
    process.exit(2);
  }

  const findings = [];
  for (const file of inputs) {
    try {
      const doc = loadJson(file);
      const extracted = extractFindings(doc);
      console.log(`ci-gate: loaded ${extracted.length} finding(s) from ${path.basename(file)}`);
      findings.push(...extracted);
    } catch (err) {
      console.error(`ci-gate: failed to parse ${file}: ${err.message}`);
      process.exit(2);
    }
  }

  const result = evaluateGate(findings, {
    requireConfirmed: args.requireConfirmed,
    severities: args.severities.length ? args.severities : [...SEVERE],
  });

  if (result.ok) {
    console.log(
      `ci-gate: PASS — no ${result.requireConfirmed ? 'Confirmed ' : ''}${result.severities.join('/')} findings (${result.scanned} total).`,
    );
    process.exit(0);
  }

  console.error(
    `ci-gate: FAIL — ${result.blockers.length} blocker(s) (${result.requireConfirmed ? 'Confirmed ' : ''}${result.severities.join('/')}):`,
  );
  for (const b of result.blockers.slice(0, 20)) {
    console.error(`  - [${b.severity}/${b.confidence}] ${b.title}${b.endpoint ? ` @ ${b.endpoint}` : ''}`);
  }
  process.exit(1);
}

module.exports = {
  evaluateGate,
  extractFindings,
  findingsFromScanResult,
  findingsFromSarif,
};

if (require.main === module) main();
