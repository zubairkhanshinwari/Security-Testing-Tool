#!/usr/bin/env node
const path = require('path');
const { runAssessment } = require('./scanner');
const { generateReports } = require('./report/pdfReport');
const { DEFAULT_SELECTED } = require('./scanner/securityTypes');

function usage() {
  console.log(`
Web Security Assessment Tool (CLI)

Usage:
  npm run scan -- --url https://example.com --yes [options]

Options:
  --url <url>              Target URL (required)
  --project <name>         Project name
  --env <name>             Environment (default: Development)
  --tester <name>          Tester name
  --username <user>        Optional login username/email (obtains token)
  --password <pass>        Optional login password
  --types <ids>            Comma-separated security type ids (default: recommended)
  --out <dir>              Output directory (default: ./reports)
  --yes                    Confirm you are authorized to test the target

Example:
  npm run scan -- --url https://dev.example.com --username user@ex.com --password secret --yes
`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--url') args.url = argv[++i];
    else if (a === '--project') args.project = argv[++i];
    else if (a === '--env') args.env = argv[++i];
    else if (a === '--tester') args.tester = argv[++i];
    else if (a === '--username') args.username = argv[++i];
    else if (a === '--password') args.password = argv[++i];
    else if (a === '--types') args.types = argv[++i];
    else if (a === '--out') args.out = argv[++i];
    else if (a === '--yes') args.yes = true;
    else if (a === '--help' || a === '-h') args.help = true;
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.url) {
    usage();
    process.exit(args.help ? 0 : 1);
  }
  if (!args.yes) {
    console.error('Refusing to scan without --yes (authorization confirmation).');
    process.exit(1);
  }

  const securityTypes = args.types
    ? args.types.split(',').map((s) => s.trim()).filter(Boolean)
    : DEFAULT_SELECTED;

  console.log(`Target: ${args.url}`);
  if (args.username) console.log(`Login:  ${args.username} (password provided)`);
  console.log(`Types:  ${securityTypes.length} selected`);

  const data = await runAssessment({
    targetUrl: args.url,
    projectName: args.project || 'Web Security Assessment',
    environment: args.env || 'Development',
    testerName: args.tester || 'Security Assessment Tool',
    username: args.username || null,
    password: args.password || null,
    securityTypes,
    onProgress: (p) => console.log(`[${p.stage}] ${p.message}`),
  });

  const outDir = path.resolve(args.out || path.join(__dirname, '..', 'reports'));
  const files = await generateReports(data, outDir);

  console.log('');
  console.log('Assessment complete');
  console.log(`  Login          : ${data.meta.loginSuccess ? 'ok' : data.meta.loginAttempted ? 'failed' : 'skipped'}`);
  console.log(`  Total findings : ${data.stats.totalFindings}`);
  console.log(`  Risk           : ${data.stats.overallRisk}`);
  console.log(`  Score          : ${data.stats.securityScore}/100`);
  console.log(`  PDF            : ${files.pdfPath}`);
  console.log(`  HTML           : ${files.htmlPath}`);
  console.log(`  JSON           : ${files.jsonPath}`);
}

main().catch((err) => {
  console.error('Scan failed:', err.message);
  process.exit(1);
});
