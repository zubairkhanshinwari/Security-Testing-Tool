#!/usr/bin/env node
import path from 'path';
import { bootstrap } from './bootstrap';

function usage() {
  console.log(`
SecureAssess Platform CLI

Usage:
  npm run scan -- --url https://example.com --yes [options]

Options:
  --url <url>            Target URL (required)
  --project <name>       Project name
  --project-id <id>      Existing project id
  --env <name>           Environment
  --tester <name>        Tester name
  --username <user>      Account A login (optional)
  --password <pass>      Account A password (optional)
  --username2 <user>     Account B login (optional, IDOR/BOLA)
  --password2 <pass>     Account B password (optional)
  --types <ids>          Comma-separated security type ids
  --plugins <ids>        Comma-separated plugin ids
  --mode <mode>          passive | active-safe | authenticated
  --profile <id>         quick | standard | deep | openapi | focused
  --focus <urls>         Comma-separated focus paths/URLs (high-value routes)
  --openapi <url>        OpenAPI/Swagger document URL
  --out <dir>            Reports directory override
  --yes                  Authorization confirmation (required)
`);
}

function parseArgs(argv: string[]) {
  const args: Record<string, any> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--url') args.url = next();
    else if (a === '--project') args.project = next();
    else if (a === '--project-id') args.projectId = next();
    else if (a === '--env') args.env = next();
    else if (a === '--tester') args.tester = next();
    else if (a === '--username') args.username = next();
    else if (a === '--password') args.password = next();
    else if (a === '--username2') args.username2 = next();
    else if (a === '--password2') args.password2 = next();
    else if (a === '--types') args.types = next();
    else if (a === '--plugins') args.plugins = next();
    else if (a === '--mode') args.mode = next();
    else if (a === '--profile') args.profile = next();
    else if (a === '--focus') args.focus = next();
    else if (a === '--openapi') args.openapi = next();
    else if (a === '--out') args.out = next();
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

  const { orchestrator, store, config } = await bootstrap();
  if (args.out) (config.storage as any).reportsDir = args.out;

  let projectId = args.projectId;
  if (!projectId) {
    projectId = store.createProject({
      name: args.project || 'Web Security Assessment',
      targetUrl: args.url,
    }).id;
  }

  const { result, files } = await orchestrator.runAndReport({
    targetUrl: args.url,
    projectId,
    projectName: args.project || 'Web Security Assessment',
    environment: args.env || 'Development',
    testerName: args.tester || 'SecureAssess Platform',
    username: args.username || null,
    password: args.password || null,
    username2: args.username2 || null,
    password2: args.password2 || null,
    securityTypes: args.types ? args.types.split(',').map((s: string) => s.trim()) : undefined,
    pluginIds: args.plugins ? args.plugins.split(',').map((s: string) => s.trim()) : undefined,
    mode: args.mode || 'active-safe',
    profile: args.profile || 'standard',
    focusEndpoints: args.focus
      ? String(args.focus)
          .split(',')
          .map((s: string) => s.trim())
          .filter(Boolean)
      : [],
    openApiUrl: args.openapi || null,
    authorized: true,
    onProgress: (p) => console.log(`[${p.stage}] ${p.message}`),
  });

  store.saveScan({
    projectId,
    targetUrl: args.url,
    score: result.risk.overallScore,
    risk: result.risk.overallRisk,
    findings: result.stats.totalFindings as number,
    meta: result.meta,
    files: Object.fromEntries(
      Object.entries(files)
        .filter(([, v]) => typeof v === 'string')
        .map(([k, v]) => [k, path.basename(String(v))]),
    ),
    result,
  });

  console.log('');
  console.log('Assessment complete');
  console.log(`  Score     : ${result.risk.overallScore}/100`);
  console.log(`  Risk      : ${result.risk.overallRisk}`);
  console.log(`  Findings  : ${result.stats.totalFindings}`);
  console.log(`  Plugins   : ${(result.meta.plugins as string[])?.join(', ')}`);
  console.log(`  HTML      : ${files.htmlPath}`);
  console.log(`  PDF       : ${files.pdfPath}`);
  console.log(`  SARIF     : ${files.sarifPath}`);
  console.log(`  CSV       : ${files.csvPath}`);
  console.log(`  JUnit     : ${files.junitPath}`);
}

main().catch((err) => {
  console.error('Scan failed:', err.message || err);
  process.exit(1);
});
