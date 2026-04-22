#!/usr/bin/env node
'use strict';

/**
 * STVOR SDK CLI
 *
 * Usage:
 *   stvor-cli status              — live relay stats
 *   stvor-cli stats               — alias for status
 *   stvor-cli health              — relay health check
 *   stvor-cli export [json|csv]   — export relay stats
 *   --version / -v
 *   --relay  <url>                — relay URL (default: $STVOR_RELAY_URL or http://localhost:3002)
 *   --token  <token>              — app token  (default: $STVOR_APP_TOKEN)
 */

const https = require('https');
const http  = require('http');
const fs    = require('fs');

const c = {
  reset:  '\x1b[0m',
  bright: '\x1b[1m',
  dim:    '\x1b[2m',
  red:    '\x1b[31m',
  green:  '\x1b[32m',
  yellow: '\x1b[33m',
  cyan:   '\x1b[36m',
};

function col(color, text) { return `${c[color]}${text}${c.reset}`; }
function header(title) {
  console.log('\n' + col('cyan', '═'.repeat(45)));
  console.log(' ' + col('bright', title));
  console.log(col('cyan', '═'.repeat(45)) + '\n');
}

// ── CLI arg parsing ───────────────────────────────────────────────────────────

const args = process.argv.slice(2);
let command = null;
let relayUrl = process.env.STVOR_RELAY_URL || 'http://localhost:3002';
let appToken = process.env.STVOR_APP_TOKEN || '';
let exportFormat = 'json';

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--relay' && args[i + 1]) { relayUrl = args[++i]; continue; }
  if (args[i] === '--token' && args[i + 1]) { appToken = args[++i]; continue; }
  if (args[i] === '--version' || args[i] === '-v') { command = 'version'; continue; }
  if (!command) command = args[i];
  else if (command === 'export') exportFormat = args[i];
}

if (!command || command === 'help' || command === '-h' || command === '--help') {
  command = 'help';
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

function fetch(url, options = {}) {
  return new Promise((resolve, reject) => {
    const lib    = url.startsWith('https') ? https : http;
    const parsed = new URL(url);
    const req    = lib.request({
      hostname: parsed.hostname,
      port:     parsed.port || (url.startsWith('https') ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   options.method || 'GET',
      headers:  options.headers || {},
      timeout:  5000,
    }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    if (options.body) req.write(options.body);
    req.end();
  });
}

function authHeaders() {
  return appToken ? { Authorization: `Bearer ${appToken}` } : {};
}

// ── Commands ──────────────────────────────────────────────────────────────────

async function cmdHealth() {
  header('Relay Health');
  try {
    const { status, body } = await fetch(`${relayUrl}/health`);
    const data = JSON.parse(body);
    if (status === 200 && data.status === 'ok') {
      console.log(col('green', '✓ Relay is healthy'));
    } else {
      console.log(col('red', `✗ Relay returned status ${status}`));
    }
    console.log(`  URL: ${col('cyan', relayUrl)}\n`);
  } catch (e) {
    console.log(col('red', `✗ Cannot reach relay at ${relayUrl}`));
    console.log(`  ${col('dim', e.message)}\n`);
    process.exit(1);
  }
}

async function cmdStatus() {
  header('Relay Status');

  // Health
  try {
    const { status } = await fetch(`${relayUrl}/health`);
    console.log(`  Health:  ${status === 200 ? col('green', '● ONLINE') : col('red', '● OFFLINE')}`);
  } catch {
    console.log(`  Health:  ${col('red', '● OFFLINE — cannot reach relay')}`);
    console.log(`  URL: ${relayUrl}\n`);
    process.exit(1);
  }

  // Stats (requires token)
  if (!appToken) {
    console.log(`  ${col('yellow', '⚠ No app token — set STVOR_APP_TOKEN or use --token to see registry stats')}\n`);
    return;
  }

  try {
    const { status, body } = await fetch(`${relayUrl}/stats`, { headers: authHeaders() });
    if (status !== 200) {
      console.log(`  ${col('yellow', `⚠ Stats unavailable (HTTP ${status}): ${body}`)}\n`);
      return;
    }
    const d = JSON.parse(body);
    const reg = d.registry || {};
    console.log(`\n  Registry:`);
    console.log(`    Projects:         ${col('cyan', reg.projects ?? '—')}`);
    console.log(`    Connected users:  ${col('cyan', reg.users ?? '—')}`);
    console.log(`    Pending messages: ${col('cyan', reg.pendingMessages ?? '—')}`);
    if (d.limits) {
      console.log(`\n  Limits:`);
      console.log(`    Max users/project: ${d.limits.maxUsersPerProject ?? '—'}`);
      console.log(`    Max msgs/user:     ${d.limits.maxMessagesPerUser ?? '—'}`);
      console.log(`    Max msg size:      ${d.limits.maxMessageSize ? (d.limits.maxMessageSize / 1024).toFixed(0) + ' KB' : '—'}`);
      console.log(`    Message TTL:       ${d.limits.messageTtlMs ? (d.limits.messageTtlMs / 60000).toFixed(0) + ' min' : '—'}`);
    }
    console.log('');
  } catch (e) {
    console.log(`  ${col('red', `✗ Failed to fetch stats: ${e.message}`)}\n`);
  }
}

async function cmdExport(format) {
  if (!appToken) {
    console.error(col('red', '✗ --token or STVOR_APP_TOKEN required for export'));
    process.exit(1);
  }

  let statsData = {};
  try {
    const { status, body } = await fetch(`${relayUrl}/stats`, { headers: authHeaders() });
    if (status !== 200) throw new Error(`HTTP ${status}: ${body}`);
    statsData = JSON.parse(body);
  } catch (e) {
    console.error(col('red', `✗ Cannot fetch stats: ${e.message}`));
    process.exit(1);
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  let content = '';
  let filename = '';

  if (format === 'csv') {
    const reg = statsData.registry || {};
    content  = 'Metric,Value\n';
    content += `Projects,${reg.projects ?? 0}\n`;
    content += `Users,${reg.users ?? 0}\n`;
    content += `PendingMessages,${reg.pendingMessages ?? 0}\n`;
    content += `ExportedAt,${new Date().toISOString()}\n`;
    filename = `stvor-stats-${timestamp}.csv`;
  } else {
    content  = JSON.stringify({ ...statsData, exportedAt: new Date().toISOString() }, null, 2);
    filename = `stvor-stats-${timestamp}.json`;
  }

  fs.writeFileSync(filename, content);
  console.log(col('green', `✓ Exported to ${filename}`));
  console.log(`  Format: ${format.toUpperCase()}, Size: ${(content.length / 1024).toFixed(1)} KB\n`);
}

function cmdVersion() {
  try {
    const pkg = require('../package.json');
    console.log(`@stvor/sdk v${pkg.version}`);
  } catch {
    console.log('@stvor/sdk CLI');
  }
}

function cmdHelp() {
  header('STVOR CLI');
  console.log('  Commands:\n');
  const cmds = [
    ['status',          'Show live relay stats'],
    ['health',          'Check relay health'],
    ['export [format]', 'Export stats (json | csv)'],
    ['--version',       'Show version'],
    ['help',            'Show this help'],
  ];
  cmds.forEach(([cmd, desc]) => {
    console.log(`  ${col('cyan', cmd.padEnd(22))} ${desc}`);
  });
  console.log('\n  Options:\n');
  console.log(`  ${col('cyan', '--relay <url>'.padEnd(22))} Relay URL (default: $STVOR_RELAY_URL or http://localhost:3002)`);
  console.log(`  ${col('cyan', '--token <token>'.padEnd(22))} App token (default: $STVOR_APP_TOKEN)`);
  console.log('\n  Examples:\n');
  console.log(`    stvor-cli status`);
  console.log(`    stvor-cli status --relay http://relay.example.com --token stvor_live_xxx`);
  console.log(`    stvor-cli export csv --token stvor_live_xxx\n`);
}

// ── Main ──────────────────────────────────────────────────────────────────────

(async () => {
  switch (command) {
    case 'status':
    case 'stats':
      await cmdStatus();
      break;
    case 'health':
      await cmdHealth();
      break;
    case 'export':
      await cmdExport(exportFormat);
      break;
    case 'version':
      cmdVersion();
      break;
    case 'help':
    default:
      cmdHelp();
  }
})().catch((e) => {
  console.error(col('red', `✗ Unexpected error: ${e.message}`));
  process.exit(1);
});
