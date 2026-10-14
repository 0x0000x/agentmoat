#!/usr/bin/env node
'use strict';
/*
 * moat-shell — universal wrapper for agents whose harness doesn't have hooks.
 * The full argv is checked as one command, then executed only on "allow".
 */
const { spawn, execFileSync } = require('child_process');
const path = require('path');
const moat = path.join(__dirname, 'moat.js');

const command = process.argv.slice(2).join(' ');
if (!command) { process.stderr.write('moat-shell: no command given\n'); process.exit(1); }

let res = { verdict: 'confirm', reason: 'moat could not evaluate the command' };
try {
  const out = execFileSync(process.execPath,
    [moat, 'check', '--tool', 'Bash', '--command', command, '--json'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
  res = JSON.parse(out);
} catch (e) {
  // nonzero exit (10/20) still prints the JSON verdict on stdout
  if (e.stdout) { try { res = JSON.parse(e.stdout); } catch { /* keep default */ } }
}

if (res.verdict === 'block') {
  process.stderr.write(`moat-shell: BLOCKED by agentmoat — ${res.reason}\ncommand: ${command}\n`);
  process.exit(20);
}
if (res.verdict === 'confirm') {
  process.stderr.write(`moat-shell: held for confirmation by agentmoat — ${res.reason}\ncommand: ${command}\n`);
  process.exit(10);
}
const child = spawn(command, { shell: '/bin/bash', stdio: 'inherit' });
child.on('exit', (code, sig) => process.exit(code == null ? (sig ? 128 + 15 : 1) : code));
