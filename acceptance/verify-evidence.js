#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const crypto = require('node:crypto');
const { VERSION, REQUIRED, CASES, SAFE_STATUSES, evaluate } = require('./protocol');
const MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

function validateEvidence(input, now = Date.now()) {
  const errors = [];
  if (!input || typeof input !== 'object' || Array.isArray(input)) return ['Invalid evidence JSON object'];
  const { sha256, ...payload } = input;
  const correct = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('base64url');
  if (typeof sha256 !== 'string' || sha256 !== correct) errors.push('SHA-256 integrity check failed');
  if (payload.schema !== 'passkeys-real-device-acceptance/v1' || payload.suiteVersion !== VERSION) errors.push('Unrecognized suite version/schema');
  if (!payload.origin || typeof payload.origin !== 'string') errors.push('Missing origin');
  else {
    try {
      const url = new URL(payload.origin);
      if (url.origin !== payload.origin || (url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === 'localhost'))) errors.push('Origin must be HTTPS or localhost');
    } catch { errors.push('Invalid origin URL'); }
  }
  if (typeof payload.userAgent !== 'string' || payload.userAgent.length < 10) errors.push('Missing userAgent');
  const started = Date.parse(payload.startedAt);
  const exported = Date.parse(payload.exportedAt);
  if (!Number.isFinite(started) || !Number.isFinite(exported) || started > exported || exported > now + 5 * 60 * 1000 || now - exported > MAX_AGE_MS) errors.push('Evidence timestamps invalid or stale');
  const env = payload.environment;
  if (!env || typeof env !== 'object' || env.realDeviceConfirmed !== true) errors.push('Physical authenticator attestation missing');
  for (const key of ['testerAlias', 'deviceClass', 'model', 'os', 'browser', 'authenticator']) {
    if (typeof env?.[key] !== 'string' || !env[key].trim() || env[key].length > 120) errors.push('Invalid device metadata: ' + key);
  }
  if (!['mobile', 'desktop', 'security-key'].includes(env?.deviceClass)) errors.push('Device class must be mobile/desktop/security-key');
  const expected = CASES.map(([id]) => id);
  if (!Array.isArray(payload.cases) || payload.cases.length !== expected.length) errors.push('Evidence must contain every declared case exactly once');
  else {
    const ids = payload.cases.map(test => test?.id);
    if (ids.some((id, i) => id !== expected[i])) errors.push('Case order and IDs differ from suite manifest');
    for (const test of payload.cases) {
      if (!SAFE_STATUSES.includes(test?.status)) errors.push('Invalid status for ' + test?.id);
      if (test.status === 'PASS' && (!Number.isFinite(Date.parse(test.at)) || Date.parse(test.at) < started || Date.parse(test.at) > exported)) errors.push('Invalid PASS timestamp for ' + test.id);
      if (test.status === 'PASS' && (typeof test.detail !== 'string' || !test.detail)) errors.push('Missing PASS summary for ' + test.id);
      if (Object.keys(test).some(k => !['id','status','at','detail'].includes(k))) errors.push('Unexpected case field (possible secret leakage)');
    }
  }
  if (payload.verdict !== 'PASS' || !Array.isArray(payload.cases) || !evaluate(payload.cases, env)) errors.push('Required test case not passed');
  if (payload.provenance !== 'operator-attested; device authenticity NOT cryptographically verified') errors.push('Missing provenance disclaimer');
  if (Object.keys(payload).some(k => !['schema','suiteVersion','startedAt','exportedAt','origin','userAgent','environment','cases','verdict','provenance'].includes(k))) errors.push('Unexpected evidence field');
  return errors;
}
function verifyRelease(reports) {
  const errors = [];
  if (reports.length < 2) errors.push('Release acceptance requires at least 2 physical devices');
  const classes = new Set(reports.map(report => report.environment.deviceClass));
  if (!classes.has('mobile') || (!classes.has('desktop') && !classes.has('security-key'))) errors.push('Release requires mobile plus desktop or external security key');
  const platforms = new Set(reports.map(report => report.environment.os.toLowerCase().split(/[\s\d]/)[0]));
  if (platforms.size < 2) errors.push('Release requires at least two distinct operating-system families');
  if (new Set(reports.map(report => report.origin)).size !== 1) errors.push('Reports must use the same application origin');
  if (new Set(reports.map(report => report.environment.model.toLowerCase())).size < 2) errors.push('Reports must represent distinct physical device models');
  return errors;
}
function cli(args = process.argv.slice(2)) {
  const release = args[0] === '--release';
  const paths = release ? args.slice(1) : args;
  if (!paths.length) {
    console.error('Usage: node acceptance/verify-evidence.js [--release] <evidence.json> [more-evidence.json]');
    return 2;
  }
  const reports = [];
  let failed = false;
  for (const path of paths) {
    try {
      const report = JSON.parse(fs.readFileSync(path, 'utf8'));
      const errors = validateEvidence(report);
      if (errors.length) { failed = true; console.error('REJECTED', path, ':', errors.join('; ')); }
      else { reports.push(report); console.log('EVIDENCE VALID', path, '- operator attestation only; not cryptographic hardware proof'); }
    } catch (err) { failed = true; console.error('REJECTED', path, ':', err.message); }
  }
  if (release) {
    if (failed) return 1;
    const errors = verifyRelease(reports);
    if (errors.length) { console.error('RELEASE NO_GO:', errors.join('; ')); return 1; }
    console.log('RELEASE EVIDENCE COMPLETE (self-attested; independent review required)');
  }
  return failed ? 1 : 0;
}
if (require.main === module) process.exitCode = cli();
module.exports = { validateEvidence, verifyRelease, cli };
