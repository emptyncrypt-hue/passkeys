'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const P = require('../acceptance/protocol');
const { validateEvidence, verifyRelease } = require('../acceptance/verify-evidence');

test('WebAuthn base64url codecs preserve binary data', () => {
  const source = Uint8Array.of(0, 1, 127, 128, 254, 255);
  assert.deepEqual(P.bytesFromBase64url(P.base64urlFromBytes(source)), source);
  assert.throws(() => P.bytesFromBase64url('!invalid')); // rejects bad encoding
});
test('registration options convert all binary protocol inputs', () => {
  const sample = P.base64urlFromBytes(Uint8Array.of(1, 2, 3));
  const options = P.creationOptions({ challenge: sample, user: { id: sample, name: 'qa' }, excludeCredentials: [{ id: sample, type: 'public-key' }] });
  assert.ok(options.challenge instanceof Uint8Array);
  assert.ok(options.user.id instanceof Uint8Array);
  assert.ok(options.excludeCredentials[0].id instanceof Uint8Array);
});
test('assertion options convert credential IDs', () => {
  const sample = P.base64urlFromBytes(Uint8Array.of(3, 2, 1));
  const options = P.requestOptions({ challenge: sample, allowCredentials: [{ id: sample }] });
  assert.deepEqual(options.allowCredentials[0].id, Uint8Array.of(3, 2, 1));
});
test('WebAuthn response serialization only includes protocol fields', () => {
  const buffer = Uint8Array.of(4, 5).buffer;
  const base = { id: 'cred', rawId: buffer, type: 'public-key', getClientExtensionResults: () => ({}) };
  const registered = P.registrationJSON({ ...base, response: { clientDataJSON: buffer, attestationObject: buffer, getTransports: () => ['internal'] } });
  assert.equal(registered.response.attestationObject, 'BAU');
  const assertion = P.assertionJSON({ ...base, response: { clientDataJSON: buffer, authenticatorData: buffer, signature: buffer, userHandle: null } });
  assert.equal(assertion.response.userHandle, null);
  assert.equal(assertion.response.signature, 'BAU');
});
function sample(model = 'Device A', deviceClass = 'mobile', os = 'iOS 27') {
  const started = new Date(Date.now() - 60000).toISOString();
  const ended = new Date().toISOString();
  const payload = {
    schema: 'passkeys-real-device-acceptance/v1', suiteVersion: P.VERSION,
    startedAt: started, exportedAt: ended, origin: 'https://staging.example.com',
    userAgent: 'Browser passkeys useragent', environment: { testerAlias: 'tester', deviceClass, model, os, browser: 'Safari 27', authenticator: 'Platform passkey', realDeviceConfirmed: true },
    cases: P.CASES.map(([id]) => ({ id, status: 'PASS', at: ended, detail: 'Observed request status and operator gate' })),
    verdict: 'PASS', provenance: 'operator-attested; device authenticity NOT cryptographically verified',
  };
  return { ...payload, sha256: crypto.createHash('sha256').update(JSON.stringify(payload)).digest('base64url') };
}
test('complete operator-attested evidence passes integrity and completeness validation', () => {
  assert.deepEqual(validateEvidence(sample()), []);
});
test('tampered evidence fails hash integrity', () => {
  const report = sample(); report.environment.model = 'Attacker changed this';
  assert.match(validateEvidence(report).join(','), /SHA-256/);
});
test('report with missing replay PASS is rejected even if recomputed digest', () => {
  const report = sample(); report.cases.find(x => x.id === 'REPLAY').status = 'FAIL';
  const { sha256, ...payload } = report;
  report.sha256 = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('base64url');
  assert.match(validateEvidence(report).join(','), /Required test/);
});
test('no evidence accepted without operator physical-device assertion', () => {
  const report = sample(); report.environment.realDeviceConfirmed = false;
  const { sha256, ...payload } = report;
  report.sha256 = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('base64url');
  assert.match(validateEvidence(report).join(','), /Physical authenticator/);
});
test('release gate requires mobile plus desktop and distinct platforms/models', () => {
  assert.deepEqual(verifyRelease([sample(), sample('MacBook Pro', 'desktop', 'macOS 15')]), []);
  assert.match(verifyRelease([sample(), sample('Device B', 'mobile', 'iOS 27')]).join(','), /mobile plus desktop/);
  assert.match(verifyRelease([sample()]).join(','), /at least 2/);
});
