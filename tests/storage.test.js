'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createUserStore } = require('../storage');

test('registration is create-only, survives restart, and persists counters', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'passkeys-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'data', 'users.json');
  const store = createUserStore(file);
  const first = { credentialID: 'credential-1', credentialPublicKey: 'public-key', counter: 0, transports: [] };
  assert.equal(store.create('alice', first), true);
  assert.equal(store.create('alice', { ...first, credentialID: 'attacker-key' }), false);
  assert.equal(store.get('alice').credentialID, 'credential-1');
  store.updateCounter('alice', 9);
  assert.throws(() => store.updateCounter('alice', 8), /regressing/);
  const reloaded = createUserStore(file);
  assert.equal(reloaded.get('alice').counter, 9);
  assert.equal(reloaded.get('alice').credentialID, 'credential-1');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});
test('corrupt credential store is refused, not reset', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'passkeys-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'users.json');
  fs.writeFileSync(file, '{bad-json');
  assert.throws(() => createUserStore(file), SyntaxError);
});
