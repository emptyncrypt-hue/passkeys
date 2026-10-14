'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeUsername, newRandomToken, createChallengeStore, createSessionStore, cookieToken, securityConfiguration } = require('../security');

test('usernames canonicalize and block prototype keys', () => {
  assert.equal(normalizeUsername(' Alice '), 'alice');
  for (const name of ['__proto__', 'ab', 'A B', '', null, 123]) assert.equal(normalizeUsername(name), null);
});
test('cryptographic challenges are URL-safe and unique', () => {
  const values = new Set(Array.from({ length: 64 }, newRandomToken));
  assert.equal(values.size, 64);
  for (const value of values) assert.match(value, /^[A-Za-z0-9_-]{43}$/);
});
test('challenges are single-use and purpose bound', () => {
  const challenges = createChallengeStore();
  challenges.issue('register', 'alice', 'test-challenge');
  assert.equal(challenges.consume('login', 'alice'), null);
  assert.equal(challenges.consume('register', 'alice'), 'test-challenge');
  assert.equal(challenges.consume('register', 'alice'), null);
});
test('expired challenges fail closed', () => {
  let now = 0;
  const challenges = createChallengeStore(() => now);
  challenges.issue('login', 'alice', 'expiring');
  now = 300001;
  assert.equal(challenges.consume('login', 'alice'), null);
});
test('sessions are opaque, expire, and revoke on logout', () => {
  let now = 100;
  const sessions = createSessionStore(() => now);
  const token = sessions.create('alice');
  assert.equal(sessions.resolve(token), 'alice');
  assert.equal(sessions.resolve('invalid'), null);
  sessions.revoke(token);
  assert.equal(sessions.resolve(token), null);
  const later = sessions.create('alice');
  now += 8 * 60 * 60 * 1000 + 1;
  assert.equal(sessions.resolve(later), null);
});
test('production requires HTTPS and RP origin match', () => {
  assert.throws(() => securityConfiguration({ NODE_ENV: 'production', APP_ORIGIN: 'http://localhost:3000' }), /HTTPS/);
  assert.throws(() => securityConfiguration({ APP_ORIGIN: 'https://evil.com', RP_ID: 'good.com' }), /RP_ID/);
  assert.deepEqual(securityConfiguration({ APP_ORIGIN: 'https://login.example.com', RP_ID: 'example.com' }), { origin: 'https://login.example.com', rpID: 'example.com', secureCookie: true });
});
test('host session cookies are parsed without confusing other names', () => {
  assert.equal(cookieToken('x=1; __Host-passkey_session=abc123; y=2'), 'abc123');
  assert.equal(cookieToken('prefix__Host-passkey_session=fake'), null);
});
