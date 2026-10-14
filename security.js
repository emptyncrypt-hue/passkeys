'use strict';
const { randomBytes, createHash } = require('node:crypto');
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const MAX_PENDING_CHALLENGES = 10000;
const MAX_ACTIVE_SESSIONS = 10000;
function normalizeUsername(value) {
  if (typeof value !== 'string') return null;
  const username = value.trim().toLowerCase();
  return /^[a-z0-9][a-z0-9_.-]{2,63}$/.test(username) ? username : null;
}
function newRandomToken() { return randomBytes(32).toString('base64url'); }
function createChallengeStore(now = Date.now) {
  const entries = new Map();
  const key = (purpose, username) => purpose + ':' + username;
  return {
    issue(purpose, username, challenge = newRandomToken()) {
      if (purpose !== 'register' && purpose !== 'login') throw new Error('Invalid challenge purpose');
      for (const [k, v] of entries) if (v.expiresAt <= now()) entries.delete(k);
      if (entries.size >= MAX_PENDING_CHALLENGES) throw new Error('Challenge capacity exceeded');
      entries.set(key(purpose, username), { challenge, expiresAt: now() + CHALLENGE_TTL_MS });
      return challenge;
    },
    consume(purpose, username) {
      const k = key(purpose, username);
      const current = entries.get(k);
      entries.delete(k);
      return current && current.expiresAt > now() ? current.challenge : null;
    },
  };
}
function tokenHash(token) { return createHash('sha256').update(token).digest('hex'); }
function createSessionStore(now = Date.now) {
  const sessions = new Map();
  return {
    create(username) {
      for (const [hash, entry] of sessions) if (entry.expiresAt <= now()) sessions.delete(hash);
      if (sessions.size >= MAX_ACTIVE_SESSIONS) throw new Error('Session capacity exceeded');
      const token = newRandomToken();
      sessions.set(tokenHash(token), { username, expiresAt: now() + SESSION_TTL_MS });
      return token;
    },
    resolve(token) {
      if (typeof token !== 'string' || !/^[\w-]{43}$/.test(token)) return null;
      const hash = tokenHash(token);
      const entry = sessions.get(hash);
      if (!entry) return null;
      if (entry.expiresAt <= now()) { sessions.delete(hash); return null; }
      return entry.username;
    },
    revoke(token) { if (typeof token === 'string') sessions.delete(tokenHash(token)); },
  };
}
function cookieToken(cookieHeader) {
  if (typeof cookieHeader !== 'string') return null;
  const entry = cookieHeader.split(';').map(v => v.trim()).find(v => v.startsWith('__Host-passkey_session='));
  return entry ? entry.slice('__Host-passkey_session='.length) : null;
}
function securityConfiguration(environment = process.env) {
  const origin = environment.APP_ORIGIN || 'http://localhost:3000';
  const parsed = new URL(origin);
  const rpID = environment.RP_ID || 'localhost';
  if (parsed.origin !== origin || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error('APP_ORIGIN must be an exact origin (scheme, host, optional port)');
  }
  if (parsed.hostname !== rpID && !parsed.hostname.endsWith('.' + rpID)) {
    throw new Error('RP_ID must be the origin hostname or one of its parent domains');
  }
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && rpID === 'localhost')) {
    throw new Error('HTTPS is mandatory except for localhost development');
  }
  if (environment.NODE_ENV === 'production' && parsed.protocol !== 'https:') {
    throw new Error('Production requires HTTPS APP_ORIGIN');
  }
  return { origin, rpID, secureCookie: parsed.protocol === 'https:' };
}
module.exports = { normalizeUsername, newRandomToken, createChallengeStore, createSessionStore, cookieToken, securityConfiguration, CHALLENGE_TTL_MS, SESSION_TTL_MS };
