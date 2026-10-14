'use strict';

const express = require('express');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
require('dotenv').config();
const {
  normalizeUsername,
  createChallengeStore,
  createSessionStore,
  cookieToken,
  securityConfiguration,
  SESSION_TTL_MS,
} = require('./security');
const { createUserStore } = require('./storage');

const { origin, rpID, secureCookie } = securityConfiguration();
const app = express();
const users = createUserStore();
const challenges = createChallengeStore();
const sessions = createSessionStore();
const COOKIE = '__Host-passkey_session';
const PORT = Number(process.env.PORT || 3000);

app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(__dirname, 'passkey-frontend/dist/passkey-frontend/browser')));

// Real-device acceptance UI: explicitly enabled in disposable staging only.
// Never expose the evidence validator or local acceptance files through static serving.
if (process.env.APP_ENABLE_ACCEPTANCE === '1') {
  for (const [url, file] of [
    ['/acceptance', 'index.html'],
    ['/acceptance/protocol.js', 'protocol.js'],
    ['/acceptance/runner.js', 'runner.js'],
  ]) {
    app.get(url, (_req, res) => res.sendFile(path.join(__dirname, 'acceptance', file)));
  }
}


// Browser writes must be same-origin. Wildcard CORS intentionally removed.
app.use((req, res, next) => {
  if (req.method === 'POST') {
    const requestOrigin = req.get('origin');
    const site = req.get('sec-fetch-site');
    if ((requestOrigin && requestOrigin !== origin) ||
        (site && site !== 'same-origin') ||
        (process.env.NODE_ENV === 'production' && !requestOrigin)) {
      return res.status(403).json({ error: 'Invalid request origin' });
    }
  }
  next();
});

// Small, in-memory abuse limit, for a single Node process only.
const requestBuckets = new Map();
function throttle(req, res, next) {
  const now = Date.now();
  if (requestBuckets.size > 10000) {
    for (const [key, bucket] of requestBuckets) if (bucket.reset <= now) requestBuckets.delete(key);
    if (requestBuckets.size > 10000) return res.status(503).json({ error: 'Try again later' });
  }
  const key = req.ip + ':' + req.path;
  const previous = requestBuckets.get(key);
  const bucket = !previous || previous.reset <= now ? { count: 0, reset: now + 60000 } : previous;
  bucket.count += 1;
  requestBuckets.set(key, bucket);
  if (bucket.count > 20) return res.status(429).json({ error: 'Rate limit exceeded' });
  next();
}
app.use(['/register/start', '/register/finish', '/login/start', '/login/finish'], throttle);

const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res)).catch(next);
function usernameFrom(req, res) {
  const username = normalizeUsername(req.body?.username);
  if (!username) res.status(400).json({ error: 'Username must have 3-64 valid characters' });
  return username;
}
function setSession(res, token) {
  const secure = secureCookie ? '; Secure' : '';
  // __Host- cookies require Secure, so localhost HTTP needs a separate dev cookie name.
  const name = secureCookie ? COOKIE : 'passkey_dev_session';
  res.setHeader('Set-Cookie', name + '=' + token + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=' + (SESSION_TTL_MS / 1000) + secure);
}
function readSession(req) {
  if (!secureCookie) {
    const match = (req.get('cookie') || '').split(';').map(v => v.trim()).find(v => v.startsWith('passkey_dev_session='));
    return match ? match.slice('passkey_dev_session='.length) : null;
  }
  return cookieToken(req.get('cookie'));
}

app.post('/register/start', asyncRoute(async (req, res) => {
  const username = usernameFrom(req, res);
  if (!username) return;
  if (users.has(username)) return res.status(409).json({ error: 'Account already exists' });
  const options = await generateRegistrationOptions({
    rpName: 'Passkeys Demo', rpID, userName: username,
    userID: randomBytes(16), attestationType: 'none',
    supportedAlgorithmIDs: [-7, -257],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
  });
  challenges.issue('register', username, options.challenge);
  res.json(options);
}));

app.post('/register/finish', asyncRoute(async (req, res) => {
  const username = usernameFrom(req, res);
  if (!username) return;
  const expectedChallenge = challenges.consume('register', username);
  if (!expectedChallenge) return res.status(400).json({ error: 'Registration challenge expired or already used' });
  if (users.has(username)) return res.status(409).json({ error: 'Account already exists' });
  if (!req.body?.data) return res.status(400).json({ error: 'Missing credential response' });
  let verified, registrationInfo;
  try {
    ({ verified, registrationInfo } = await verifyRegistrationResponse({
      response: req.body.data, expectedChallenge, expectedOrigin: origin,
      expectedRPID: rpID, requireUserVerification: true,
    }));
  } catch (_) {
    return res.status(400).json({ error: 'Invalid registration response' });
  }
  if (!verified || !registrationInfo?.credentialID || !registrationInfo?.credentialPublicKey) {
    return res.status(400).json({ error: 'Registration verification failed' });
  }
  const record = {
    credentialID: registrationInfo.credentialID,
    credentialPublicKey: Buffer.from(registrationInfo.credentialPublicKey).toString('base64url'),
    counter: registrationInfo.counter,
    transports: Array.isArray(req.body.data.response?.transports) ? req.body.data.response.transports : [],
  };
  // Re-check AFTER await: concurrent registration cannot overwrite this account.
  if (!users.create(username, record)) return res.status(409).json({ error: 'Account already exists' });
  res.json({ res: true });
}));

app.post('/login/start', asyncRoute(async (req, res) => {
  const username = usernameFrom(req, res);
  if (!username) return;
  const user = users.get(username);
  if (!user) return res.status(401).json({ error: 'Authentication failed' });
  const options = await generateAuthenticationOptions({
    rpID, userVerification: 'required',
    allowCredentials: [{ id: user.credentialID, type: 'public-key', transports: user.transports || [] }],
  });
  challenges.issue('login', username, options.challenge);
  res.json(options);
}));

app.post('/login/finish', asyncRoute(async (req, res) => {
  const username = usernameFrom(req, res);
  if (!username) return;
  const expectedChallenge = challenges.consume('login', username);
  const user = users.get(username);
  if (!expectedChallenge || !user || !req.body?.data || req.body.data.id !== user.credentialID) {
    return res.status(401).json({ error: 'Authentication failed' });
  }
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body.data, expectedChallenge, expectedOrigin: origin,
      expectedRPID: rpID, requireUserVerification: true,
      authenticator: {
        credentialID: user.credentialID,
        credentialPublicKey: Buffer.from(user.credentialPublicKey, 'base64url'),
        counter: user.counter,
        transports: user.transports || [],
      },
    });
  } catch (_) {
    return res.status(401).json({ error: 'Authentication failed' });
  }
  if (!verification.verified || !verification.authenticationInfo?.userVerified) {
    return res.status(401).json({ error: 'Authentication failed' });
  }
  // Persist signature counter before establishing an authenticated session.
  users.updateCounter(username, verification.authenticationInfo.newCounter);
  const token = sessions.create(username);
  setSession(res, token);
  res.json({ res: true });
}));

app.get('/session', (req, res) => {
  const username = sessions.resolve(readSession(req));
  if (!username) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, username });
});

app.post('/logout', (req, res) => {
  sessions.revoke(readSession(req));
  const name = secureCookie ? COOKIE : 'passkey_dev_session';
  res.setHeader('Set-Cookie', name + '=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' + (secureCookie ? '; Secure' : ''));
  res.json({ res: true });
});

app.use((error, req, res, next) => {
  console.error('Request failed:', error?.message || 'Unknown error');
  if (res.headersSent) return next(error);
  res.status(error?.type === 'entity.too.large' ? 413 : 500).json({ error: 'Request failed' });
});

if (require.main === module) {
  app.listen(PORT, () => console.log('Listening on ' + PORT + ' (' + origin + ')'));
}
module.exports = app;
