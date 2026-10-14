'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { normalizeUsername } = require('./security');
// Single-process demo store. Use a transactional database for multi-instance deployments.
function createUserStore(filePath = process.env.AUTH_STORE_PATH || path.join(__dirname, 'data', 'users.json')) {
  const location = path.resolve(filePath);
  const dir = path.dirname(location);
  const users = new Map();
  if (fs.existsSync(location)) {
    if (!fs.lstatSync(location).isFile()) throw new Error('User store must be a regular file');
    const parsed = JSON.parse(fs.readFileSync(location, 'utf8'));
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error('Invalid user store');
    for (const [name, record] of Object.entries(parsed)) {
      if (normalizeUsername(name) !== name || typeof record?.credentialID !== 'string' ||
          typeof record?.credentialPublicKey !== 'string' || !Number.isSafeInteger(record?.counter) || record.counter < 0) {
        throw new Error('Corrupt user store record');
      }
      users.set(name, record);
    }
  }
  function persist() {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmp = location + '.' + randomUUID() + '.tmp';
    try {
      fs.writeFileSync(tmp, JSON.stringify(Object.fromEntries(users), null, 2) + '\n', { flag: 'wx', mode: 0o600 });
      fs.renameSync(tmp, location);
      fs.chmodSync(location, 0o600);
    } finally {
      if (fs.existsSync(tmp)) fs.unlinkSync(tmp);
    }
  }
  return {
    has(username) { return users.has(username); },
    get(username) { return users.get(username) || null; },
    create(username, record) {
      if (users.has(username)) return false;
      users.set(username, record);
      try { persist(); } catch (error) { users.delete(username); throw error; }
      return true;
    },
    updateCounter(username, counter) {
      const existing = users.get(username);
      if (!existing) return false;
      if (!Number.isSafeInteger(counter) || counter < 0 || (existing.counter > 0 && counter <= existing.counter)) {
        throw new Error('Invalid or regressing signature counter');
      }
      const updated = { ...existing, counter };
      users.set(username, updated);
      try { persist(); } catch (error) { users.set(username, existing); throw error; }
      return true;
    },
  };
}
module.exports = { createUserStore };
