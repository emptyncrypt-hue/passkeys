'use strict';
/* Runs in a real browser. No WebAuthn mocks or virtual authenticators. */
(() => {
  const API = PasskeyAcceptance;
  const KEY = 'passkey-real-device-acceptance-v1';
  const byId = id => document.getElementById(id);
  const saved = (() => { try { return JSON.parse(sessionStorage.getItem(KEY) || 'null'); } catch { return null; } })();
  const generateUsername = () => 'qa-' + Array.from(crypto.getRandomValues(new Uint8Array(9)), x => x.toString(16).padStart(2, '0')).join('');
  const state = saved && Array.isArray(saved.results) && /^qa-[a-f0-9]{18}$/.test(saved.username)
    ? saved : { username: generateUsername(), startedAt: new Date().toISOString(), results: [], reloadObserved: false };
  let lastAssertion = null; // Never stored to browser storage, logs, or evidence.
  if (performance.getEntriesByType('navigation')[0]?.type === 'reload' &&
      state.results.some(x => x.id === 'LOGIN' && x.status === 'PASS') &&
      state.results.some(x => x.id === 'REPLAY' && x.status === 'PASS')) state.reloadObserved = true;
  function save() { sessionStorage.setItem(KEY, JSON.stringify(state)); }
  const status = id => state.results.find(x => x.id === id)?.status || 'NOT_RUN';
  function requireCases(...ids) {
    for (const id of ids) if (status(id) !== 'PASS') throw Error('Complete ' + id + ' first');
  }
  function mark(id, passed, message) {
    const record = { id, status: passed ? 'PASS' : 'FAIL', at: new Date().toISOString(), detail: String(message).slice(0, 150) };
    state.results = state.results.filter(x => x.id !== id).concat(record);
    save(); render();
  }
  function note(message) { byId('message').textContent = message; }
  async function request(path, body) {
    const response = await fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    let value = null;
    try { value = await response.json(); } catch { /* HTTP status still checked. */ }
    return { status: response.status, value };
  }
  async function session(expectedStatus, expectedUsername) {
    const response = await fetch('/session', { credentials: 'same-origin', cache: 'no-store' });
    if (response.status !== expectedStatus) throw Error('Expected session HTTP ' + expectedStatus + ', observed ' + response.status);
    if (expectedStatus === 200) {
      const data = await response.json();
      if (!data.authenticated || data.username !== expectedUsername) throw Error('Session did not match the enrolled identity');
      // Cookie is HttpOnly; browser JavaScript must not read it.
      if (document.cookie.split(';').some(x => /^\s*(?:__Host-passkey_session|passkey_dev_session)=/.test(x))) throw Error('Session cookie accessible to JavaScript');
    }
  }
  async function login(keepAssertion) {
    const begin = await request('/login/start', { username: state.username });
    if (begin.status !== 200) throw Error('Login challenge HTTP ' + begin.status);
    const assertion = await navigator.credentials.get({ publicKey: API.requestOptions(begin.value) });
    if (!assertion) throw Error('Authenticator returned no assertion');
    const data = API.assertionJSON(assertion);
    const finish = await request('/login/finish', { username: state.username, data });
    if (finish.status !== 200 || finish.value?.res !== true) throw Error('Login verification HTTP ' + finish.status);
    await session(200, state.username);
    if (keepAssertion) lastAssertion = data;
    return 'Native assertion verified, HttpOnly session validated';
  }
  const actions = {
    async ENV() {
      if (!isSecureContext || !window.PublicKeyCredential || !navigator.credentials?.create || !navigator.credentials?.get) {
        throw Error('Native WebAuthn requires a secure context and a compatible browser');
      }
      return 'Secure context and native WebAuthn available';
    },
    async REGISTER() {
      requireCases('ENV');
      const begin = await request('/register/start', { username: state.username });
      if (begin.status !== 200) throw Error('Registration options HTTP ' + begin.status + '; reset requires a new fresh server account');
      const credential = await navigator.credentials.create({ publicKey: API.creationOptions(begin.value) });
      if (!credential) throw Error('No platform/roaming credential created');
      const finish = await request('/register/finish', { username: state.username, data: API.registrationJSON(credential) });
      if (finish.status !== 200 || finish.value?.res !== true) throw Error('Registration verification HTTP ' + finish.status);
      return 'Physical passkey registration accepted (HTTP 200)';
    },
    async DUPLICATE() {
      requireCases('REGISTER');
      const result = await request('/register/start', { username: state.username });
      if (result.status !== 409) throw Error('Expected duplicate enrollment 409; got ' + result.status);
      return 'Account overwrite rejected (HTTP 409)';
    },
    async LOGIN() { requireCases('REGISTER', 'DUPLICATE'); return login(true); },
    async REPLAY() {
      requireCases('LOGIN');
      if (!lastAssertion) throw Error('Replay material exists only in this page. Run LOGIN again, then REPLAY before refresh.');
      const result = await request('/login/finish', { username: state.username, data: lastAssertion });
      if (result.status !== 401) throw Error('Expected replay rejection 401; got ' + result.status);
      await session(200, state.username);
      lastAssertion = null;
      return 'Replayed assertion rejected; original session remains valid';
    },
    async SESSION() {
      requireCases('LOGIN', 'REPLAY');
      if (!state.reloadObserved || !byId('reloadConfirmed').checked) throw Error('Refresh this tab after REPLAY, then confirm reload');
      await session(200, state.username);
      return 'Existing HttpOnly browser session survived page reload';
    },
    async LOGOUT() {
      requireCases('SESSION');
      const result = await request('/logout', {});
      if (result.status !== 200) throw Error('Logout HTTP ' + result.status);
      await session(401);
      return 'Logout revoked access and cleared cookie';
    },
    async CANCEL() {
      requireCases('LOGOUT');
      await session(401);
      note('When the native authenticator prompt appears, CANCEL it. Do not use biometric/PIN here.');
      const begin = await request('/login/start', { username: state.username });
      if (begin.status !== 200) throw Error('Login options HTTP ' + begin.status);
      let cancelled = false;
      try { await navigator.credentials.get({ publicKey: API.requestOptions(begin.value) }); }
      catch (error) { cancelled = error?.name === 'NotAllowedError' || error?.name === 'AbortError'; }
      await session(401);
      if (!cancelled || !byId('cancelObserved').checked) throw Error('Prompt cancellation must be observed and attested by operator');
      return 'Authenticator prompt cancelled; no session created';
    },
    async RESTART() {
      requireCases('CANCEL');
      if (!byId('backendRestarted').checked) throw Error('Operator must restart backend and confirm persistent AUTH_STORE_PATH');
      await session(401);
      await login(false);
      return 'Passkey re-login succeeded after operator-confirmed backend restart';
    },
    async UV() {
      requireCases('LOGIN', 'RESTART');
      if (!byId('uvObserved').checked) throw Error('Operator must attest having completed biometric or PIN verification');
      return 'Operator attested real-device biometric or device PIN user verification';
    },
  };
  let running = false;
  async function run(id) {
    if (running) return;
    running = true;
    render();
    try {
      const detail = await actions[id]();
      mark(id, true, detail);
      note(id + ' PASS — ' + detail);
    } catch (error) {
      mark(id, false, error?.name === 'NotAllowedError' ? 'Authenticator request was denied or cancelled' : error?.message || 'Unknown error');
      note(id + ' FAIL — ' + (error?.message || 'Unknown error'));
    } finally { running = false; render(); }
  }
  function metadata() {
    return { testerAlias: byId('tester').value.trim(), deviceClass: byId('deviceClass').value, model: byId('model').value.trim(),
      os: byId('os').value.trim(), browser: byId('browser').value.trim(),
      authenticator: byId('authenticator').value, realDeviceConfirmed: byId('realDevice').checked };
  }
  function render() {
    byId('username').textContent = state.username;
    const tbody = byId('cases');
    tbody.replaceChildren();
    for (const [id, description] of API.CASES) {
      const row = document.createElement('tr');
      const idCell = document.createElement('td'); idCell.textContent = id;
      const infoCell = document.createElement('td'); infoCell.textContent = description;
      const resultCell = document.createElement('td'); resultCell.textContent = status(id); resultCell.className = status(id);
      const actionCell = document.createElement('td');
      const button = document.createElement('button'); button.textContent = 'Run'; button.disabled = running;
      button.addEventListener('click', () => run(id)); actionCell.append(button);
      row.append(idCell, infoCell, resultCell, actionCell); tbody.append(row);
    }
    const environment = metadata();
    const complete = API.evaluate(state.results, environment) && Object.entries(environment).every(([k,v]) => k === 'realDeviceConfirmed' || Boolean(v));
    byId('verdict').textContent = complete ? 'PASS — all required test steps completed on operator-attested physical device' :
      'NOT ACCEPTED — required steps and physical-device attestation must all pass';
  }
  const fields = ['tester', 'deviceClass', 'model', 'os', 'browser', 'authenticator', 'realDevice', 'reloadConfirmed', 'backendRestarted', 'cancelObserved', 'uvObserved'];
  const storedFields = saved?.fields || {};
  for (const id of fields) {
    const element = byId(id);
    if (Object.prototype.hasOwnProperty.call(storedFields, id)) {
      if (element.type === 'checkbox') element.checked = storedFields[id]; else element.value = storedFields[id];
    }
    element.addEventListener('change', () => {
      state.fields = Object.fromEntries(fields.map(name => [name, byId(name).type === 'checkbox' ? byId(name).checked : byId(name).value]));
      save(); render();
    });
  }
  byId('export').addEventListener('click', async () => {
    if (running) return;
    const environment = metadata();
    if (Object.entries(environment).some(([key, value]) => key !== 'realDeviceConfirmed' && !value)) {
      note('Fill all device/tester metadata before exporting'); return;
    }
    const payload = {
      schema: 'passkeys-real-device-acceptance/v1', suiteVersion: API.VERSION,
      startedAt: state.startedAt, exportedAt: new Date().toISOString(), origin: location.origin,
      userAgent: navigator.userAgent, environment,
      cases: API.CASES.map(([id]) => state.results.find(x => x.id === id) || { id, status: 'NOT_RUN' }),
      verdict: API.evaluate(state.results, environment) && Object.entries(environment).every(([k,v]) => k === 'realDeviceConfirmed' || Boolean(v)) ? 'PASS' : 'NOT_ACCEPTED',
      provenance: 'operator-attested; device authenticity NOT cryptographically verified',
    };
    const content = JSON.stringify(payload);
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content));
    const report = JSON.stringify({ ...payload, sha256: API.base64urlFromBytes(digest) }, null, 2);
    const url = URL.createObjectURL(new Blob([report + '\n'], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url;
    link.download = 'real-device-passkey-acceptance-' + new Date().toISOString().slice(0, 10) + '.json';
    link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    note('Evidence exported. Hash detects file alterations, but does not prove physical hardware attestation.');
  });
  byId('reset').addEventListener('click', () => {
    if (!confirm('Reset runner state? This will NOT delete the account/passkey from the backend or authenticator.')) return;
    sessionStorage.removeItem(KEY); location.reload();
  });
  save(); render();
})();
