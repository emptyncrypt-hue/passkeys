'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../index');
test('acceptance UI is not served when feature flag is disabled', async (t) => {
  assert.notEqual(process.env.APP_ENABLE_ACCEPTANCE, '1', 'This negative test must run with acceptance disabled');
  const server = app.listen(0);
  t.after(() => server.close());
  await new Promise(resolve => server.once('listening', resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  for (const endpoint of ['/acceptance', '/acceptance/protocol.js', '/acceptance/runner.js', '/acceptance/verify-evidence.js']) {
    const response = await fetch(base + endpoint);
    assert.equal(response.status, 404, 'Unexpected acceptance file exposed: ' + endpoint);
  }
});
