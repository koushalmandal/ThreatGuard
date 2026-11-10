const test = require('node:test');
const assert = require('node:assert/strict');
const { getAllowedOrigins, isAllowedOrigin } = require('./cors');

test('development CORS allows only localhost and the configured LAN frontend', () => {
  const allowed = getAllowedOrigins('http://localhost:5173,http://192.168.1.104:5173');
  assert.equal(isAllowedOrigin('http://localhost:5173', allowed), true);
  assert.equal(isAllowedOrigin('http://192.168.1.104:5173', allowed), true);
  assert.equal(isAllowedOrigin('http://192.168.1.105:5173', allowed), false);
  assert.equal(isAllowedOrigin('http://example.com', allowed), false);
});

test('default development CORS origins are explicit', () => {
  assert.deepEqual(getAllowedOrigins(''), ['http://localhost:5173', 'http://192.168.1.104:5173']);
});
