const test = require('node:test');
const assert = require('node:assert/strict');
const connectDB = require('./db');

test('Atlas connection summary identifies expected host without credentials', () => {
  const summary = connectDB.getMongoConfigSummary(
    'mongodb+srv://test-user:secret-value@cluster0.wmlp8on.mongodb.net/threatguard?retryWrites=true&w=majority',
  );
  assert.deepEqual(summary, {
    configured: true,
    parseable: true,
    scheme: 'mongodb+srv:',
    host: 'cluster0.wmlp8on.mongodb.net',
    database: 'threatguard',
    hasUsername: true,
    hasPassword: true,
    matchesExpectedAtlasHost: true,
    isSrv: true,
  });
  assert.equal(JSON.stringify(summary).includes('secret-value'), false);
});

test('safe MongoDB diagnostics preserve nested refusal codes without error messages', () => {
  const nested = Object.assign(new Error('sensitive URI must not be logged'), { name: 'MongoNetworkError', code: 'ECONNREFUSED' });
  const summary = connectDB.safeErrorSummary({
    name: 'MongooseServerSelectionError',
    code: 'ETIMEDOUT',
    message: 'sensitive URI must not be logged',
    reason: { servers: new Map([['shard.example.mongodb.net:27017', { type: 'Unknown', error: nested }]]) },
  });
  const serialized = JSON.stringify(summary);
  assert.equal(summary.code, 'ETIMEDOUT');
  assert.equal(summary.servers[0].error.code, 'ECONNREFUSED');
  assert.equal(serialized.includes('sensitive URI'), false);
  assert.equal(serialized.includes('secret'), false);
});
