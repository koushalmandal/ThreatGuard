const test = require('node:test');
const assert = require('node:assert/strict');
const { completedScanFilter, historySort } = require('./scanQueries');

test('dashboard query counts only owned completed scans with valid score/type/level', () => {
  assert.deepEqual(completedScanFilter('owner-hash'), {
    ownerHash: 'owner-hash',
    status: 'complete',
    type: { $in: ['website', 'email', 'pdf'] },
    riskScore: { $type: 'number', $gte: 0, $lte: 100 },
    threatLevel: { $in: ['safe', 'low', 'medium', 'suspicious', 'high', 'malicious'] },
  });
});

test('history sorts newest first with stable pagination ties; risk sort remains supported', () => {
  assert.deepEqual(historySort(), { createdAt: -1, _id: -1 });
  assert.deepEqual(historySort('date'), { createdAt: -1, _id: -1 });
  assert.deepEqual(historySort('risk'), { riskScore: -1, createdAt: -1, _id: -1 });
});
