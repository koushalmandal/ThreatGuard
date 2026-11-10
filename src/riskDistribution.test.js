import test from 'node:test';
import assert from 'node:assert/strict';
import { createRiskDistribution } from './riskDistribution.js';

test('risk distribution handles an empty database result without percentages', () => {
  const result = createRiskDistribution({ safe: 0, medium: 0, high: 0 });
  assert.equal(result.total, 0);
  assert.deepEqual(result.categories.map(category => category.percentage), [0, 0, 0]);
});

test('risk distribution represents all-safe, all-medium, all-high, and mixed scans', () => {
  for (const [levels, expectedIndex] of [
    [{ safe: 4, medium: 0, high: 0 }, 0],
    [{ safe: 0, medium: 4, high: 0 }, 1],
    [{ safe: 0, medium: 0, high: 4 }, 2],
  ]) {
    const result = createRiskDistribution(levels);
    assert.equal(result.total, 4);
    assert.equal(result.categories[expectedIndex].percentage, 100);
    assert.equal(result.categories.filter(category => category.percentage > 0).length, 1);
  }

  const mixed = createRiskDistribution({ safe: 2, medium: 1, high: 1 });
  assert.equal(mixed.total, 4);
  assert.deepEqual(mixed.categories.map(category => category.percentage), [50, 25, 25]);
});

test('missing or invalid categories are not silently counted as safe', () => {
  const result = createRiskDistribution({ medium: 2, unknown: 9, safe: 'invalid' });
  assert.equal(result.total, 2);
  assert.equal(result.categories[0].count, 0);
});
