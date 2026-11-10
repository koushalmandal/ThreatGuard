import test from 'node:test';
import assert from 'node:assert/strict';
import { getAnonymousToken, STORAGE_KEY } from './token.js';

function storage(initial = null) {
  let value = initial;
  return { getItem: () => value, setItem: (_key, next) => { value = next; }, read: () => value };
}

test('anonymous token is generated as 32 random bytes, persisted, and reused', () => {
  const fakeStorage = storage();
  let calls = 0;
  const fakeCrypto = { getRandomValues(bytes) { calls++; for (let i = 0; i < bytes.length; i++) bytes[i] = i; return bytes; } };
  const first = getAnonymousToken(fakeStorage, fakeCrypto);
  const second = getAnonymousToken(fakeStorage, fakeCrypto);
  assert.match(first, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(fakeStorage.read(), first);
  assert.equal(second, first);
  assert.equal(calls, 1);
  assert.equal(STORAGE_KEY, 'tg_anonymous_token');
});

test('malformed stored token is replaced before an API request', () => {
  const fakeStorage = storage('undefined');
  const token = getAnonymousToken(fakeStorage, { getRandomValues(bytes) { bytes.fill(9); return bytes; } });
  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(fakeStorage.read(), token);
});
