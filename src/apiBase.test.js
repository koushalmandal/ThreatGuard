import test from 'node:test';
import assert from 'node:assert/strict';
import { getApiBaseUrl } from './apiBase.js';

test('API URL follows localhost and LAN page hostnames', () => {
  assert.equal(getApiBaseUrl('localhost'), 'http://localhost:5000/api');
  assert.equal(getApiBaseUrl('192.168.1.104'), 'http://192.168.1.104:5000/api');
});

test('explicit API URL override takes precedence', () => {
  assert.equal(getApiBaseUrl('192.168.1.104', 'http://api.example.test/api'), 'http://api.example.test/api');
});
