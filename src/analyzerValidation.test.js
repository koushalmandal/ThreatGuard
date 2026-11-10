import test from 'node:test';
import assert from 'node:assert/strict';
import { validateEmailInput, validateWebsiteInput } from './analyzerValidation.js';

test('frontend URL validation accepts HTTP(S) domains and rejects free text', () => {
  for (const url of ['https://www.wikipedia.org', 'https://www.google.com', 'http://example.com']) assert.equal(validateWebsiteInput(url), '');
  for (const url of ['daycyacg', 'hello', 'hello world', 'ftp://example.com', 'https://bad host.test']) assert.ok(validateWebsiteInput(url));
});

test('frontend email validation requires a valid sender, subject, and meaningful body', () => {
  assert.match(validateEmailInput({}), /sender email/);
  assert.match(validateEmailInput({ sender: 'not-an-email', subject: 'Subject', body: 'Meaningful body text' }), /valid sender/);
  assert.match(validateEmailInput({ sender: 'a@example.com', subject: '', body: 'Meaningful body text' }), /subject/);
  assert.match(validateEmailInput({ sender: 'a@example.com', subject: 'Subject', body: '  ' }), /body/);
  assert.equal(validateEmailInput({ sender: 'a@example.com', subject: 'Subject', body: 'Meaningful body text' }), '');
});
