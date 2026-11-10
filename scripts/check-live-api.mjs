import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { getAnonymousToken } from '../src/token.js';

const base = process.env.API_BASE_URL || 'http://127.0.0.1:5000/api';
let persistedToken = null;
const token = getAnonymousToken(
  { getItem: () => persistedToken, setItem: (_key, value) => { persistedToken = value; } },
  { getRandomValues(bytes) { bytes.set(randomBytes(bytes.length)); return bytes; } },
);
assert.match(token, /^[A-Za-z0-9_-]{43}$/);
assert.equal(persistedToken, token);
const headers = { 'X-Anonymous-Token': token };
const created = [];
async function call(path, options = {}) {
  const response = await fetch(`${base}${path}`, { ...options, headers: { ...headers, ...options.headers } });
  const data = response.headers.get('content-type')?.includes('application/json') ? await response.json() : null;
  return { response, data };
}
function pdfSample(message = 'Please send your OTP immediately to avoid account suspension.') {
  const content = message ? `BT /F1 16 Tf 40 700 Td (${message}) Tj ET` : '';
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    `<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream`,
  ];
  let out = '%PDF-1.4\n'; const offsets = [0];
  objects.forEach((obj, i) => { offsets.push(Buffer.byteLength(out)); out += `${i + 1} 0 obj\n${obj}\nendobj\n`; });
  const xref = Buffer.byteLength(out); out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets.slice(1)) out += `${String(offset).padStart(10, '0')} 00000 n \n`;
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(out, 'latin1');
}

try {
  let r = await fetch(`${base}/health`); assert.equal(r.status, 200); assert.equal((await r.json()).database, 'connected');
  for (const origin of ['http://localhost:5173', 'http://192.168.1.104:5173']) {
    const preflight = await fetch(`${base}/scans/pdf`, { method: 'OPTIONS', headers: { Origin: origin, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type,x-anonymous-token' } });
    assert.equal(preflight.status, 204); assert.equal(preflight.headers.get('access-control-allow-origin'), origin);
  }
  const unlistedPreflight = await fetch(`${base}/scans/pdf`, { method: 'OPTIONS', headers: { Origin: 'http://example.com', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type,x-anonymous-token' } });
  assert.equal(unlistedPreflight.headers.get('access-control-allow-origin'), null);
  let result = await call('/scans/website', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'http://user:secret@secure.account.paypal-login.evil.example:8080/login/verify?redirect=https%3A%2F%2Fother.example' }) });
  assert.equal(result.response.status, 201); assert.equal(result.data.scan.riskScore, 100); assert.equal(result.data.scan.threatLevel, 'high');
  for (const name of ['Embedded URL credentials','Excessive subdomains','Nonstandard web port','Encoded external redirect destination','Credential-lure URL structure','Brand-like hostname on another domain']) assert.ok(result.data.scan.indicators.some(item => item.name === name), `API result missing ${name}`);
  assert.doesNotMatch(result.data.scan.inputSummary, /user|secret/); assert.ok(!Object.hasOwn(result.data.scan, 'ownerHash'));
  const syntheticId = result.data.scan._id; const savedSynthetic = await call(`/scans/${syntheticId}`); assert.equal(savedSynthetic.response.status, 200); assert.equal(savedSynthetic.data.scan.riskScore, 100);
  assert.equal((await call(`/scans/${syntheticId}`, { method: 'DELETE' })).response.status, 200);
  result = await call('/scans/website', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'http://192.168.1.1/login' }) });
  assert.equal(result.response.status, 201); assert.equal(result.data.scan.riskScore, 40); assert.equal(result.data.scan.threatLevel, 'medium'); assert.ok(result.data.scan.indicators.some(item => item.name === 'IP address host')); assert.equal(result.data.scan.checks.redirects.status, 'blocked'); assert.equal(result.data.scan.checks.analysis.status, 'unverified');
  assert.equal((await call(`/scans/${result.data.scan._id}`, { method: 'DELETE' })).response.status, 200);
  const missingToken = await fetch(`${base}/scans/website`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'https://example.com' }) }); assert.equal(missingToken.status, 401);
  const malformedToken = await fetch(`${base}/scans/website`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Anonymous-Token': 'bad-token' }, body: JSON.stringify({ url: 'https://example.com' }) }); assert.equal(malformedToken.status, 401);
  const missingHistoryCapability = await fetch(`${base}/scans`); assert.equal(missingHistoryCapability.status, 401);
  const malformedHistoryCapability = await fetch(`${base}/scans`, { headers: { 'X-Anonymous-Token': 'bad-token' } }); assert.equal(malformedHistoryCapability.status, 401);
  result = await call('/scans/website', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'https://user:secret@example.com/path' }) });
  assert.equal(result.response.status, 201); assert.ok(result.data.scan._id); assert.equal(result.data.scan.status, 'complete'); created.push(result.data.scan._id); assert.ok(['safe','medium','high'].includes(result.data.scan.threatLevel)); assert.ok(result.data.scan.checks?.dns); assert.ok(result.data.scan.checks?.tls); assert.ok(result.data.scan.checks?.redirects); assert.equal(result.data.scan.checks?.analysis?.mode, 'rule_based'); assert.ok(result.data.scan.indicators.some(item => item.name === 'Embedded URL credentials')); assert.doesNotMatch(result.data.scan.inputSummary, /user|secret/); assert.ok(!Object.hasOwn(result.data.scan, 'ownerHash'));
  result = await call('/scans/email', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sender: 'alerts@gmail.com', displayName: 'Bank Security Team', subject: 'URGENT', body: 'Send your password and one-time password immediately at http://bit.ly/x' }) });
  assert.equal(result.response.status, 201); assert.ok(result.data.scan._id); assert.equal(result.data.scan.status, 'complete'); created.push(result.data.scan._id); assert.ok(result.data.scan.indicators.some(item => item.name === 'Urgent coercive credential or payment request')); assert.equal(result.data.scan.threatLevel, 'high');
  const form = new FormData(); form.append('file', new Blob([pdfSample()], { type: 'application/pdf' }), 'sample.pdf');
  result = await call('/scans/pdf', { method: 'POST', body: form });
  assert.equal(result.response.status, 201); assert.ok(result.data.scan._id); assert.equal(result.data.scan.status, 'complete'); created.push(result.data.scan._id); assert.match(result.data.scan.inputSummary, /1 page/); assert.ok(result.data.scan.indicators.some(item => item.name === 'Urgent coercive credential or payment request')); assert.equal(result.data.scan.checks.ocr.status, 'not_configured');
  result = await call('/dashboard/stats'); assert.equal(result.response.status, 200); assert.equal(result.data.total, 3); assert.deepEqual(result.data.types, { website: 1, email: 1, pdf: 1 });
  const expectedLevels = { safe: 0, medium: 0, high: 0 };
  for (const scanId of created) {
    const scanResult = await call(`/scans/${scanId}`); assert.equal(scanResult.response.status, 200);
    const level = scanResult.data.scan.threatLevel === 'safe' || scanResult.data.scan.threatLevel === 'low' ? 'safe' : scanResult.data.scan.threatLevel === 'medium' || scanResult.data.scan.threatLevel === 'suspicious' ? 'medium' : 'high';
    expectedLevels[level]++;
  }
  assert.deepEqual(result.data.levels, expectedLevels);
  result = await call('/scans'); assert.equal(result.response.status, 200); assert.equal(result.data.total, 3); assert.equal(result.data.scans.length, 3);
  const newestFirstIds = result.data.scans.map(scan => scan._id);
  const scanDates = result.data.scans.map(scan => Date.parse(scan.createdAt));
  assert.deepEqual(scanDates, [...scanDates].sort((a, b) => b - a));
  const pagedHistory = [];
  for (let page = 1; page <= 3; page++) {
    const pageResult = await call(`/scans?page=${page}&limit=1`);
    assert.equal(pageResult.response.status, 200);
    pagedHistory.push(pageResult.data.scans[0]._id);
  }
  assert.deepEqual(pagedHistory, newestFirstIds);
  for (const origin of ['http://localhost:5173', 'http://192.168.1.104:5173']) {
    const browserHistory = await call('/scans', { headers: { Origin: origin } });
    assert.equal(browserHistory.response.status, 200); assert.equal(browserHistory.response.headers.get('access-control-allow-origin'), origin);
    assert.equal(browserHistory.data.total, 3);
  }
  result = await call(`/scans/${created[0]}`); assert.equal(result.response.status, 200); assert.ok(!Object.hasOwn(result.data.scan, 'ownerHash'));
  const otherToken = randomBytes(32).toString('base64url');
  const privateResult = await fetch(`${base}/scans/${created[0]}`, { headers: { 'X-Anonymous-Token': otherToken } }); assert.equal(privateResult.status, 404);
  const otherHistory = await fetch(`${base}/scans`, { headers: { 'X-Anonymous-Token': otherToken } }); assert.equal((await otherHistory.json()).total, 0);
  const otherStats = await fetch(`${base}/dashboard/stats`, { headers: { 'X-Anonymous-Token': otherToken } }); assert.equal((await otherStats.json()).total, 0);
  const otherBulkDelete = await fetch(`${base}/scans`, { method: 'DELETE', headers: { 'X-Anonymous-Token': otherToken } }); assert.equal((await otherBulkDelete.json()).deleted, 0);
  result = await call('/scans'); assert.equal(result.data.total, 3);
  result = await call('/scans/website', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'http://localhost' }) }); assert.equal(result.response.status, 400);
  result = await call('/scans/website', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'not a valid url %%' }) }); assert.equal(result.response.status, 400);
  for (const url of ['daycyacg', 'hello world', 'javascript:alert(1)']) {
    result = await call('/scans/website', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
    assert.equal(result.response.status, 400); assert.match(result.data.error, /valid|URL/i);
  }
  for (const details of [{ sender: '', subject: 'Subject', body: 'Meaningful body content' }, { sender: 'broken', subject: 'Subject', body: 'Meaningful body content' }, { sender: 'a@example.com', subject: 'Subject', body: '   ' }]) {
    result = await call('/scans/email', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(details) }); assert.equal(result.response.status, 400);
  }
  const badPdf = new FormData(); badPdf.append('file', new Blob(['not a pdf'], { type: 'application/pdf' }), 'bad.pdf');
  result = await call('/scans/pdf', { method: 'POST', body: badPdf }); assert.equal(result.response.status, 400);
  const emptyPdf = new FormData(); emptyPdf.append('file', new Blob([], { type: 'application/pdf' }), 'empty.pdf');
  result = await call('/scans/pdf', { method: 'POST', body: emptyPdf }); assert.equal(result.response.status, 400);
  const renamedText = new FormData(); renamedText.append('file', new Blob(['%PDF-not really'], { type: 'text/plain' }), 'renamed.pdf');
  result = await call('/scans/pdf', { method: 'POST', body: renamedText }); assert.equal(result.response.status, 400);
  const textlessPdf = new FormData(); textlessPdf.append('file', new Blob([pdfSample('')], { type: 'application/pdf' }), 'scanned.pdf');
  result = await call('/scans/pdf', { method: 'POST', body: textlessPdf }); assert.equal(result.response.status, 400); assert.match(result.data.error, /OCR is not configured/);
  result = await call('/scans/pdf', { method: 'POST', body: new FormData() }); assert.equal(result.response.status, 400);
  const emptyEmail = await call('/scans/email', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); assert.equal(emptyEmail.response.status, 400);
  result = await call('/scans'); assert.equal(result.response.status, 200); assert.equal(result.data.total, 3, 'invalid inputs must not create completed scan records');
  const largePdf = new FormData(); largePdf.append('file', new Blob([Buffer.alloc(10 * 1024 * 1024 + 1)], { type: 'application/pdf' }), 'large.pdf');
  result = await call('/scans/pdf', { method: 'POST', body: largePdf }); assert.equal(result.response.status, 400);
  result = await call(`/scans/${created[0]}`, { method: 'DELETE' }); assert.equal(result.response.status, 200); created.shift();
  result = await call('/scans', { method: 'DELETE' }); assert.equal(result.response.status, 200); assert.equal(result.data.deleted, 2); created.length = 0;
  result = await call('/dashboard/stats'); assert.equal(result.data.total, 0);
  console.log('Integration checks passed: health/CORS, missing and malformed capability rejection, website/email/PDF persistence, dashboard/history/report isolation, invalid inputs, upload limits, and scoped deletion.');
} finally {
  await call('/scans', { method: 'DELETE' }).catch(() => {});
}
