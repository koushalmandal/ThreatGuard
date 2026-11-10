const test = require('node:test');
const assert = require('node:assert/strict');
const website = require('./website');
const score = require('./scoring');
const email = require('./email');
const pdf = require('./pdf');
const { isPublicAddress, inspectWebsite } = require('./websiteNetwork');
const validatePdfUpload = require('./pdfUpload');
const validateWebsiteInputPromise = import('../../../src/analyzerValidation.js').then(module => module.validateWebsiteInput);

const offline = { inspect: async url => ({ checks: {
  dns: { status: 'resolved', addresses: [{ address: '93.184.216.34', family: 4 }] },
  tls: url.protocol === 'https:' ? { status: 'valid', authorized: true, issuer: 'Test CA' } : { status: 'not_applicable' },
  redirects: { status: 'complete', chain: [{ host: url.hostname, statusCode: 200 }], finalHost: url.hostname, crossDomain: false },
} }) };

test('normal public HTTPS websites are SAFE with deterministic zero score', async () => {
  for (const input of ['https://www.wikipedia.org', 'https://www.google.com']) {
    const first = await website(input, offline); const second = await website(input, offline);
    assert.equal(first.riskScore, 0); assert.equal(first.threatLevel, 'safe');
    assert.deepEqual(first, second); assert.equal(first.checks.analysis.mode, 'rule_based');
  }
});

test('plain text and malformed or unsupported website inputs are validation errors', async () => {
  for (const input of ['hello123', 'hello world', 'https://bad host.test', 'ftp://example.com', 'https://-bad.test'])
    await assert.rejects(website(input), { status: 400 });
});

test('website feature parsing extracts URL components without losing redirect values', () => {
  const { url } = website.validate('http://user:secret@secure.account.paypal-login.evil.example.com:8080/login/verify?redirect=https%3A%2F%2Fother.example');
  const features = website.extractFeatures(url);
  assert.equal(features.protocol, 'http:');
  assert.equal(features.hostname, 'secure.account.paypal-login.evil.example.com');
  assert.equal(features.domain, 'example.com');
  assert.deepEqual(features.subdomains, ['secure', 'account', 'paypal-login', 'evil']);
  assert.equal(features.usernamePresent, true); assert.equal(features.passwordPresent, true);
  assert.equal(features.port, '8080'); assert.equal(features.path, '/login/verify');
  assert.deepEqual(features.encodedRedirectDestinations, [{ key: 'redirect', hostname: 'other.example', encoded: true }]);
  const ipFeatures = website.extractFeatures(website.validate('http://192.168.1.1/login').url);
  assert.equal(ipFeatures.ipAddress, '192.168.1.1'); assert.equal(ipFeatures.domain, '192.168.1.1');
});

test('backend accepts embedded URL credentials, scores them and strips them before inspection and persistence summary', async () => {
  let inspected;
  const result = await website('https://user:secret@example.com/path', { inspect: async url => { inspected = url; return offline.inspect(url); } });
  assert.equal(inspected.username, ''); assert.equal(inspected.password, '');
  assert.ok(result.indicators.some(item => item.name === 'Embedded URL credentials' && item.weight === 40));
  assert.doesNotMatch(result.inputSummary, /user|secret/);
});

test('encoded external redirects and combined suspicious URL structures reach scoring once', async () => {
  const result = await website('http://user:secret@secure.account.paypal-login.evil.example.com:8080/login/verify?redirect=https%3A%2F%2Fother.example', offline);
  for (const name of ['Embedded URL credentials', 'Excessive subdomains', 'Nonstandard web port', 'Encoded external redirect destination', 'Credential-lure URL structure', 'Brand-like hostname on another domain'])
    assert.equal(result.indicators.filter(item => item.name === name).length, 1, `${name} should be recorded once`);
  assert.equal(result.riskScore, 100); assert.equal(result.threatLevel, 'high');
});

test('shared scorer deduplicates findings, clamps scores, and applies requested thresholds', () => {
  const make = weight => ({ name: `signal-${weight}`, severity: 'medium', weight, explanation: 'Evidence present.' });
  assert.equal(score('website', 'x', [make(39)]).threatLevel, 'safe');
  assert.equal(score('website', 'x', [make(40)]).threatLevel, 'medium');
  assert.equal(score('website', 'x', [make(70)]).threatLevel, 'high');
  const duplicate = make(35);
  assert.equal(score('website', 'x', [duplicate, duplicate]).riskScore, 35);
  assert.equal(score('website', 'x', [make(100), make(100)]).riskScore, 100);
});

test('the eight requested URL examples have deterministic input, finding, score and network outcomes', async () => {
  const validateWebsiteInput = await validateWebsiteInputPromise;
  const cases = [
    ['https://www.wikipedia.org', true, 0, 'safe', []],
    ['https://www.google.com', true, 0, 'safe', []],
    ['https://github.com', true, 0, 'safe', []],
    ['http://testsafebrowsing.appspot.com/s/malware.html', true, 5, 'safe', ['Unencrypted HTTP']],
    ['http://user:secret@secure.account.paypal-login.evil.example.com:8080/login/verify?redirect=https%3A%2F%2Fother.example', true, 100, 'high', ['Embedded URL credentials', 'Encoded external redirect destination']],
    ['http://192.168.1.1/login', true, 40, 'medium', ['IP address host']],
    ['hello123', false],
    ['javascript:alert(1)', false],
  ];
  for (const [input, valid, expectedScore, expectedLevel, expectedIndicators = []] of cases) {
    const frontError = validateWebsiteInput(input);
    if (!valid) {
      assert.ok(frontError, `${input} must fail frontend validation`);
      await assert.rejects(website(input, offline), { status: 400 });
      continue;
    }
    assert.equal(frontError, '', `${input} should pass frontend validation`);
    const analysis = await website(input, input.includes('192.168.1.1') ? { inspect: url => inspectWebsite(url) } : offline);
    assert.equal(analysis.riskScore, expectedScore, input);
    assert.equal(analysis.threatLevel, expectedLevel, input);
    for (const name of expectedIndicators) assert.ok(analysis.indicators.some(item => item.name === name), `${input}: missing ${name}`);
    if (input.includes('192.168.1.1')) assert.equal(analysis.checks.redirects.status, 'blocked');
    else assert.equal(analysis.checks.redirects.status, 'complete');
  }
});

test('frontend clears stale scan state before validation and shows only current request results', () => {
  const fs = require('node:fs');
  const app = fs.readFileSync(require('node:path').join(__dirname, '../../../src/App.jsx'), 'utf8');
  const submit = app.indexOf('async function submit(e)');
  const clear = app.indexOf('setScan(null)', submit);
  const validate = app.indexOf('const validation=', submit);
  const apiRequest = app.indexOf("api.post('/scans/website'", submit);
  assert.ok(submit >= 0 && clear > submit && clear < validate, 'must clear prior results before validating');
  assert.ok(apiRequest > validate, 'must validate before making API request');
  assert.match(app, /setScan\(response\.data\.scan\)/, 'must display current API response');
});

test('HTTP alone is a low weight signal and is not classified as a threat', async () => {
  const result = await website('http://example.com', offline);
  assert.equal(result.riskScore, 5); assert.equal(result.threatLevel, 'safe');
  assert.equal(result.indicators[0].weight, 5);
});

test('IP URL gets an indicator and private IP remote fetching is blocked', async () => {
  const result = await website('http://192.168.1.1/login', { inspect: url => inspectWebsite(url) });
  assert.ok(result.indicators.some(item => item.name === 'IP address host'));
  assert.equal(result.checks.redirects.status, 'blocked');
  assert.equal(result.threatLevel, 'medium');
  assert.ok(result.limitations.some(item => /No request was sent/.test(item)));
  assert.equal(isPublicAddress('192.168.1.1'), false);
});

test('multiple independently named suspicious URL structure signals accumulate to HIGH risk', async () => {
  const result = await website('http://user:secret@secure.account.paypal-login.evil.example.com:8080/login/verify?redirect=https%3A%2F%2Fother.example', offline);
  assert.ok(result.indicators.some(item => item.name === 'Embedded URL credentials'));
  assert.ok(result.indicators.some(item => item.name === 'Brand-like hostname on another domain'));
  assert.ok(result.indicators.some(item => item.name === 'Excessive subdomains'));
  assert.equal(result.riskScore, 100); assert.equal(result.threatLevel, 'high');
  assert.doesNotMatch(result.inputSummary, /user|secret/);
  assert.ok(result.indicators.every(item => item.name && item.severity && item.weight > 0 && item.explanation && item.recommendation));
});

test('known brand host is not flagged by substring matching', async () => {
  const result = await website('https://www.paypal.com', offline);
  assert.equal(result.indicators.some(item => item.name.includes('Brand-like')), false);
});

test('private DNS destinations are blocked before network request', async () => {
  const dns = require('node:dns').promises;
  const original = { resolve4: dns.resolve4, resolve6: dns.resolve6, resolveMx: dns.resolveMx, resolveNs: dns.resolveNs };
  try {
    dns.resolve4 = async () => ['192.168.1.20']; dns.resolve6 = async () => [];
    dns.resolveMx = async () => []; dns.resolveNs = async () => [];
    const result = await inspectWebsite(new URL('https://private.example'));
    assert.equal(result.checks.redirects.status, 'blocked'); assert.deepEqual(result.checks.dns.addresses, []);
  } finally { Object.assign(dns, original); }
});

test('email context rules leave routine announcements, account notices, and isolated urgency unflagged', async () => {
  const samples = [
    { subject: 'Class announcement', body: 'The lecture will begin at ten tomorrow in the usual classroom. Please bring your notes.' },
    { subject: 'Account notification', body: 'Your account settings were updated. You can review the notice by opening the college portal directly.' },
    { subject: 'Urgent meeting', body: 'Urgent: please attend the project meeting at 3 PM and bring the lab results.' },
    { subject: 'Security education', body: 'In this experiment, students discuss passwords, OTPs, account verification, and phishing examples.' },
  ];
  for (const sample of samples) {
    const result = await email({ sender: 'teacher@college.example', ...sample });
    assert.equal(result.riskScore, 0, sample.subject); assert.equal(result.threatLevel, 'safe');
    assert.equal(result.indicators.length, 0, sample.subject);
  }
});

test('email detects direct OTP/password/banking requests and increases risk for coercive urgency', async () => {
  const otp = await email({ sender: 'notice@outside.example', subject: 'Account notice', body: 'Reply with your OTP to finish the requested update.' });
  assert.ok(otp.indicators.some(item => item.name === 'Credential or OTP disclosure request' && item.weight === 40));
  assert.equal(otp.riskScore, 40); assert.equal(otp.threatLevel, 'medium');
  const password = await email({ sender: 'service@outside.example', subject: 'Password information', body: 'Please send your password in a reply to this message.' });
  assert.equal(password.riskScore, 40); assert.equal(password.threatLevel, 'medium');
  const banking = await email({ sender: 'billing@outside.example', subject: 'Bank details', body: 'Provide your bank account details using this reply.' });
  assert.ok(banking.indicators.some(item => item.name === 'Banking information request'));
  const strong = await email({ sender: 'alerts@gmail.com', displayName: 'Bank Security Team', subject: 'Final warning', body: 'Your account will be suspended within 24 hours unless you send your password and bank details immediately.' });
  assert.ok(strong.indicators.some(item => item.name === 'Sender brand/domain inconsistency' || item.name === 'Display name and sender mismatch'));
  assert.ok(strong.indicators.some(item => item.name === 'Urgent coercive credential or payment request' && item.weight === 70));
  assert.equal(strong.threatLevel, 'high'); assert.doesNotMatch(strong.inputSummary, /password|bank details/);
});

test('email analyzes suspicious external links and HTML visible/destination mismatches', async () => {
  const result = await email({ sender:'student@example.edu', subject:'Reference links', body:'Review this <a href="https://paypal-login.evil.example/login/verify">https://paypal-login.evil.example/login/verify</a> and https://bit.ly/reference' });
  assert.ok(result.indicators.some(item => item.name.includes('Brand-like hostname on another domain')));
  assert.ok(result.indicators.some(item => item.name.includes('URL shortener')));
  const multiple = await email({ sender:'student@example.edu', subject:'Reference list', body:'https://paypal-login.evil.example/login/verify and https://amazon-login.evil.example/login/verify' });
  assert.ok(multiple.indicators.some(item => item.name.includes('paypal-login.evil.example')));
  assert.ok(multiple.indicators.some(item => item.name.includes('amazon-login.evil.example')));
  assert.equal(multiple.threatLevel, 'high');
  const mismatch = await email({ sender:'student@example.edu', subject:'Notice', body:'Please review <a href="https://evil.example/path">https://trusted.example/</a> for details.' });
  assert.ok(mismatch.indicators.some(item => item.name === 'Visible link and destination mismatch' && item.weight === 35));
});

test('email input validation rejects empty and malformed data', async () => {
  await assert.rejects(email({}), /sender email address/);
  await assert.rejects(email({ sender: 'nope', subject: 'Hi', body: 'Body has sufficient characters.' }), /valid sender/);
  await assert.rejects(email({ sender: 'a@example.com', subject: ' ', body: 'Body has sufficient characters.' }), /subject/);
  await assert.rejects(email({ sender: 'a@example.com', subject: 'Hi', body: '   ' }), /at least 10/);
});

function makePdf(text = '', includeJavaScript = false) {
  const safeText = text.replace(/[\\()]/g, '\\$&');
  const stream = text ? `BT /F1 16 Tf 40 700 Td (${safeText}) Tj ET` : '';
  const catalog = includeJavaScript ? '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R /Names << /JavaScript << /Names [(demo) 6 0 R] >> >> >>' : '<< /Type /Catalog /Pages 2 0 R >>';
  const objects = [catalog,'<< /Type /Pages /Kids [3 0 R] /Count 1 >>','<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>','<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',`<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}\nendstream`];
  if (includeJavaScript) {
    const action = typeof includeJavaScript === 'string' ? includeJavaScript : 'app.launchURL("https://outside.example")';
    objects.push(`<< /S /JavaScript /JS (${action.replace(/[()\\]/g, '\\$&')}) >>`);
  }
  let out='%PDF-1.4\n'; const offsets=[0]; objects.forEach((object,index)=>{offsets.push(Buffer.byteLength(out));out+=`${index+1} 0 obj\n${object}\nendobj\n`;});
  const xref=Buffer.byteLength(out);out+=`xref\n0 ${objects.length+1}\n0000000000 65535 f \n`;for(const offset of offsets.slice(1))out+=`${String(offset).padStart(10,'0')} 00000 n \n`;out+=`trailer\n<< /Size ${objects.length+1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;return Buffer.from(out,'latin1');
}

test('PDF upload validation rejects missing, empty and renamed text files', () => {
  assert.throws(() => validatePdfUpload(undefined), /Choose a PDF file/);
  assert.throws(() => validatePdfUpload({ originalname:'empty.pdf', mimetype:'application/pdf', size:0, buffer:Buffer.alloc(0) }), /non-empty PDF/);
  assert.throws(() => validatePdfUpload({ originalname:'renamed.pdf', mimetype:'application/pdf', size:10, buffer:Buffer.from('plain text') }), /extension, PDF MIME/);
  assert.equal(validatePdfUpload({ originalname:'valid.pdf', mimetype:'application/pdf', size:10, buffer:Buffer.from('%PDF-1.4') }), true);
});

test('PDF rejects invalid files and does not flag academic technical terms or textual PDF marker mentions', async () => {
  await assert.rejects(pdf(Buffer.alloc(0)), /non-empty PDF/);
  await assert.rejects(pdf(Buffer.from('plain text')), /valid PDF/);
  await assert.rejects(pdf(Buffer.from('%PDF-1.4 damaged')), /Could not read this PDF/);
  await assert.rejects(pdf(makePdf()), /OCR is not configured/);
  const result = await pdf(makePdf('In this experiment, students discuss password fields and account verification. The text mentions /JavaScript /OpenAction but does not define PDF actions.'));
  assert.equal(result.checks.textExtraction.status, 'complete');
  assert.equal(result.riskScore, 0); assert.equal(result.threatLevel, 'safe');
  assert.equal(result.checks.ocr.status, 'not_configured'); assert.equal(result.checks.activeContent.status, 'inspected');
  assert.equal(result.checks.activeContent.javascriptActions, 0); assert.equal(result.checks.activeContent.executed, false);
  const collegeNotice = await pdf(makePdf('College notice: classes resume Monday. Visit the college portal at https://college.edu for the updated schedule.'));
  assert.equal(collegeNotice.riskScore, 0); assert.equal(collegeNotice.threatLevel, 'safe');
  const phraseOnly = await pdf(makePdf('Urgent payment required is a phrase in this example; no payment is requested from the reader.'));
  assert.equal(phraseOnly.riskScore, 0); assert.equal(phraseOnly.indicators.length, 0);
});

test('PDF flags direct credential requests and separately confirms PDF.js structural JavaScript actions', async () => {
  const otp = await pdf(makePdf('Please reply with your OTP to continue.'));
  assert.equal(otp.riskScore, 40); assert.equal(otp.threatLevel, 'medium');
  assert.ok(otp.indicators.some(item => item.name === 'Credential or OTP disclosure request'));
  const password = await pdf(makePdf('Please send your password using this reply.'));
  assert.equal(password.riskScore, 40); assert.ok(password.indicators.some(item => item.name === 'Credential or OTP disclosure request'));
  const urgent = await pdf(makePdf('Your account will be disabled within 24 hours unless you send your password immediately.'));
  assert.ok(urgent.indicators.some(item => item.name === 'Urgent coercive credential or payment request' && item.weight === 70));
  assert.equal(urgent.threatLevel, 'high');
  const active = await pdf(makePdf('A readable academic document.', true));
  assert.equal(active.checks.activeContent.status, 'inspected');
  assert.ok(active.checks.activeContent.javascriptActions > 0);
  assert.ok(active.indicators.some(item => item.name === 'PDF JavaScript uses potentially risky APIs'));
  assert.equal(active.checks.activeContent.executed, false);
});

test('PDF print-only OpenAction is disclosed but not scored as suspicious JavaScript', async () => {
  const result = await pdf(makePdf('A readable academic experiment.', 'this.print({bUI:true,bSilent:false,bShrinkToFit:true});'));
  assert.equal(result.riskScore, 0);
  assert.equal(result.threatLevel, 'safe');
  assert.ok(result.checks.activeContent.javascriptActions >= 1);
  assert.equal(result.checks.activeContent.javascriptAssessment, 'known_print_action');
  assert.equal(result.checks.activeContent.openActionPresent, true);
  assert.deepEqual(result.indicators, []);
  assert.equal(result.checks.activeContent.executed, false);
});

test('PDF checks suspicious external links while skipping reserved example links', async () => {
  const example = await pdf(makePdf('For example, documentation is at https://example.org/login/verify?redirect=https%3A%2F%2Fother.example'));
  assert.equal(example.checks.links.reservedExamplesSkipped, 1); assert.equal(example.riskScore, 0);
  const suspicious = await pdf(makePdf('Review https://paypal-login.evil.example.com/login/verify?redirect=https%3A%2F%2Foutside.test before continuing.'));
  assert.ok(suspicious.indicators.some(item => item.name.includes('Brand-like hostname on another domain')));
  assert.ok(suspicious.indicators.some(item => item.name.includes('Obfuscated URL encoding')));
});

test('PDF upload validation rejects a TXT file renamed as PDF', () => {
  assert.throws(() => validatePdfUpload({ originalname:'renamed.pdf', mimetype:'application/pdf', size:10, buffer:Buffer.from('plain text') }), /extension, PDF MIME/);
});
