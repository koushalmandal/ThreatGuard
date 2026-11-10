const score = require('./scoring');
const analyzeWebsite = require('./website');
const { findDisclosureRequests } = require('./textSignals');

const BRANDS = {
  microsoft: ['microsoft.com', 'microsoftonline.com'], google: ['google.com', 'googlemail.com', 'gmail.com'],
  paypal: ['paypal.com'], apple: ['apple.com', 'icloud.com'], amazon: ['amazon.com', 'amazon.co.uk'],
  netflix: ['netflix.com'], dropbox: ['dropbox.com'],
};
const CONSUMER_DOMAINS = new Set(['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']);
const EMAIL_PATTERN = /^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$/i;
const item = (name, severity, weight, explanation, evidence, recommendation) => ({ name, severity, weight, explanation, evidence, recommendation });

function normalizeLookalike(label) { return label.toLowerCase().replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's'); }
function matchesOfficialDomain(domain, domains) { return domains.some(official => domain === official || domain.endsWith(`.${official}`)); }

module.exports = async function analyzeEmail(input) {
  if (!input || typeof input !== 'object') throw Object.assign(new Error('Provide email details.'), { status: 400 });
  const sender = String(input.sender || '').trim().slice(0, 254);
  const displayName = String(input.displayName || '').trim().slice(0, 120);
  const subject = String(input.subject || '').trim().slice(0, 300);
  const body = String(input.body || '').trim();
  const headers = String(input.headers || '').trim();
  if (!sender) throw Object.assign(new Error('Enter the sender email address.'), { status: 400 });
  if (body.length > 100000 || headers.length > 32000) throw Object.assign(new Error('Email body must be at most 100,000 characters and optional headers at most 32,000 characters.'), { status: 400 });
  if (!EMAIL_PATTERN.test(sender)) throw Object.assign(new Error('Enter a valid sender email address.'), { status: 400 });
  if (!subject) throw Object.assign(new Error('Enter an email subject.'), { status: 400 });
  if (body.length < 10) throw Object.assign(new Error('Enter an email body with at least 10 non-whitespace characters.'), { status: 400 });

  const findings = [];
  const text = `${subject}\n${body}`;
  const headerEvidence = { status: headers ? 'provided_unverified' : 'not_provided' };
  if (headers) {
    const authResults = headers.split(/\r?\n/).filter(line => /^(authentication-results|received-spf|dkim-signature)\s*:/i.test(line));
    const claims = [];
    for (const line of authResults.slice(0, 10)) for (const match of line.matchAll(/\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b/ig)) claims.push({ mechanism: match[1].toLowerCase(), claimedResult: match[2].toLowerCase() });
    headerEvidence.claims = claims;
    headerEvidence.notice = 'Header text was supplied by the user and is not authenticated; no SPF, DKIM, or DMARC verification was performed.';
  }

  const domain = sender.split('@')[1].toLowerCase();
  const claimedBrand = Object.keys(BRANDS).find(brand => displayName.toLowerCase().includes(brand));
  const officialClaim = claimedBrand && matchesOfficialDomain(domain, BRANDS[claimedBrand]);
  const domainLabels = domain.split('.');
  const lookalikeBrand = Object.entries(BRANDS).find(([brand, officialDomains]) =>
    !matchesOfficialDomain(domain, officialDomains) && domainLabels.some(label => normalizeLookalike(label).includes(brand) && label.toLowerCase() !== brand)
  )?.[0];
  if ((claimedBrand && !officialClaim) || lookalikeBrand) {
    const brand = claimedBrand && !officialClaim ? claimedBrand : lookalikeBrand;
    findings.push(item('Sender brand/domain inconsistency', 'medium', 25,
      'The display name or sender hostname resembles a known brand while using a different domain. This is a heuristic; sender identity is not verified.',
      `Brand-like term: ${brand}; sender domain: ${domain}.`, 'Verify the sender through the organization’s official website or a known contact method.'));
  } else if (domain.includes('xn--')) {
    findings.push(item('Internationalized sender domain', 'medium', 20, 'The sender domain uses punycode and may be difficult to distinguish visually.', domain, 'Check the exact sender domain before replying or opening links.'));
  } else if (CONSUMER_DOMAINS.has(domain) && /\b(?:bank|payroll|it support|security team|administrator)\b/i.test(displayName)) {
    findings.push(item('Display name and sender mismatch', 'medium', 20, 'An organization or security-team style name is paired with a consumer mailbox domain.', `${displayName || 'Display name'} <${domain}>.`, 'Contact the organization through a known official channel.'));
  }

  const requests = findDisclosureRequests(text);
  const pressuredSentences = new Set(requests.pressure);
  if (pressuredSentences.size) findings.push(item('Urgent coercive credential or payment request', 'high', 70,
    'The message combines a request for sensitive information or money with urgency, a deadline, or a threat.',
    [...pressuredSentences].map(sentence => sentence.slice(0, 180)).join(' | '), 'Do not reply or follow its links. Verify the request independently.'));
  const independentCredentialRequests = requests.credentials.filter(sentence => !pressuredSentences.has(sentence));
  const independentBankRequests = requests.banking.filter(sentence => !pressuredSentences.has(sentence));
  const independentPaymentRequests = requests.payment.filter(sentence => !pressuredSentences.has(sentence));
  if (independentCredentialRequests.length) findings.push(item('Credential or OTP disclosure request', 'high', 40,
    'The message directly instructs the recipient to send, enter, or disclose a password, OTP, or authentication code.', independentCredentialRequests.map(x => x.slice(0, 180)).join(' | '), 'Never send passwords or one-time codes in response to an email.'));
  if (independentBankRequests.length) findings.push(item('Banking information request', 'high', 40,
    'The message directly requests banking or payment-card details.', independentBankRequests.map(x => x.slice(0, 180)).join(' | '), 'Verify payment or banking changes using a known contact method.'));
  if (independentPaymentRequests.length) findings.push(item('Unusual payment instruction', 'high', 35,
    'The message directs the recipient to send money, make a wire transfer, or purchase an unusual payment instrument.', independentPaymentRequests.map(x => x.slice(0, 180)).join(' | '), 'Confirm payment instructions independently before sending funds.'));
  if (requests.accountThreats.length) findings.push(item('Account suspension or closure threat', 'medium', 15,
    'The message threatens an account consequence with a deadline or condition. No isolated use of “account” or “urgent” is scored.', requests.accountThreats.map(x => x.slice(0, 180)).join(' | '), 'Open the service directly through its known official address to check account notices.'));

  const suppliedUrls = Array.isArray(input.urls) ? input.urls.filter(value => typeof value === 'string') : [];
  const extractedUrls = text.match(/https?:\/\/[^\s<>"')\]]+/gi) || [];
  const links = [...new Set([...suppliedUrls, ...extractedUrls].map(value => value.slice(0, 2048)))].slice(0, 30);
  const analyzedHosts = new Set();
  for (const rawLink of links.slice(0, 12)) {
    try {
      const { url } = analyzeWebsite.validate(rawLink.replace(/[.,;:!?]+$/, ''));
      const host = url.hostname.toLowerCase();
      if (analyzedHosts.has(host)) continue;
      analyzedHosts.add(host);
      for (const indicator of analyzeWebsite.analyzeStructure(url)) {
        findings.push({ ...indicator, category: 'email_link', name: `Email link ${host}: ${indicator.name}`, evidence: `Host ${host}; ${indicator.evidence}`.slice(0, 180) });
      }
    } catch { /* Invalid extracted text is not treated as a threat indicator. */ }
  }

  const anchors = [...text.matchAll(/<a\b[^>]*\bhref\s*=\s*(['"])(.*?)\1[^>]*>([\s\S]*?)<\/a\s*>/gi)].slice(0, 20);
  for (const [, , destination, labelHtml] of anchors) {
    const visible = labelHtml.replace(/<[^>]*>/g, '').replace(/&amp;/gi, '&').trim();
    if (!/^https?:\/\//i.test(visible)) continue;
    try {
      const actualHost = analyzeWebsite.validate(destination).url.hostname.toLowerCase();
      const visibleHost = new URL(visible).hostname.toLowerCase();
      if (actualHost !== visibleHost) findings.push(item('Visible link and destination mismatch', 'high', 35,
        'The hostname shown in the supplied HTML differs from the actual link destination.',
        `Visible host ${visibleHost}; destination host ${actualHost}.`, 'Do not follow the link; navigate to the expected site directly.'));
    } catch { /* URL structure validation handles usable destinations. */ }
  }

  const summary = `Email scan from ${domain}`;
  return score('email', summary, findings,
    ['Verify sensitive requests through a known contact method. Never share passwords or one-time codes by email.'],
    ['Email body and optional header text are analyzed in memory and are not retained. Sender identity is not verified.', 'At most 12 distinct link hosts receive structural URL checks; links are not fetched.', headers ? 'Authentication-related header claims are user-supplied and unverified; SPF, DKIM, and DMARC were not independently checked.' : 'SPF, DKIM, DMARC, and full message-header verification were not performed.'],
    { checks: { headers: headerEvidence, links: { status: 'structural_only', extracted: links.length, analyzedHosts: analyzedHosts.size } } });
};
