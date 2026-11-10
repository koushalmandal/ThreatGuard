const EDUCATIONAL_CONTEXT = /\b(?:academic|coursework|lecture|textbook|lab(?:oratory)?|experiment|student|research|training simulation|phishing simulation|sample message|for example|e\.g\.)\b/i;
const CREDENTIAL = '(?:passwords?|passcodes?|login credentials?|one[- ]time (?:password|code)|otps?|verification code|authentication code|security code)';
const BANKING = '(?:bank(?:ing)? details?|bank account|routing number|credit card (?:number|details?)|debit card (?:number|details?)|cvv|security code)';
const REQUEST_VERB = '(?:send|reply(?:\s+with)?|provide|share|submit|enter|type|text|email|forward|disclose|verify)';

function splitSentences(text) {
  return String(text || '').replace(/\r/g, '\n').split(/(?<=[.!?])\s+|\n+/).map(sentence => sentence.trim()).filter(Boolean);
}

function isNegatedDisclosure(sentence, targetIndex) {
  const prefix = sentence.slice(Math.max(0, targetIndex - 48), targetIndex);
  return /\b(?:never|do not|don't|should not|shouldn't|cannot|can't|avoid)\b(?:\W+\w+){0,5}\W*$/i.test(prefix);
}

function directRequest(sentence, targetPattern) {
  const targetFirst = new RegExp(`\\b(?:your\\s+)?${targetPattern}\\b[^.!?]{0,50}\\b(?:to|by|via)\\s+(?:reply|send|email|text|provide|share|submit|enter|type)\\b`, 'i');
  const actionFirst = new RegExp(`\\b${REQUEST_VERB}\\b[^.!?]{0,45}\\b(?:your\\s+)?${targetPattern}\\b`, 'i');
  const match = sentence.match(targetFirst) || sentence.match(actionFirst);
  if (!match) return false;
  if (isNegatedDisclosure(sentence, match.index)) return false;
  return !EDUCATIONAL_CONTEXT.test(sentence);
}

function findDisclosureRequests(text) {
  const requests = { credentials: [], banking: [], payment: [], pressure: [], accountThreats: [] };
  for (const sentence of splitSentences(text)) {
    const credential = directRequest(sentence, CREDENTIAL);
    const banking = directRequest(sentence, BANKING);
    const payment = /\b(?:send|wire|transfer|purchase|pay)\b[^.!?]{0,45}\b(?:money|funds|payment|wire transfer|bank transfer|gift cards?|cryptocurrency|bitcoin)\b/i.test(sentence)
      || /\b(?:wire|bank) transfer\b[^.!?]{0,35}\b(?:to|into)\b/i.test(sentence);
    const accountThreat = /\baccount\b[^.!?]{0,55}\b(?:will be|may be|unless|otherwise|or else|within|immediately)\b[^.!?]{0,35}\b(?:suspend\w*|lock\w*|clos\w*|terminat\w*|disable\w*)\b/i.test(sentence)
      || /\b(?:suspend\w*|lock\w*|clos\w*|terminat\w*|disable\w*)\b[^.!?]{0,40}\baccount\b[^.!?]{0,35}\b(?:unless|within|immediately|otherwise|or else)\b/i.test(sentence);
    const pressure = /\b(?:immediately|within\s+(?:\d+\s+)?(?:hours?|minutes?|days?)|act now|final warning|avoid arrest|legal action|or else|otherwise|unless you|account (?:will be|may be) (?:suspended|locked|closed|disabled))\b/i.test(sentence);
    if (credential && pressure) requests.pressure.push(sentence);
    else if (credential) requests.credentials.push(sentence);
    if (banking) requests.banking.push(sentence);
    if (payment && pressure) requests.pressure.push(sentence);
    else if (payment) requests.payment.push(sentence);
    if (accountThreat && !credential && !banking && !payment) requests.accountThreats.push(sentence);
  }
  for (const key of Object.keys(requests)) requests[key] = [...new Set(requests[key])].slice(0, 5);
  return requests;
}

module.exports = { splitSentences, findDisclosureRequests, EDUCATIONAL_CONTEXT };
