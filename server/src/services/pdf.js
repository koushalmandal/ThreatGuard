const score = require('./scoring');
const website = require('./website');
const { findDisclosureRequests } = require('./textSignals');

const item = (name, severity, weight, explanation, evidence, recommendation) => ({ name, severity, weight, explanation, evidence, recommendation });
const RESERVED_EXAMPLE_HOST = host => host === 'example.com' || host === 'example.org' || host === 'example.net'
  || /\.(?:example|test|invalid|localhost)$/.test(host);

function structuralCount(value) {
  if (!value) return 0;
  if (typeof value.size === 'number') return value.size;
  if (Array.isArray(value)) return value.length;
  return typeof value === 'object' ? Object.keys(value).length : 0;
}

function getJavaScriptActionScripts(actions) {
  if (actions instanceof Map) return [...actions.values()].flatMap(value => Array.isArray(value) ? value : [value]).filter(value => typeof value === 'string');
  if (Array.isArray(actions)) return actions.filter(value => typeof value === 'string');
  if (actions && typeof actions === 'object') return Object.values(actions).flatMap(value => Array.isArray(value) ? value : [value]).filter(value => typeof value === 'string');
  return [];
}

function assessJavaScriptActions(actions) {
  const scripts = getJavaScriptActionScripts(actions).map(script => script.trim()).filter(Boolean);
  const printOnly = scripts.length > 0 && scripts.every(script => /^this\.print\s*\(\s*\{[^{}]*\}\s*\)\s*;?$/i.test(script));
  const suspiciousBehavior = scripts.some(script => /\b(?:app\.launchURL|(?:this|doc)\.submitForm|(?:this|doc)\.mailDoc|app\.openDoc|(?:this|doc)\.exportDataObject|util\.readFileIntoStream)\b|\b(?:eval|Function)\s*\(/i.test(script));
  return {
    scripts,
    assessment: printOnly ? 'known_print_action' : suspiciousBehavior ? 'suspicious_api_usage' : scripts.length ? 'unclassified_action' : 'content_not_exposed',
    suspiciousBehavior,
  };
}

module.exports = async function analyzePdf(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) throw Object.assign(new Error('Choose a non-empty PDF file.'), { status: 400 });
  if (buffer.subarray(0, 5).toString() !== '%PDF-') throw Object.assign(new Error('File content is not a valid PDF. A .pdf filename alone is not sufficient.'), { status: 400 });
  const { getDocument } = await import('pdfjs-dist/legacy/build/pdf.mjs');
  let document, loadingTask;
  try {
    loadingTask = getDocument({ data: new Uint8Array(buffer), useSystemFonts: true, disableFontFace: true, isEvalSupported: false });
    document = await loadingTask.promise;
    if (!document.numPages) throw new Error('PDF has no readable pages.');
  } catch (error) {
    if (/password|encrypt/i.test(error.message || '')) throw Object.assign(new Error('This PDF is encrypted or password-protected and cannot be analyzed.'), { status: 400 });
    throw Object.assign(new Error('Could not read this PDF. It may be damaged, encrypted, or unsupported.'), { status: 400 });
  }

  let text = '';
  try {
    for (let pageNumber = 1; pageNumber <= document.numPages; pageNumber++) {
      const page = await document.getPage(pageNumber);
      const content = await page.getTextContent();
      text += `${content.items.map(entry => entry.str || '').join(' ')}\n`;
    }
  } catch (error) {
    if (loadingTask) await loadingTask.destroy().catch(() => {});
    if (/password|encrypt/i.test(error.message || '')) throw Object.assign(new Error('This PDF is encrypted or password-protected and cannot be analyzed.'), { status: 400 });
    throw Object.assign(new Error('Could not extract readable text from this PDF. The file may be damaged or unsupported.'), { status: 400 });
  }

  let metadataCheck = { status: 'unavailable', fieldsPresent: [] };
  let activeContentCheck = { status: 'unavailable', executed: false, inspection: 'PDF.js structural inspection failed; no active content was executed.' };
  try {
    const metadata = await document.getMetadata();
    const info = metadata?.info || {};
    metadataCheck = { status: 'inspected', fieldsPresent: ['Title', 'Author', 'Subject', 'Creator', 'Producer', 'CreationDate'].filter(key => Boolean(info[key])) };
    const [jsActions, attachments, openAction] = await Promise.all([
      document.getJSActions(), document.getAttachments(), document.getOpenAction(),
    ]);
    const javascriptActions = structuralCount(jsActions);
    const jsAssessment = assessJavaScriptActions(jsActions);
    const embeddedFiles = structuralCount(attachments);
    activeContentCheck = {
      status: 'inspected', executed: false, javascriptActions, embeddedFiles,
      javascriptAssessment: jsAssessment.assessment,
      javascriptEvidence: jsAssessment.scripts.map(script => script.slice(0, 240)),
      openActionPresent: Boolean(openAction) || (jsActions instanceof Map && [...jsActions.keys()].some(name => String(name).toLowerCase() === 'openaction')),
      inspection: 'PDF.js catalog APIs checked JavaScript actions, attachments, and the document open action. Known print-only actions are reported but are not scored as suspicious; selected risky APIs are flagged. This is limited structure inspection, not complete malware scanning.',
    };
  } catch {
    // Keep the document usable for text analysis, but mark the unsupported check honestly.
  }

  text = text.slice(0, 200000);
  if (text.replace(/\s/g, '').length < 10) {
    await loadingTask.destroy().catch(() => {});
    throw Object.assign(new Error('No meaningful machine-readable text was found. OCR is not configured, so scanned or image-only PDFs cannot be analyzed.'), { status: 400 });
  }

  const findings = [];
  const rawUrls = [...new Set(text.match(/https?:\/\/[^\s<>"')\]]+/gi) || [])].slice(0, 30);
  const urlHosts = new Set();
  let exampleLinksSkipped = 0;
  for (const rawLink of rawUrls.slice(0, 12)) {
    try {
      const { url } = website.validate(rawLink.replace(/[.,;:!?]+$/, ''));
      const host = url.hostname.toLowerCase();
      if (RESERVED_EXAMPLE_HOST(host)) { exampleLinksSkipped++; continue; }
      if (urlHosts.has(host)) continue;
      urlHosts.add(host);
      for (const indicator of website.analyzeStructure(url)) {
        findings.push({ ...indicator, category: 'pdf_link', name: `Embedded link ${host}: ${indicator.name}`, evidence: `Host ${host}; ${indicator.evidence}`.slice(0, 180) });
      }
    } catch {
      // Broken line wrapping or reference text is not by itself evidence of a malicious link.
    }
  }

  const requests = findDisclosureRequests(text);
  const pressuredSentences = new Set(requests.pressure);
  if (pressuredSentences.size) findings.push(item('Urgent coercive credential or payment request', 'high', 70,
    'The document combines a direct request for sensitive information or money with urgency, a deadline, or a threat.',
    [...pressuredSentences].map(sentence => sentence.slice(0, 180)).join(' | '), 'Do not follow the request. Verify it with the named organization through a trusted channel.'));
  const isolated = key => requests[key].filter(sentence => !pressuredSentences.has(sentence));
  if (isolated('credentials').length) findings.push(item('Credential or OTP disclosure request', 'high', 40,
    'The extracted text directly instructs a reader to send, enter, or disclose a password, OTP, or authentication code.', isolated('credentials').map(sentence => sentence.slice(0, 180)).join(' | '), 'Do not share passwords or one-time codes through an untrusted document link.'));
  if (isolated('banking').length) findings.push(item('Banking information request', 'high', 40,
    'The extracted text directly requests banking or payment-card details.', isolated('banking').map(sentence => sentence.slice(0, 180)).join(' | '), 'Verify payment or banking changes independently.'));
  if (isolated('payment').length) findings.push(item('Unusual payment instruction', 'high', 35,
    'The extracted text directs the reader to send money or use a wire transfer, gift card, or cryptocurrency.', isolated('payment').map(sentence => sentence.slice(0, 180)).join(' | '), 'Confirm payment instructions through a trusted channel before sending funds.'));
  if (requests.accountThreats.length) findings.push(item('Account suspension or closure threat', 'medium', 15,
    'The extracted text threatens an account consequence with a deadline or condition.', requests.accountThreats.map(sentence => sentence.slice(0, 180)).join(' | '), 'Check account notices by navigating directly to the official service.'));

  if (activeContentCheck.status === 'inspected' && activeContentCheck.javascriptAssessment === 'suspicious_api_usage') findings.push(item('PDF JavaScript uses potentially risky APIs', 'high', 40,
    'PDF.js found JavaScript actions using APIs associated with external navigation, form submission, document launching, file access, or dynamic code execution. The scripts were not executed.', activeContentCheck.javascriptEvidence.join(' | ').slice(0, 240), 'Do not open or interact with this document unless its source and behavior are verified.'));
  if (activeContentCheck.status === 'inspected' && activeContentCheck.embeddedFiles > 0) findings.push(item('PDF embedded files present', 'medium', 20,
    'PDF.js found embedded file attachments. The files were not extracted or executed.', `${activeContentCheck.embeddedFiles} embedded file(s) reported by PDF.js.`, 'Do not open embedded files unless their source and purpose are verified.'));
  if (activeContentCheck.status === 'inspected' && activeContentCheck.openActionPresent && activeContentCheck.javascriptActions === 0) findings.push(item('PDF open action present', 'low', 8,
    'The PDF has a document open action. This can be benign and does not by itself prove malicious behavior.', 'Open action detected by PDF.js; action content was not executed.', 'Review the document source before opening it.'));

  const limitations = [
    'PDF.js extracted machine-readable text. OCR is not configured; image-only text is not analyzed.',
    'Extracted links receive structural URL checks only; no link is fetched during PDF analysis.',
    activeContentCheck.inspection,
    ...(activeContentCheck.javascriptAssessment === 'unclassified_action' ? ['JavaScript is present but its behavior did not match the supported risk patterns; manual review may be needed.'] : []),
    `Up to 12 distinct non-example link hosts are checked structurally; ${exampleLinksSkipped} reserved example/test link(s) were skipped.`,
  ];
  const result = score('pdf', `PDF document (${document.numPages} page${document.numPages === 1 ? '' : 's'})`, findings,
    ['Do not open links or active content from an untrusted document. Verify the sender and expected document independently.'], limitations,
    { checks: {
      textExtraction: { status: 'complete', pages: document.numPages, charactersProcessed: text.length },
      ocr: { status: 'not_configured' }, metadata: metadataCheck, activeContent: activeContentCheck,
      links: { status: 'structural_only', extracted: rawUrls.length, distinctNonExampleHostsAnalyzed: urlHosts.size, reservedExamplesSkipped: exampleLinksSkipped },
    } });
  await loadingTask.destroy().catch(() => {});
  return result;
};

module.exports.assessJavaScriptActions = assessJavaScriptActions;
