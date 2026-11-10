export function validateWebsiteInput(value) {
  const input = String(value || '').trim();
  if (!input || input.length > 2048 || /\s/.test(input)) return 'Enter a valid HTTP or HTTPS website URL.';
  let parsed;
  try {
    if (/^[a-z][a-z\d+.-]*:\/\//i.test(input) && !/^https?:\/\//i.test(input)) return 'Only HTTP and HTTPS website URLs are supported.';
    parsed = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`);
  } catch { return 'Enter a valid HTTP or HTTPS website URL.'; }
  const host = parsed.hostname.toLowerCase();
  // Credentials are inspected as a risk indicator by the backend. They are
  // never used for outbound requests and are removed from saved summaries.
  if (!['http:', 'https:'].includes(parsed.protocol) || !host) return 'Enter a valid HTTP or HTTPS website URL.';
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host === 'metadata.google.internal') return 'Local and metadata destinations cannot be analyzed.';
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
    const labels = host.replace(/\.$/, '').split('.');
    if (labels.length < 2 || labels.some(label => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)) || labels.at(-1).length < 2 || /^\d+$/.test(labels.at(-1))) return 'Enter a valid HTTP or HTTPS website URL with a domain name.';
  }
  return '';
}

export function validateEmailInput({ sender = '', subject = '', body = '' } = {}) {
  const address = sender.trim();
  if (!address) return 'Enter the sender email address.';
  if (!/^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$/i.test(address)) return 'Enter a valid sender email address.';
  if (!subject.trim()) return 'Enter an email subject.';
  if (body.trim().length < 10) return 'Enter an email body with at least 10 non-whitespace characters.';
  return '';
}
