const net = require('node:net');
const score = require('./scoring');
const { inspectWebsite } = require('./websiteNetwork');

function invalid(message = 'Enter a valid HTTP or HTTPS website URL with a fully qualified domain name.') {
  throw Object.assign(new Error(message), { status: 400 });
}

function validateWebsiteUrl(value) {
  if (typeof value !== 'string' || !value.trim() || value.length > 2048) invalid('Enter a URL under 2,048 characters.');
  const input = value.trim();
  if (/\s/.test(input)) invalid();
  if (/^[a-z][a-z\d+.-]*:\/\//i.test(input) && !/^https?:\/\//i.test(input)) invalid('Only HTTP or HTTPS URLs are supported.');
  let url;
  try { url = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`); } catch { invalid(); }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) invalid('Only HTTP or HTTPS URLs are supported.');
  const host = url.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || ['metadata.google.internal', 'metadata.google'].includes(host)) invalid('Local and metadata destinations cannot be analyzed.');
  if (!net.isIP(host)) {
    const labels = host.replace(/\.$/, '').split('.');
    if (labels.length < 2 || labels.some(label => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label))) invalid();
    if (labels.at(-1).length < 2 || /^\d+$/.test(labels.at(-1))) invalid();
  }
  return { url, host };
}

function finding(name, severity, weight, explanation, evidence, recommendation) {
  return { name, severity, weight, explanation, evidence, recommendation };
}

function extractFeatures(inputUrl) {
  const url = inputUrl instanceof URL ? inputUrl : validateWebsiteUrl(inputUrl).url;
  const host = url.hostname.toLowerCase();
  const labels = host.replace(/\.$/, '').split('.');
  const suffixes = ['co.uk', 'org.uk', 'com.au', 'net.au', 'co.in', 'com.br', 'co.jp'];
  const multipartSuffix = suffixes.find(suffix => host.endsWith(`.${suffix}`));
  const domainLabelCount = net.isIP(host) ? labels.length : multipartSuffix ? 3 : 2;
  const domain = labels.slice(-domainLabelCount).join('.');
  const queryParameters = [...url.searchParams.entries()];
  const encodedRedirectDestinations = queryParameters.flatMap(([key, value]) => {
    if (!/^(?:redirect|return|continue|next|target|url|destination)$/i.test(key)) return [];
    try {
      const destination = new URL(value);
      if (!['http:', 'https:'].includes(destination.protocol)) return [];
      return [{ key, hostname: destination.hostname.toLowerCase(), encoded: /%[0-9a-f]{2}/i.test(url.search) }];
    } catch { return []; }
  });
  return {
    protocol: url.protocol, hostname: host, domain,
    subdomains: net.isIP(host) ? [] : labels.slice(0, -domainLabelCount),
    usernamePresent: Boolean(url.username), passwordPresent: Boolean(url.password),
    port: url.port || null, path: url.pathname, queryParameters,
    encodedRedirectDestinations, ipAddress: net.isIP(host) ? host : null,
    internationalizedDomain: host.includes('xn--'), urlLength: url.href.length,
  };
}

function analyzeStructure(url) {
  const features = extractFeatures(url);
  const host = features.hostname;
  const findings = [];
  if (url.protocol === 'http:') findings.push(finding('Unencrypted HTTP', 'low', 5, 'HTTP does not encrypt traffic. HTTP alone is not evidence that a site is malicious.', 'Scheme is http.', 'Prefer HTTPS and avoid entering sensitive information over an unencrypted connection.'));
  if (net.isIP(host)) findings.push(finding('IP address host', 'medium', 35, 'The destination uses a raw IP address rather than a conventional domain; this is less common for public services and can obscure ownership.', host, 'Verify the destination owner before opening it; ThreatGuard blocks remote inspection of private or reserved IPs.'));
  if (features.usernamePresent || features.passwordPresent) findings.push(finding('Embedded URL credentials', 'high', 40, 'The URL includes user information before the hostname, a pattern that can disguise the actual destination.', 'User information is present; values omitted.', 'Do not open this link. Remove the embedded credentials and verify the real hostname.'));
  if (features.urlLength > 200) findings.push(finding('Unusually long URL', 'low', 8, 'A long URL can make the actual destination and parameters harder to review.', `${features.urlLength} characters.`, 'Inspect the hostname and query parameters before opening the link.'));
  if (features.subdomains.length > 2) findings.push(finding('Excessive subdomains', 'medium', 20, 'Several subdomain labels can make the registered domain harder to notice.', `${features.subdomains.length} subdomain labels before ${features.domain}.`, 'Read the hostname from right to left and verify the registered domain.'));
  if (features.internationalizedDomain) findings.push(finding('Internationalized domain encoding', 'medium', 20, 'The hostname uses punycode, which can represent characters that resemble other scripts or brands.', host, 'Confirm the exact domain spelling through a trusted source.'));
  if (features.port && !['80', '443'].includes(features.port)) findings.push(finding('Nonstandard web port', 'medium', 15, 'The URL uses a port outside standard HTTP and HTTPS ports.', `Port ${features.port}.`, 'Do not continue unless the destination and port are expected.'));
  if (['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rb.gy'].includes(host)) findings.push(finding('URL shortener', 'low', 8, 'A shortened link hides its final destination from a quick review.', host, 'Expand and verify the destination before opening it.'));
  const sensitiveKeys = features.queryParameters.map(([key]) => key).filter(key => /^(?:redirect|return|continue|next|target|url|destination)$/i.test(key));
  const externalEncodedRedirects = features.encodedRedirectDestinations.filter(item => item.encoded && item.hostname !== host);
  if (externalEncodedRedirects.length) findings.push(finding('Encoded external redirect destination', 'medium', 20, 'An encoded redirect parameter points to a different hostname, obscuring where the link may send a user.', externalEncodedRedirects.map(item => `${item.key} -> ${item.hostname}`).slice(0, 3).join(', '), 'Do not follow the redirect; open the intended service from its known official address.'));
  else {
    const dangerousEncoding = /%(?:2f|5c|40|2e|25)/i.test(`${url.pathname}${url.search}`) || /%[0-9a-f]{2}.*%[0-9a-f]{2}/i.test(`${url.pathname}${url.search}`);
    if (dangerousEncoding) findings.push(finding('Obfuscated URL encoding', 'medium', 20, 'Repeated or separator-like percent encoding can obscure the path or destination parameters.', 'Encoded separators or repeated encoded characters detected.', 'Decode and inspect the destination before opening the link.'));
    if (sensitiveKeys.length) findings.push(finding('Redirect-style query parameter', 'low', 8, 'A query parameter appears to carry a destination or redirect target; this is not malicious by itself.', sensitiveKeys.slice(0, 4).join(', '), 'Check any destination parameter before following the link.'));
  }
  const pathTerms = ['login', 'verify', 'account', 'password', 'signin', 'update'];
  const path = `${url.pathname} ${url.search}`.toLowerCase();
  const pathHits = pathTerms.filter(term => new RegExp(`(?:^|[^a-z])${term}(?:[^a-z]|$)`).test(path));
  if (pathHits.length >= 2) findings.push(finding('Credential-lure URL structure', 'medium', 20, 'Multiple credential or account-related terms appear together in the URL path or query. A word alone is not treated as proof of a threat.', pathHits.join(', '), 'Navigate to the service directly instead of using this link.'));
  const brandDomains = { paypal: ['paypal.com'], microsoft: ['microsoft.com', 'microsoftonline.com'], google: ['google.com', 'googlemail.com'], apple: ['apple.com'], amazon: ['amazon.com', 'amazon.co.uk'], netflix: ['netflix.com'], facebook: ['facebook.com'], dropbox: ['dropbox.com'] };
  const brandLike = Object.entries(brandDomains).find(([brand, domains]) => host.split('.').some(label => label.includes(brand)) && !domains.some(domain => host === domain || host.endsWith(`.${domain}`)))?.[0];
  if (brandLike) findings.push(finding('Brand-like hostname on another domain', 'high', 35, 'A hostname includes a recognizable brand name but does not end in that brand’s known domain. This is a structural warning, not proof of impersonation.', `Brand-like term: ${brandLike}; hostname: ${host}`, 'Use the organization’s known official address rather than this link.'));
  return findings;
}

async function analyzeWebsite(value, integrations = {}) {
  const { url } = validateWebsiteUrl(value);
  const findings = analyzeStructure(url);
  // Never send embedded credentials to the remote inspector or retain them in reports.
  const safeUrl = new URL(url.href);
  safeUrl.username = '';
  safeUrl.password = '';
  const network = await (integrations.inspect || inspectWebsite)(safeUrl);
  if (network.checks?.tls?.status === 'failed') findings.push(finding('TLS certificate or handshake check failed', 'medium', 20, 'The HTTPS certificate validation or TLS connection failed. This can have benign network causes and is not by itself proof of maliciousness.', network.checks.tls.error || 'TLS validation failed.', 'Check the site from a trusted network and do not enter sensitive information until its connection is understood.'));
  if (network.checks?.redirects?.crossDomain) findings.push(finding('Cross-domain redirect', 'low', 8, 'The site redirected to a different hostname. Such redirects can be legitimate but warrant review.', `Final host: ${network.checks.redirects.finalHost}`, 'Verify that the final hostname is expected.'));
  const limitations = [];
  if (network.checks?.redirects?.status === 'blocked') limitations.push('Remote inspection was blocked because the target resolved to a private, reserved, or otherwise prohibited address. No request was sent to that destination.');
  if (!network.checks?.dns || !['resolved', 'not_applicable'].includes(network.checks.dns.status)) limitations.push('DNS checks did not complete; no DNS-based conclusion was made.');
  if (network.checks?.redirects?.status !== 'complete') limitations.push('Redirect inspection did not complete; the final destination was not verified.');
  if (network.checks?.tls?.status === 'not_applicable') limitations.push('TLS checks apply only to HTTPS URLs.');
  limitations.push('ThreatGuard uses deterministic URL heuristics and limited network checks. It does not use threat intelligence, antivirus, or malware scanning; no detected indicators do not guarantee safety.');
  const summaryUrl = new URL(url.href); summaryUrl.username = ''; summaryUrl.password = '';
  const checksComplete = Boolean(network.checks?.dns && ['resolved', 'not_applicable'].includes(network.checks.dns.status)
    && network.checks?.redirects?.status === 'complete'
    && (url.protocol !== 'https:' || network.checks?.tls?.status === 'valid'));
  return score('website', summaryUrl.origin + (summaryUrl.pathname === '/' ? '' : summaryUrl.pathname), findings,
    ['Confirm the domain through a trusted channel before sharing sensitive information.', 'Do not rely on HTTPS alone as evidence that a site is trustworthy.'], limitations,
    { checks: { ...network.checks, analysis: { status: checksComplete ? 'complete' : 'unverified', mode: 'rule_based' } } });
}

analyzeWebsite.validate = validateWebsiteUrl;
analyzeWebsite.analyzeStructure = analyzeStructure;
analyzeWebsite.extractFeatures = extractFeatures;
module.exports = analyzeWebsite;
