const dns = require('node:dns').promises;
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');

const DNS_TIMEOUT_MS = 3000;
const REQUEST_TIMEOUT_MS = 4500;
const MAX_REDIRECTS = 4;
const MAX_RESPONSE_BYTES = 64 * 1024;
const METADATA_HOSTS = new Set(['metadata.google.internal', 'metadata.google', 'instance-data.ec2.internal']);

function ipv4Number(address) {
  if (net.isIP(address) !== 4) return null;
  return address.split('.').reduce((n, part) => (n * 256) + Number(part), 0) >>> 0;
}

function ipv6Number(address) {
  if (net.isIP(address) !== 6) return null;
  let value = address.toLowerCase().split('%')[0];
  const ipv4Tail = value.match(/(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (ipv4Tail) {
    const n = ipv4Number(ipv4Tail[1]);
    if (n === null) return null;
    value = value.slice(0, -ipv4Tail[1].length) + `${((n >>> 16) & 0xffff).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right];
  if (groups.length !== 8 || groups.some(x => !/^[\da-f]{1,4}$/.test(x))) return null;
  return groups.reduce((n, group) => (n << 16n) | BigInt(`0x${group}`), 0n);
}

function isPublicAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const n = ipv4Number(address);
    const blocked = [
      [0x00000000, 8], [0x0a000000, 8], [0x64400000, 10], [0x7f000000, 8],
      [0xa9fe0000, 16], [0xac100000, 12], [0xc0000000, 24], [0xc0000200, 24],
      [0xc0586300, 24], [0xc0a80000, 16], [0xc6120000, 15], [0xc6336400, 24],
      [0xcb007100, 24], [0xe0000000, 4], [0xf0000000, 4],
    ];
    return !blocked.some(([base, bits]) => Math.floor(n / (2 ** (32 - bits))) === Math.floor(base / (2 ** (32 - bits))));
  }
  if (family === 6) {
    const n = ipv6Number(address);
    if (n === null) return false;
    const mappedPrefix = BigInt('0xffff');
    if ((n >> 32n) === mappedPrefix) return isPublicAddress(`${Number((n >> 24n) & 255n)}.${Number((n >> 16n) & 255n)}.${Number((n >> 8n) & 255n)}.${Number(n & 255n)}`);
    // Permit global unicast only, excluding documentation and other special ranges.
    return (n >> 125n) === 1n && (n >> 96n) !== BigInt('0x20010db8');
  }
  return false;
}

function timeout(promise, ms, message) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), ms); }),
  ]).finally(() => clearTimeout(timer));
}

async function resolvePublic(host) {
  if (METADATA_HOSTS.has(host.toLowerCase())) throw new Error('Metadata destination blocked.');
  if (net.isIP(host)) {
    if (!isPublicAddress(host)) throw new Error('Private or reserved destination blocked.');
    return [{ address: host, family: net.isIP(host) }];
  }
  const records = await timeout(dns.lookup(host, { all: true, verbatim: true }), DNS_TIMEOUT_MS, 'DNS lookup timed out.');
  if (!records.length) throw new Error('No address records found.');
  // Reject mixed public/private answers; use only an address pinned from this lookup.
  if (records.some(record => !isPublicAddress(record.address))) throw new Error('Private or reserved DNS destination blocked.');
  return records;
}

function pinnedLookup(expectedHost, records) {
  return (hostname, options, callback) => {
    if (hostname.toLowerCase() !== expectedHost.toLowerCase()) return callback(Object.assign(new Error('Unexpected DNS lookup.'), { code: 'ENOTFOUND' }));
    const all = typeof options === 'object' && options?.all;
    if (all) callback(null, records);
    else callback(null, records[0].address, records[0].family);
  };
}

function requestOnce(url, records) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
    if ((url.protocol === 'https:' && port !== 443) || (url.protocol === 'http:' && port !== 80)) return reject(new Error('Outbound port blocked.'));
    const request = transport.request(url, {
      method: 'GET',
      headers: { Range: 'bytes=0-8191', 'User-Agent': 'ThreatGuard-URL-Inspector/1.0', Accept: 'text/html,text/plain;q=0.9,*/*;q=0.1' },
      lookup: pinnedLookup(url.hostname, records),
      timeout: REQUEST_TIMEOUT_MS,
      maxHeaderSize: 16 * 1024,
      // Node's normal HTTPS certificate and hostname verification remain enabled.
    }, response => {
      const cert = url.protocol === 'https:' ? response.socket.getPeerCertificate() : null;
      const certificate = cert && Object.keys(cert).length ? {
        authorized: response.socket.authorized === true,
        issuer: cert.issuer?.O || cert.issuer?.CN || null,
        validFrom: cert.valid_from || null,
        validTo: cert.valid_to || null,
        subjectAltNamePresent: Boolean(cert.subjectaltname),
      } : null;
      const statusCode = response.statusCode || 0;
      const location = response.headers.location || '';
      let received = 0;
      response.on('data', chunk => {
        received += chunk.length;
        if (received >= MAX_RESPONSE_BYTES) response.destroy();
      });
      response.on('end', () => resolve({ statusCode, location, certificate, responseBytesObserved: Math.min(received, MAX_RESPONSE_BYTES) }));
      response.on('close', () => resolve({ statusCode, location, certificate, responseBytesObserved: Math.min(received, MAX_RESPONSE_BYTES) }));
      response.on('error', error => reject(error));
    });
    request.on('timeout', () => request.destroy(Object.assign(new Error('Remote request timed out.'), { code: 'ETIMEDOUT' })));
    request.on('error', reject);
    request.end();
  });
}

async function resolveDns(host) {
  const methods = [['A', () => dns.resolve4(host)], ['AAAA', () => dns.resolve6(host)], ['MX', () => dns.resolveMx(host)], ['NS', () => dns.resolveNs(host)]];
  const results = await Promise.all(methods.map(async ([type, run]) => {
    try { return [type, await timeout(run(), DNS_TIMEOUT_MS, 'DNS lookup timed out.')]; }
    catch (error) { return [type, { error: error.code || 'DNS_LOOKUP_FAILED' }]; }
  }));
  const entries = Object.fromEntries(results);
  const addresses = [...(Array.isArray(entries.A) ? entries.A.map(address => ({ address, family: 4 })) : []), ...(Array.isArray(entries.AAAA) ? entries.AAAA.map(address => ({ address, family: 6 })) : [])];
  const publicAddresses = addresses.filter(record => isPublicAddress(record.address));
  const blockedAddressCount = addresses.length - publicAddresses.length;
  return {
    status: blockedAddressCount ? 'blocked_private' : addresses.length ? 'resolved' : 'unavailable',
    A: Array.isArray(entries.A) ? entries.A.filter(isPublicAddress).slice(0, 20) : entries.A,
    AAAA: Array.isArray(entries.AAAA) ? entries.AAAA.filter(isPublicAddress).slice(0, 20) : entries.AAAA,
    MX: entries.MX, NS: entries.NS,
    addresses: publicAddresses.slice(0, 20),
    ...(blockedAddressCount ? { blockedAddressCount } : {}),
  };
}

async function inspectWebsite(initialUrl) {
  const checks = { dns: { status: 'unavailable' }, tls: { status: 'not_applicable' }, redirects: { status: 'unavailable', chain: [] } };
  const dnsResult = net.isIP(initialUrl.hostname)
    ? { status: 'not_applicable', A: [], AAAA: [], MX: [], NS: [], addresses: [{ address: initialUrl.hostname, family: net.isIP(initialUrl.hostname) }] }
    : await resolveDns(initialUrl.hostname);
  checks.dns = dnsResult;
  const addresses = dnsResult.addresses;
  if (dnsResult.status === 'blocked_private') {
    checks.redirects.status = 'blocked';
    checks.redirects.error = 'Private or reserved DNS destination blocked.';
    return { checks };
  }
  if (!addresses.length && !net.isIP(initialUrl.hostname)) return { checks, error: 'DNS resolution did not return an address.' };

  let current = initialUrl;
  const originalHost = current.hostname.toLowerCase();
  for (let index = 0; index <= MAX_REDIRECTS; index++) {
    let records;
    try { records = await resolvePublic(current.hostname); }
    catch (error) {
      checks.redirects.status = 'blocked';
      checks.redirects.error = error.message;
      return { checks };
    }
    try {
      const response = await requestOnce(current, records);
      if (current.protocol === 'https:') checks.tls = { status: response.certificate?.authorized ? 'valid' : 'failed', ...response.certificate };
      const isRedirect = [301, 302, 303, 307, 308].includes(response.statusCode);
      checks.redirects.chain.push({ host: current.hostname, statusCode: response.statusCode });
      if (!isRedirect || !response.location) {
        checks.redirects.status = 'complete';
        checks.redirects.finalHost = current.hostname;
        checks.redirects.crossDomain = current.hostname.toLowerCase() !== originalHost;
        return { checks };
      }
      if (index === MAX_REDIRECTS) {
        checks.redirects.status = 'limit_reached';
        return { checks };
      }
      const next = new URL(response.location, current);
      if (!['http:', 'https:'].includes(next.protocol) || next.username || next.password) throw new Error('Unsafe redirect protocol or embedded credentials.');
      const nextPort = Number(next.port || (next.protocol === 'https:' ? 443 : 80));
      if (!((next.protocol === 'https:' && nextPort === 443) || (next.protocol === 'http:' && nextPort === 80))) throw new Error('Redirect to a nonstandard port blocked.');
      // DNS is re-resolved and pinned on the next iteration; no credentials are forwarded.
      current = next;
    } catch (error) {
      checks.redirects.status = 'unavailable';
      checks.redirects.error = error.code || 'REMOTE_CHECK_FAILED';
      if (current.protocol === 'https:') {
        const tlsFailure = /^(CERT_|ERR_TLS_|ERR_SSL_)/.test(error.code || '');
        checks.tls = { status: tlsFailure ? 'failed' : 'unavailable', error: error.code || 'TLS_OR_REQUEST_FAILED' };
      }
      return { checks };
    }
  }
  return { checks };
}

module.exports = { inspectWebsite, resolveDns, resolvePublic, isPublicAddress, ipv6Number };
