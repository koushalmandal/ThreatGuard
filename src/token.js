const STORAGE_KEY = 'tg_anonymous_token';
const TOKEN_FORMAT = /^[A-Za-z0-9_-]{43}$/;
const accessError = message => Object.assign(new Error(message), { code: 'TG_BROWSER_ACCESS' });

export function getAnonymousToken(storage = globalThis.localStorage, cryptoApi = globalThis.crypto) {
  if (!storage) throw accessError('ThreatGuard needs browser storage enabled to keep anonymous scan access.');
  let token;
  try { token = storage.getItem(STORAGE_KEY); }
  catch { throw accessError('ThreatGuard could not read browser storage. Enable local storage and retry.'); }
  if (TOKEN_FORMAT.test(token || '')) return token;
  if (!cryptoApi?.getRandomValues || typeof globalThis.btoa !== 'function') {
    throw accessError('This browser does not support secure anonymous scan access. Use an up-to-date browser over localhost.');
  }
  const bytes = cryptoApi.getRandomValues(new Uint8Array(32));
  const nextToken = globalThis.btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  if (!TOKEN_FORMAT.test(nextToken)) throw accessError('Could not create a valid anonymous scan capability.');
  try { storage.setItem(STORAGE_KEY, nextToken); }
  catch { throw accessError('ThreatGuard could not save browser scan access. Enable local storage and retry.'); }
  return nextToken;
}

export { STORAGE_KEY, TOKEN_FORMAT };
