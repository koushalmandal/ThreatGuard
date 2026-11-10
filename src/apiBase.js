export function getApiBaseUrl(pageHostname = 'localhost', override = '') {
  return override || `http://${pageHostname}:5000/api`;
}
