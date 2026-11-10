import axios from 'axios';
import { getAnonymousToken } from './token.js';
import { getApiBaseUrl } from './apiBase.js';
const pageHostname = typeof window === 'undefined' ? 'localhost' : window.location.hostname;
const api = axios.create({ baseURL: getApiBaseUrl(pageHostname, import.meta.env.VITE_API_BASE_URL), timeout: 30000 });
api.interceptors.request.use(config => {
  if (typeof config.headers.set === 'function') config.headers.set('X-Anonymous-Token', getAnonymousToken());
  else config.headers['X-Anonymous-Token'] = getAnonymousToken();
  return config;
});
export default api;
