import axios from 'axios';
const baseURL = import.meta.env.VITE_API_BASE_URL || '';
export const configurationError = import.meta.env.PROD && !/^https:\/\/[^/]+\/?$/.test(baseURL)
  ? 'Set VITE_API_BASE_URL to the HTTPS Render backend origin and redeploy the frontend.' : '';
export const api = axios.create({ baseURL });
api.interceptors.request.use(config => {
  const token = sessionStorage.getItem('token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});
