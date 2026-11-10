const DEFAULT_ORIGINS = [
  'http://localhost:5173',
  'http://192.168.1.104:5173',
];

function getAllowedOrigins(configured = process.env.CLIENT_ORIGIN) {
  const value = typeof configured === 'string' && configured.trim()
    ? configured
    : DEFAULT_ORIGINS.join(',');
  return [...new Set(value.split(',').map(origin => origin.trim()).filter(Boolean))];
}

function isAllowedOrigin(origin, allowedOrigins = getAllowedOrigins()) {
  return !origin || allowedOrigins.includes(origin);
}

module.exports = { DEFAULT_ORIGINS, getAllowedOrigins, isAllowedOrigin };
