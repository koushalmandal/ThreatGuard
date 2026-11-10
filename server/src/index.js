const path = require('node:path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
const dns = require('node:dns');
// On some Windows networks Node's local DNS stub refuses Atlas SRV queries;
// use the configurable resolver before Mongoose/its MongoDB driver starts DNS lookups.
const servers = (process.env.MONGODB_DNS_SERVERS || '').split(',').map(x => x.trim()).filter(Boolean);
if (servers.length) dns.setServers(servers);
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const connectDB = require('./config/db');
const corsPolicy = require('./config/cors');
const api = require('./routes/api');
const app = express();
app.disable('x-powered-by');
app.use(helmet());
const allowedOrigins = corsPolicy.getAllowedOrigins(process.env.CLIENT_ORIGIN);
app.use(cors({
  origin(origin, callback) { callback(null, corsPolicy.isAllowedOrigin(origin, allowedOrigins)); },
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Anonymous-Token'],
  optionsSuccessStatus: 204,
}));
app.use(express.json({ limit: '200kb' }));
app.get('/api/health', (_req, res) => res.json({ status: 'ok', database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' }));
app.use('/api', rateLimit({ windowMs: 60_000, limit: 90, standardHeaders: true, legacyHeaders: false }), api);
app.use((err, _req, res, _next) => {
  if (err instanceof require('multer').MulterError) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? `PDF exceeds ${process.env.UPLOAD_MAX_MB || 10} MB.` : 'Invalid upload.' });
  if (/^Multipart:|Unexpected end of form/i.test(err.message || '')) return res.status(400).json({ error: 'The PDF upload was incomplete. Please select the file and retry.' });
  const status = err.status || 500;
  if (status >= 500) console.error(`Request failed (${err.name || 'Error'}).`);
  return res.status(status).json({ error: status >= 500 ? 'Request could not be completed.' : err.message });
});
const port = Number(process.env.PORT) || 5000;
const host = process.env.API_HOST || '0.0.0.0';
async function findSrvCnameAliases(error) {
  const targets = error?.reason?.servers;
  if (!targets || typeof targets.keys !== 'function') return [];
  const checks = await Promise.all([...targets.keys()].map(async target => {
    const hostname = String(target).slice(0, String(target).lastIndexOf(':'));
    try {
      const aliases = await dns.promises.resolveCname(hostname);
      return aliases.length ? { hostname, aliases } : null;
    } catch {
      return null;
    }
  }));
  return checks.filter(Boolean);
}
connectDB().then(() => {
  const server = app.listen(port, host, () => console.log(`ThreatGuard API listening on ${host}:${port}`));
  server.on('error', err => {
    if (err.code === 'EADDRINUSE') console.error(`Port ${port} is already in use. Stop the other ThreatGuard API process before restarting.`);
    else console.error(`ThreatGuard API could not listen (${err.code || err.name || 'Error'}).`);
    mongoose.disconnect().finally(() => process.exit(1));
  });
}).catch(async err => {
  console.error('MongoDB connection failed. Safe diagnostics (credentials and URI omitted):');
  console.error(JSON.stringify({
    config: connectDB.getMongoConfigSummary(),
    dnsResolvers: dns.getServers(),
    error: connectDB.safeErrorSummary(err),
  }, null, 2));
  const safeDiagnostics = JSON.stringify(connectDB.safeErrorSummary(err));
  if (typeof err.code === 'string' && err.code.startsWith('MONGO_')) console.error(err.message);
  else if (err.code === 8000 || err.cause?.code === 8000) console.error('Atlas rejected database authentication or authorization. Verify the Atlas database user and role.');
  else if (err.name === 'MongoParseError') console.error('MongoDB rejected the URI format. Copy a fresh URI from Atlas Connect → Drivers and URL-encode special characters in the password.');
  else if (['querySrv', 'queryA', 'queryAAAA'].includes(err.syscall)) console.error(`DNS resolution failed during ${err.syscall} for ${err.hostname || connectDB.getMongoConfigSummary().host}. Check the active DNS resolver and verify it can resolve Atlas shard hostnames.`);
  else if (/ERR_SSL_TLSV1_ALERT_INTERNAL_ERROR|ERR_SSL_.*ALERT|ERR_TLS_/.test(safeDiagnostics)) {
    const aliases = await findSrvCnameAliases(err);
    if (aliases.length) {
      console.error('TLS failed for Atlas SRV target hostnames that DNS aliases through CNAME records:');
      console.error(JSON.stringify(aliases));
      console.error('MongoDB SRV discovery does not support CNAME targets. Copy a fresh driver connection string from Atlas; if its SRV targets still alias through CNAME, ask Atlas support to correct the cluster DNS/TLS endpoint mapping. Keep TLS verification enabled.');
    } else {
      console.error('Atlas DNS resolved, but TLS negotiation failed. Keep TLS verification enabled. Check the Atlas cluster endpoint mapping, system clock, Node.js support, VPN/antivirus/proxy TLS inspection, and outbound TCP 27017 rules. Do not set tlsInsecure or disable certificate validation.');
    }
  }
  else if (err.code === 'ECONNREFUSED' || safeDiagnostics.includes('ECONNREFUSED')) console.error('One or more Atlas TCP endpoints refused the connection. Check that the cluster is active, the hostname is current, and outbound TCP port 27017 is allowed.');
  else if (err.name === 'MongooseServerSelectionError') console.error('Atlas server selection failed. Use the nested host/error codes above to distinguish DNS failure, refused connections, timeouts, or authentication errors.');
  else console.error('Check the Atlas database user, Network Access allowlist, DNS resolution, and outbound TCP access to port 27017.');
  process.exit(1);
});
