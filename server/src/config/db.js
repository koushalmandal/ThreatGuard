const mongoose = require('mongoose');

// This is the Atlas cluster hostname supplied for this ThreatGuard project.
const EXPECTED_ATLAS_HOST = 'cluster0.wmlp8on.mongodb.net';

function getMongoConfigSummary(uri = process.env.MONGODB_URI || '') {
  if (!uri) return { configured: false };
  try {
    const parsed = new URL(uri);
    const database = parsed.pathname.replace(/^\//, '').split('/')[0] || '';
    return {
      configured: true,
      parseable: true,
      scheme: parsed.protocol,
      host: parsed.hostname,
      database,
      hasUsername: Boolean(parsed.username),
      hasPassword: Boolean(parsed.password),
      matchesExpectedAtlasHost: parsed.hostname.toLowerCase() === EXPECTED_ATLAS_HOST,
      isSrv: parsed.protocol === 'mongodb+srv:',
    };
  } catch {
    return { configured: true, parseable: false };
  }
}

function safeErrorSummary(error) {
  const summarize = value => value ? {
    name: typeof value.name === 'string' ? value.name : undefined,
    code: typeof value.code === 'string' || typeof value.code === 'number' ? value.code : undefined,
    syscall: typeof value.syscall === 'string' ? value.syscall : undefined,
    hostname: typeof value.hostname === 'string' ? value.hostname : undefined,
    address: typeof value.address === 'string' ? value.address : undefined,
    port: typeof value.port === 'number' ? value.port : undefined,
  } : undefined;

  const summary = summarize(error) || { name: 'UnknownError' };
  const cause = summarize(error?.cause);
  if (cause && Object.values(cause).some(value => value !== undefined)) summary.cause = cause;

  const servers = error?.reason?.servers;
  if (servers && typeof servers[Symbol.iterator] === 'function') {
    summary.servers = Array.from(servers.entries()).map(([target, server]) => {
      const serverError = server?.error || server?.description?.error;
      return {
        target: String(target),
        state: typeof server?.type === 'string' ? server.type : undefined,
        error: summarize(serverError),
        cause: summarize(serverError?.cause),
      };
    });
  }
  return summary;
}

async function connectDB() {
  const uri = process.env.MONGODB_URI || '';
  if (!uri) throw Object.assign(new Error('MONGODB_URI is missing. Set it in threatguard/server/.env.'), { code: 'MONGO_URI_MISSING' });
  if (/<[^>]+>/.test(uri) || /REPLACE_WITH|YOUR_PASSWORD/i.test(uri)) {
    throw Object.assign(new Error('MONGODB_URI still contains an example placeholder. Enter your URL-encoded Atlas password in threatguard/server/.env.'), { code: 'MONGO_URI_PLACEHOLDER' });
  }

  const config = getMongoConfigSummary(uri);
  if (!config.parseable || !['mongodb:', 'mongodb+srv:'].includes(config.scheme)) {
    throw Object.assign(new Error('MONGODB_URI is malformed. Copy the URI from Atlas Connect → Drivers.'), { code: 'MONGO_URI_INVALID' });
  }
  if (!config.matchesExpectedAtlasHost || !config.isSrv) {
    throw Object.assign(new Error(`MONGODB_URI should use the current Atlas SRV hostname ${EXPECTED_ATLAS_HOST}. Copy the current URI from Atlas Connect → Drivers.`), { code: 'MONGO_URI_HOST_MISMATCH' });
  }
  if (config.database !== 'threatguard') {
    throw Object.assign(new Error('MONGODB_URI must select the threatguard database.'), { code: 'MONGO_DATABASE_MISMATCH' });
  }
  if (!config.hasUsername || !config.hasPassword) {
    throw Object.assign(new Error('MONGODB_URI must include the Atlas database username and URL-encoded password.'), { code: 'MONGO_CREDENTIALS_MISSING' });
  }

  await mongoose.connect(uri);
  console.log(`MongoDB connected: ${mongoose.connection.name}`);
}

connectDB.getMongoConfigSummary = getMongoConfigSummary;
connectDB.safeErrorSummary = safeErrorSummary;
module.exports = connectDB;
