// server.js
// Express-based analytics backend with PostgreSQL, Redis caching, Redis token-bucket rate limiting,
// and Google OAuth onboarding (Passport).
//
// Exports: app, createServer, pgClient, initDbPromise, redisClient, initRedisPromise

require('dotenv').config();
const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { Client } = require('pg');
const Redis = require('ioredis');
const fs = require('fs');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const connectRedis = require('connect-redis');

// -------------------------
// Postgres setup
// -------------------------
const pgClient = new Client({
  host: process.env.PG_HOST || 'localhost',
  user: process.env.PG_USER || 'postgres',
  port: process.env.PG_PORT ? parseInt(process.env.PG_PORT, 10) : 5432,
  password: process.env.PG_PASSWORD || '',
  database: process.env.PG_DATABASE || 'dbanalytics',
});

let initDbPromise = (async () => {
  try {
    await pgClient.connect();
    console.log('db successfully connected');

    // Ensure tables exist
    await pgClient.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        google_id TEXT UNIQUE,
        email TEXT,
        display_name TEXT,
        avatar_url TEXT,
        created_at TIMESTAMPTZ DEFAULT now()
      );
    `);

    await pgClient.query(`
      CREATE TABLE IF NOT EXISTS apps (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        user_email TEXT NOT NULL,
        api_key TEXT UNIQUE NOT NULL,
        revoked BOOLEAN DEFAULT FALSE,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ DEFAULT now()
      );
    `);

    await pgClient.query(`
      CREATE TABLE IF NOT EXISTS events (
        id SERIAL PRIMARY KEY,
        app_id INTEGER REFERENCES apps(id) ON DELETE SET NULL,
        event_type TEXT NOT NULL,
        url TEXT,
        referrer TEXT,
        device TEXT,
        ip_address TEXT,
        timestamp TIMESTAMPTZ NOT NULL,
        metadata JSONB,
        user_id TEXT,
        created_at TIMESTAMPTZ DEFAULT now()
      );
    `);
  } catch (err) {
    console.error('Failed to connect or initialize DB:', err);
    process.exit(1);
  }
})();

// -------------------------
// Redis setup
// -------------------------
const redisHost = process.env.REDIS_HOST || '127.0.0.1';
const redisPort = process.env.REDIS_PORT ? parseInt(process.env.REDIS_PORT, 10) : 6379;
const redisUrl = process.env.REDIS_URL || null;
const redisOpts = redisUrl ? { url: redisUrl } : { host: redisHost, port: redisPort };

const redisClient = new Redis(redisOpts);
const RedisStore = connectRedis(session);

// Token-bucket Lua script (atomic)
const tokenBucketLua = `
-- KEYS[1] = bucket key
-- ARGV[1] = capacity
-- ARGV[2] = window_ms
-- ARGV[3] = tokens_to_consume
local capacity = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local consume = tonumber(ARGV[3])
local t = redis.call('TIME')
local now_ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local data = redis.call('HMGET', KEYS[1], 'tokens', 'last_refill')
local tokens = tonumber(data[1]) or capacity
local last_refill = tonumber(data[2]) or now_ms
local elapsed = now_ms - last_refill
if elapsed < 0 then elapsed = 0 end
local refill_rate = capacity / window_ms
local refill = elapsed * refill_rate
tokens = math.min(capacity, tokens + refill)
if tokens >= consume then
  tokens = tokens - consume
  redis.call('HMSET', KEYS[1], 'tokens', tostring(tokens), 'last_refill', tostring(now_ms))
  redis.call('PEXPIRE', KEYS[1], math.max(60000, window_ms * 5))
  return {1, math.floor(tokens)}
else
  local needed = consume - tokens
  local ms_until = math.ceil(needed / refill_rate)
  return {0, math.floor(tokens), ms_until}
end
`;

let tokenBucketScriptSha = null;
let initRedisPromise = (async () => {
  try {
    await redisClient.ping();
    tokenBucketScriptSha = await redisClient.script('LOAD', tokenBucketLua);
    console.log('Redis connected and token-bucket script loaded:', tokenBucketScriptSha);
  } catch (err) {
    console.error('Redis init failed (cache & distributed rate-limiting disabled):', err.message || err);
    tokenBucketScriptSha = null;
  }
})();

// -------------------------
// Config
// -------------------------
const EVENT_BUCKET_CAPACITY = parseInt(process.env.EVENT_BUCKET_CAPACITY || '100', 10);
const EVENT_BUCKET_WINDOW_MS = parseInt(process.env.EVENT_BUCKET_WINDOW_MS || '60000', 10);
const ANALYTICS_BUCKET_CAPACITY = parseInt(process.env.ANALYTICS_BUCKET_CAPACITY || '60', 10);
const ANALYTICS_BUCKET_WINDOW_MS = parseInt(process.env.ANALYTICS_BUCKET_WINDOW_MS || '60000', 10);
const CACHE_TTL_MS = parseInt(process.env.CACHE_TTL_MS || String(2 * 60 * 1000), 10);

// Fallback in-memory cache & token-bucket (single-node)
const fallbackCache = {};
const tbFallback = {};

// -------------------------
// Helpers
// -------------------------
function generateApiKey() {
  return crypto.randomBytes(16).toString('hex');
}

async function redisGetJson(key) {
  try {
    const v = await redisClient.get(key);
    return v ? JSON.parse(v) : null;
  } catch (err) {
    const fb = fallbackCache[key];
    if (fb && fb.expiry > Date.now()) return fb.value;
    return null;
  }
}

async function redisSetJson(key, value, ttlMs) {
  try {
    await redisClient.set(key, JSON.stringify(value), 'PX', ttlMs);
  } catch (err) {
    fallbackCache[key] = { value, expiry: Date.now() + ttlMs };
  }
}

function tbKeyForIp(ip) {
  return `tb:ip:${ip}`;
}
function tbKeyForApiKey(apiKey) {
  return `tb:key:${apiKey}`;
}

function consumeTokenBucketFallback(key, capacity, windowMs, tokensToConsume = 1) {
  const now = Date.now();
  const bucket = tbFallback[key] || { tokens: capacity, lastRefillMs: now };
  const refillRate = capacity / windowMs;
  const elapsed = now - bucket.lastRefillMs;
  const refill = elapsed * refillRate;
  let tokens = Math.min(capacity, bucket.tokens + refill);
  if (tokens >= tokensToConsume) {
    tokens -= tokensToConsume;
    tbFallback[key] = { tokens, lastRefillMs: now };
    return { ok: true, remaining: Math.floor(tokens), retryAfterMs: 0, limit: capacity };
  } else {
    const needed = tokensToConsume - tokens;
    const msUntil = Math.ceil(needed / refillRate);
    tbFallback[key] = { tokens, lastRefillMs: bucket.lastRefillMs };
    return { ok: false, remaining: Math.floor(tokens), retryAfterMs: msUntil, limit: capacity };
  }
}

async function consumeTokenBucketRedis(key, capacity, windowMs, tokensToConsume = 1) {
  if (!tokenBucketScriptSha) {
    // Attempt to reload
    try {
      tokenBucketScriptSha = await redisClient.script('LOAD', tokenBucketLua);
    } catch (err) {
      return consumeTokenBucketFallback(key, capacity, windowMs, tokensToConsume);
    }
  }
  try {
    const res = await redisClient.evalsha(tokenBucketScriptSha, 1, key, String(capacity), String(windowMs), String(tokensToConsume));
    if (!res) return { ok: false, remaining: 0, retryAfterMs: windowMs, limit: capacity };
    if (Number(res[0]) === 1) return { ok: true, remaining: Number(res[1]), retryAfterMs: 0, limit: capacity };
    return { ok: false, remaining: Number(res[1]), retryAfterMs: Number(res[2]), limit: capacity };
  } catch (err) {
    try {
      tokenBucketScriptSha = await redisClient.script('LOAD', tokenBucketLua);
      const res2 = await redisClient.evalsha(tokenBucketScriptSha, 1, key, String(capacity), String(windowMs), String(tokensToConsume));
      if (Number(res2[0]) === 1) return { ok: true, remaining: Number(res2[1]), retryAfterMs: 0, limit: capacity };
      return { ok: false, remaining: Number(res2[1]), retryAfterMs: Number(res2[2]), limit: capacity };
    } catch (err2) {
      return consumeTokenBucketFallback(key, capacity, windowMs, tokensToConsume);
    }
  }
}

// -------------------------
// DB helpers
// -------------------------
async function getAppByApiKey(apiKey) {
  if (!apiKey) return null;
  const q = 'SELECT * FROM apps WHERE api_key = $1 LIMIT 1';
  const r = await pgClient.query(q, [apiKey]);
  return r.rows[0] || null;
}

async function getAppById(id) {
  const q = 'SELECT * FROM apps WHERE id = $1 LIMIT 1';
  const r = await pgClient.query(q, [id]);
  return r.rows[0] || null;
}

// -------------------------
// Express app + middlewares
// -------------------------
const app = express();
app.use(express.json());

// Session store (Redis-backed)
const sessionMiddleware = session({
  store: new RedisStore({ client: redisClient, prefix: 'sess:' }),
  secret: process.env.SESSION_SECRET || 'change_this_session_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true }, // set secure: true behind TLS
});
app.use(sessionMiddleware);

// Passport Google OAuth
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID || '',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
  callbackURL: process.env.OAUTH_CALLBACK_URL || 'http://localhost:3002/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const googleId = profile.id;
    const email = profile.emails && profile.emails[0] && profile.emails[0].value;
    const displayName = profile.displayName || null;
    const avatar = profile.photos && profile.photos[0] && profile.photos[0].value;

    const upsertQ = `
      INSERT INTO users (google_id, email, display_name, avatar_url)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (google_id) DO UPDATE
        SET email = EXCLUDED.email,
            display_name = EXCLUDED.display_name,
            avatar_url = EXCLUDED.avatar_url
      RETURNING *;
    `;
    const r = await pgClient.query(upsertQ, [googleId, email, displayName, avatar]);
    const user = r.rows[0];
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
  try {
    const r = await pgClient.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, r.rows[0] || null);
  } catch (err) {
    done(err);
  }
});

app.use(passport.initialize());
app.use(passport.session());

// Helper middleware to adapt legacy handlers' response format
function sendJsonExpress(res, statusCode, data) {
  res.status(statusCode).json(data);
}

// -------------------------
// Routes (Auth + OAuth)
// -------------------------
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/auth/failure' }),
  (req, res) => {
    // On success, redirect to a simple page or return JSON.
    // For simplicity return JSON if X-Requested-With present, else redirect to /docs or dashboard.
    if (req.headers['accept'] && req.headers['accept'].includes('application/json')) {
      res.json({ message: 'Authentication successful', user: req.user });
    } else {
      res.redirect('/docs'); // or /dashboard in your frontend
    }
  }
);

app.get('/auth/failure', (req, res) => {
  res.status(401).send('Authentication failed');
});

function ensureLoggedIn(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// Protected route - register app for authenticated user
app.post('/api/auth/register-for-user', ensureLoggedIn, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return sendJsonExpress(res, 400, { error: 'Missing name' });
    const apiKey = generateApiKey();
    const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    const q = `INSERT INTO apps (name, user_email, api_key, expires_at, user_id) VALUES ($1,$2,$3,$4,$5) RETURNING id, api_key, expires_at;`;
    const r = await pgClient.query(q, [name, req.user.email || null, apiKey, expiresAt.toISOString(), req.user.id]);
    return sendJsonExpress(res, 201, r.rows[0]);
  } catch (err) {
    console.error('register-for-user error:', err);
    return sendJsonExpress(res, 500, { error: err.message });
  }
});

// -------------------------
// REST endpoints (analytics & api key management)
// These implement the same behavior as the previous server.js
// -------------------------

// POST /api/auth/register (public register)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, userEmail } = req.body || {};
    if (!name || !userEmail) {
      return sendJsonExpress(res, 400, { error: 'Missing required fields: name and userEmail' });
    }
    const apiKey = generateApiKey();
    const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    const insertQ = `
      INSERT INTO apps (name, user_email, api_key, expires_at)
      VALUES ($1, $2, $3, $4)
      RETURNING id, api_key, expires_at;
    `;
    const r = await pgClient.query(insertQ, [name, userEmail, apiKey, expiresAt.toISOString()]);
    const row = r.rows[0];
    return sendJsonExpress(res, 201, { appId: row.id, apiKey: row.api_key, expiresAt: row.expires_at });
  } catch (err) {
    console.error('handleRegister error:', err);
    return sendJsonExpress(res, 400, { error: err.message });
  }
});

// GET /api/auth/api-key?appId=...
app.get('/api/auth/api-key', async (req, res) => {
  try {
    const appIdParam = req.query.appId;
    if (!appIdParam) {
      return sendJsonExpress(res, 400, { error: 'Missing appId parameter' });
    }
    const appId = parseInt(appIdParam, 10);
    const appRow = await getAppById(appId);
    if (!appRow) return sendJsonExpress(res, 404, { error: 'App not found' });
    return sendJsonExpress(res, 200, { apiKey: appRow.api_key });
  } catch (err) {
    return sendJsonExpress(res, 500, { error: err.message });
  }
});

// POST /api/auth/revoke
app.post('/api/auth/revoke', async (req, res) => {
  try {
    const apiKey = (req.body && req.body.apiKey) || req.headers['x-api-key'] || req.headers['X-API-KEY'];
    if (!apiKey) return sendJsonExpress(res, 400, { error: 'Missing apiKey' });
    const appRow = await getAppByApiKey(apiKey);
    if (!appRow) return sendJsonExpress(res, 404, { error: 'Invalid API key' });
    await pgClient.query('UPDATE apps SET revoked = true, revoked_at = $1 WHERE id = $2', [new Date().toISOString(), appRow.id]);
    return sendJsonExpress(res, 200, { message: 'API key revoked' });
  } catch (err) {
    console.error('handleRevoke error:', err);
    return sendJsonExpress(res, 400, { error: err.message });
  }
});

// Helper: check API key validity and return app or null
async function requireValidApp(apiKey) {
  if (!apiKey) return null;
  const appRow = await getAppByApiKey(apiKey);
  if (!appRow) return null;
  if (appRow.revoked) return null;
  if (new Date() > new Date(appRow.expires_at)) return null;
  return appRow;
}

// POST /api/analytics/collect
app.post('/api/analytics/collect', async (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const apiKey = req.headers['x-api-key'] || req.headers['X-API-KEY'] || null;

  // IP token bucket
  const ipKey = tbKeyForIp(ip);
  const ipRes = (tokenBucketScriptSha ? await consumeTokenBucketRedis(ipKey, EVENT_BUCKET_CAPACITY, EVENT_BUCKET_WINDOW_MS, 1) : consumeTokenBucketFallback(ipKey, EVENT_BUCKET_CAPACITY, EVENT_BUCKET_WINDOW_MS, 1));
  if (!ipRes.ok) {
    res.setHeader('Retry-After', String(Math.ceil(ipRes.retryAfterMs / 1000)));
    res.setHeader('X-RateLimit-Limit', String(ipRes.limit));
    res.setHeader('X-RateLimit-Remaining', String(ipRes.remaining));
    return sendJsonExpress(res, 429, { error: 'Rate limit exceeded (ip)', retryAfter: Math.ceil(ipRes.retryAfterMs / 1000) });
  }

  // API-key token bucket
  if (apiKey) {
    const keyKey = tbKeyForApiKey(apiKey);
    const keyRes = (tokenBucketScriptSha ? await consumeTokenBucketRedis(keyKey, EVENT_BUCKET_CAPACITY, EVENT_BUCKET_WINDOW_MS, 1) : consumeTokenBucketFallback(keyKey, EVENT_BUCKET_CAPACITY, EVENT_BUCKET_WINDOW_MS, 1));
    if (!keyRes.ok) {
      res.setHeader('Retry-After', String(Math.ceil(keyRes.retryAfterMs / 1000)));
      res.setHeader('X-RateLimit-Limit', String(keyRes.limit));
      res.setHeader('X-RateLimit-Remaining', String(keyRes.remaining));
      return sendJsonExpress(res, 429, { error: 'Rate limit exceeded (api key)', retryAfter: Math.ceil(keyRes.retryAfterMs / 1000) });
    }
    res.setHeader('X-RateLimit-Limit', String(keyRes.limit));
    res.setHeader('X-RateLimit-Remaining', String(keyRes.remaining));
  } else {
    res.setHeader('X-RateLimit-Limit', String(ipRes.limit));
    res.setHeader('X-RateLimit-Remaining', String(ipRes.remaining));
  }

  if (!apiKey) return sendJsonExpress(res, 401, { error: 'Missing API key' });

  const appRow = await requireValidApp(apiKey);
  if (!appRow) return sendJsonExpress(res, 401, { error: 'Invalid or expired API key' });

  try {
    const { event, url, referrer, device, ipAddress, timestamp, metadata, userId } = req.body || {};
    if (!event) return sendJsonExpress(res, 400, { error: 'Missing event type' });
    const eventTime = timestamp ? new Date(timestamp) : new Date();
    const insertQ = `
      INSERT INTO events
        (app_id, event_type, url, referrer, device, ip_address, timestamp, metadata, user_id)
      VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)
      RETURNING id;
    `;
    const params = [
      appRow.id,
      event,
      url || null,
      referrer || null,
      device || null,
      ipAddress || ip,
      eventTime.toISOString(),
      metadata ? JSON.stringify(metadata) : null,
      userId || (metadata && metadata.userId) || null,
    ];
    await pgClient.query(insertQ, params);

    // Invalidate matching Redis cache keys
    try {
      const stream = redisClient.scanStream({ match: 'eventSummary:*', count: 100 });
      stream.on('data', (keys) => {
        if (keys.length) redisClient.del(...keys).catch(() => {});
      });
    } catch (err) {
      // ignore
    }

    return sendJsonExpress(res, 201, { message: 'Event recorded' });
  } catch (err) {
    console.error('handleCollect error:', err);
    return sendJsonExpress(res, 400, { error: err.message });
  }
});

// GET /api/analytics/event-summary
app.get('/api/analytics/event-summary', async (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const apiKey = req.headers['x-api-key'] || req.headers['X-API-KEY'] || null;

  const ipKey = tbKeyForIp(ip);
  const ipRes = (tokenBucketScriptSha ? await consumeTokenBucketRedis(ipKey, ANALYTICS_BUCKET_CAPACITY, ANALYTICS_BUCKET_WINDOW_MS, 1) : consumeTokenBucketFallback(ipKey, ANALYTICS_BUCKET_CAPACITY, ANALYTICS_BUCKET_WINDOW_MS, 1));
  if (!ipRes.ok) {
    res.setHeader('Retry-After', String(Math.ceil(ipRes.retryAfterMs / 1000)));
    res.setHeader('X-RateLimit-Limit', String(ipRes.limit));
    res.setHeader('X-RateLimit-Remaining', String(ipRes.remaining));
    return sendJsonExpress(res, 429, { error: 'Rate limit exceeded (ip)', retryAfter: Math.ceil(ipRes.retryAfterMs / 1000) });
  }

  if (apiKey) {
    const keyKey = tbKeyForApiKey(apiKey);
    const keyRes = (tokenBucketScriptSha ? await consumeTokenBucketRedis(keyKey, ANALYTICS_BUCKET_CAPACITY, ANALYTICS_BUCKET_WINDOW_MS, 1) : consumeTokenBucketFallback(keyKey, ANALYTICS_BUCKET_CAPACITY, ANALYTICS_BUCKET_WINDOW_MS, 1));
    if (!keyRes.ok) {
      res.setHeader('Retry-After', String(Math.ceil(keyRes.retryAfterMs / 1000)));
      res.setHeader('X-RateLimit-Limit', String(keyRes.limit));
      res.setHeader('X-RateLimit-Remaining', String(keyRes.remaining));
      return sendJsonExpress(res, 429, { error: 'Rate limit exceeded (api key)', retryAfter: Math.ceil(keyRes.retryAfterMs / 1000) });
    }
    res.setHeader('X-RateLimit-Limit', String(keyRes.limit));
    res.setHeader('X-RateLimit-Remaining', String(keyRes.remaining));
  } else {
    res.setHeader('X-RateLimit-Limit', String(ipRes.limit));
    res.setHeader('X-RateLimit-Remaining', String(ipRes.remaining));
  }

  if (!apiKey) return sendJsonExpress(res, 401, { error: 'Missing API key' });

  const appRow = await requireValidApp(apiKey);
  if (!appRow) return sendJsonExpress(res, 401, { error: 'Invalid or expired API key' });

  try {
    const eventType = req.query.event || null;
    const startDateStr = req.query.startDate || null;
    const endDateStr = req.query.endDate || null;
    const appIdParam = req.query.app_id || null;

    const cacheKey = `eventSummary:${apiKey}:${eventType || 'all'}:${startDateStr || 'null'}:${endDateStr || 'null'}:${appIdParam || 'all'}`;
    const cached = await redisGetJson(cacheKey);
    if (cached) {
      res.setHeader('X-Cache', 'HIT');
      return sendJsonExpress(res, 200, cached);
    }

    const where = [];
    const values = [];
    let idx = 1;

    if (appIdParam) {
      where.push(`app_id = $${idx++}`);
      values.push(parseInt(appIdParam, 10));
    } else {
      where.push(`app_id = $${idx++}`);
      values.push(appRow.id);
    }

    if (eventType) {
      where.push(`event_type = $${idx++}`);
      values.push(eventType);
    }
    if (startDateStr) {
      where.push(`timestamp >= $${idx++}`);
      values.push(new Date(startDateStr).toISOString());
    }
    if (endDateStr) {
      where.push(`timestamp <= $${idx++}`);
      values.push(new Date(endDateStr).toISOString());
    }

    const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const countQ = `SELECT COUNT(*)::int AS cnt FROM events ${whereClause};`;
    const countRes = await pgClient.query(countQ, values);
    const count = (countRes.rows[0] && countRes.rows[0].cnt) || 0;

    const uniqueQ = `SELECT COUNT(DISTINCT COALESCE(user_id, ip_address))::int AS unique_count FROM events ${whereClause};`;
    const uniqueRes = await pgClient.query(uniqueQ, values);
    const uniqueUsers = (uniqueRes.rows[0] && uniqueRes.rows[0].unique_count) || 0;

    const deviceQ = `SELECT device, COUNT(*)::int AS cnt FROM events ${whereClause} GROUP BY device ORDER BY cnt DESC;`;
    const deviceRes = await pgClient.query(deviceQ, values);
    const deviceCounts = {};
    deviceRes.rows.forEach(r => {
      deviceCounts[r.device || 'unknown'] = r.cnt;
    });

    const result = {
      event: eventType || 'all',
      count,
      uniqueUsers,
      deviceData: deviceCounts,
    };

    await redisSetJson(cacheKey, result, CACHE_TTL_MS);
    res.setHeader('X-Cache', 'MISS');
    return sendJsonExpress(res, 200, result);
  } catch (err) {
    console.error('handleEventSummary error:', err);
    return sendJsonExpress(res, 500, { error: err.message });
  }
});

// GET /api/analytics/user-stats?userId=...
app.get('/api/analytics/user-stats', async (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const apiKey = req.headers['x-api-key'] || req.headers['X-API-KEY'] || null;

  const ipKey = tbKeyForIp(ip);
  const ipRes = (tokenBucketScriptSha ? await consumeTokenBucketRedis(ipKey, ANALYTICS_BUCKET_CAPACITY, ANALYTICS_BUCKET_WINDOW_MS, 1) : consumeTokenBucketFallback(ipKey, ANALYTICS_BUCKET_CAPACITY, ANALYTICS_BUCKET_WINDOW_MS, 1));
  if (!ipRes.ok) {
    res.setHeader('Retry-After', String(Math.ceil(ipRes.retryAfterMs / 1000)));
    res.setHeader('X-RateLimit-Limit', String(ipRes.limit));
    res.setHeader('X-RateLimit-Remaining', String(ipRes.remaining));
    return sendJsonExpress(res, 429, { error: 'Rate limit exceeded (ip)', retryAfter: Math.ceil(ipRes.retryAfterMs / 1000) });
  }

  if (apiKey) {
    const keyKey = tbKeyForApiKey(apiKey);
    const keyRes = (tokenBucketScriptSha ? await consumeTokenBucketRedis(keyKey, ANALYTICS_BUCKET_CAPACITY, ANALYTICS_BUCKET_WINDOW_MS, 1) : consumeTokenBucketFallback(keyKey, ANALYTICS_BUCKET_CAPACITY, ANALYTICS_BUCKET_WINDOW_MS, 1));
    if (!keyRes.ok) {
      res.setHeader('Retry-After', String(Math.ceil(keyRes.retryAfterMs / 1000)));
      res.setHeader('X-RateLimit-Limit', String(keyRes.limit));
      res.setHeader('X-RateLimit-Remaining', String(keyRes.remaining));
      return sendJsonExpress(res, 429, { error: 'Rate limit exceeded (api key)', retryAfter: Math.ceil(keyRes.retryAfterMs / 1000) });
    }
    res.setHeader('X-RateLimit-Limit', String(keyRes.limit));
    res.setHeader('X-RateLimit-Remaining', String(keyRes.remaining));
  } else {
    res.setHeader('X-RateLimit-Limit', String(ipRes.limit));
    res.setHeader('X-RateLimit-Remaining', String(ipRes.remaining));
  }

  if (!apiKey) return sendJsonExpress(res, 401, { error: 'Missing API key' });

  const appRow = await requireValidApp(apiKey);
  if (!appRow) return sendJsonExpress(res, 401, { error: 'Invalid or expired API key' });

  try {
    const userId = req.query.userId;
    if (!userId) return sendJsonExpress(res, 400, { error: 'Missing userId parameter' });

    const q = `
      SELECT id, event_type, url, referrer, device, ip_address, timestamp, metadata, user_id
      FROM events
      WHERE app_id = $1 AND (user_id = $2 OR ip_address = $2)
      ORDER BY timestamp ASC;
    `;
    const r = await pgClient.query(q, [appRow.id, userId]);
    const rows = r.rows;
    if (rows.length === 0) return sendJsonExpress(res, 404, { error: 'No events found for user' });

    const totalEvents = rows.length;
    const lastEvent = rows[rows.length - 1];
    const deviceDetails = lastEvent.metadata || {};
    const response = {
      userId,
      totalEvents,
      deviceDetails,
      ipAddress: lastEvent.ip_address,
      events: rows.map(ev => ({
        id: ev.id,
        event: ev.event_type,
        url: ev.url,
        timestamp: ev.timestamp,
        metadata: ev.metadata,
      })),
    };
    return sendJsonExpress(res, 200, response);
  } catch (err) {
    console.error('handleUserStats error:', err);
    return sendJsonExpress(res, 500, { error: err.message });
  }
});

// Health & docs endpoints
app.get('/healthz', (req, res) => res.json({ ok: true }));
// /docs could be static Swagger UI — omitted here; serve via /openapi.json + static page if desired

// Fallback 404
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// -------------------------
// Start server helper
// -------------------------
function createServer() {
  return http.createServer(app);
}

if (require.main === module) {
  const port = process.env.PORT || 3002;
  const server = createServer();
  server.listen(port, () => {
    console.log(`Analytics API server listening on port ${port}`);
  });
}

// Exports
module.exports = {
  app,
  createServer,
  pgClient,
  initDbPromise,
  redisClient,
  initRedisPromise,
};
