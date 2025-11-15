// server.js
// Analytics backend with persistence to PostgreSQL for apps and events.
// Exports `createServer`, `pgClient`, and `initDbPromise` so tests can await DB readiness.

require('dotenv').config();
const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');
const { Client } = require('pg');

// Postgres client configuration (use env vars or sensible defaults)
const pgClient = new Client({
  host: process.env.PG_HOST || 'localhost',
  user: process.env.PG_USER || 'postgres',
  port: process.env.PG_PORT ? parseInt(process.env.PG_PORT, 10) : 5432,
  password: process.env.PG_PASSWORD || '',
  database: process.env.PG_DATABASE || 'dbanalytics',
  // optional: ssl: { rejectUnauthorized: false } if needed
});

// -------------------------
// initDbPromise — exported so tests can await DB setup
// -------------------------
let initDbPromise = (async () => {
  try {
    await pgClient.connect();
    console.log('db successfully connected');

    // Ensure tables exist (safe to run on start; simple migration)
    await pgClient.query(`
      CREATE TABLE IF NOT EXISTS apps (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        user_email TEXT NOT NULL,
        api_key TEXT UNIQUE NOT NULL,
        revoked BOOLEAN DEFAULT FALSE,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ,
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

// In-memory stores for cache and rate limiting
const cache = {};
const rateLimits = {};

// Configuration
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute window
const EVENT_LIMIT_PER_WINDOW = 100;     // allow 100 events per IP per minute
const ANALYTICS_LIMIT_PER_WINDOW = 60;  // allow 60 analytics requests per IP per minute
const CACHE_TTL_MS = 2 * 60 * 1000; // cache analytics summary for 2 minutes

// Helper: generate a random API key
function generateApiKey() {
  return crypto.randomBytes(16).toString('hex');
}

// Helper: parse JSON body from request
function parseRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      // Prevent large bodies
      if (body.length > 1e6) {
        req.connection.destroy();
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        const json = JSON.parse(body);
        resolve(json);
      } catch (err) {
        reject(new Error('Invalid JSON'));
      }
    });
  });
}

// Helper: send JSON response
function sendJson(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

// Middleware: rate limiter
function checkRateLimit(ip, limit) {
  const now = Date.now();
  const info = rateLimits[ip] || { count: 0, windowStart: now };
  // Reset window if expired
  if (now - info.windowStart > RATE_LIMIT_WINDOW_MS) {
    info.count = 0;
    info.windowStart = now;
  }
  info.count += 1;
  rateLimits[ip] = info;
  return info.count <= limit;
}

// DB helpers
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

// Route handlers
async function handleRegister(req, res) {
  try {
    const body = await parseRequestBody(req);
    const { name, userEmail } = body;
    if (!name || !userEmail) {
      return sendJson(res, 400, { error: 'Missing required fields: name and userEmail' });
    }
    const apiKey = generateApiKey();
    const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year expiry

    const insertQ = `
      INSERT INTO apps (name, user_email, api_key, expires_at)
      VALUES ($1, $2, $3, $4)
      RETURNING id, api_key, expires_at;
    `;
    const r = await pgClient.query(insertQ, [name, userEmail, apiKey, expiresAt.toISOString()]);
    const row = r.rows[0];
    return sendJson(res, 201, { appId: row.id, apiKey: row.api_key, expiresAt: row.expires_at });
  } catch (err) {
    console.error('handleRegister error:', err);
    return sendJson(res, 400, { error: err.message });
  }
}

async function handleGetApiKey(req, res, url) {
  try {
    const params = url.searchParams;
    const appIdParam = params.get('appId');
    if (!appIdParam) {
      return sendJson(res, 400, { error: 'Missing appId parameter' });
    }
    const appId = parseInt(appIdParam, 10);
    const app = await getAppById(appId);
    if (!app) {
      return sendJson(res, 404, { error: 'App not found' });
    }
    return sendJson(res, 200, { apiKey: app.api_key });
  } catch (err) {
    return sendJson(res, 500, { error: err.message });
  }
}

async function handleRevoke(req, res) {
  try {
    const body = await parseRequestBody(req);
    const apiKey = body.apiKey || req.headers['x-api-key'];
    if (!apiKey) {
      return sendJson(res, 400, { error: 'Missing apiKey' });
    }
    const app = await getAppByApiKey(apiKey);
    if (!app) {
      return sendJson(res, 404, { error: 'Invalid API key' });
    }
    const now = new Date();
    await pgClient.query('UPDATE apps SET revoked = true, revoked_at = $1 WHERE id = $2', [now.toISOString(), app.id]);
    return sendJson(res, 200, { message: 'API key revoked' });
  } catch (err) {
    console.error('handleRevoke error:', err);
    return sendJson(res, 400, { error: err.message });
  }
}

async function handleCollect(req, res, ip) {
  // Rate limit event submissions
  if (!checkRateLimit(ip, EVENT_LIMIT_PER_WINDOW)) {
    return sendJson(res, 429, { error: 'Rate limit exceeded' });
  }
  const apiKey = req.headers['x-api-key'] || req.headers['X-API-KEY'];
  if (!apiKey) {
    return sendJson(res, 401, { error: 'Missing API key' });
  }
  const app = await getAppByApiKey(apiKey);
  if (!app || app.revoked || new Date() > new Date(app.expires_at)) {
    return sendJson(res, 401, { error: 'Invalid or expired API key' });
  }
  try {
    const body = await parseRequestBody(req);
    const { event, url, referrer, device, ipAddress, timestamp, metadata, userId } = body;
    if (!event) {
      return sendJson(res, 400, { error: 'Missing event type' });
    }
    const eventTime = timestamp ? new Date(timestamp) : new Date();
    const insertQ = `
      INSERT INTO events
        (app_id, event_type, url, referrer, device, ip_address, timestamp, metadata, user_id)
      VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)
      RETURNING id;
    `;
    const params = [
      app.id,
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

    // Invalidate cached summaries that might be affected
    Object.keys(cache).forEach(key => {
      if (key.startsWith('eventSummary:')) {
        delete cache[key];
      }
    });

    return sendJson(res, 201, { message: 'Event recorded' });
  } catch (err) {
    console.error('handleCollect error:', err);
    return sendJson(res, 400, { error: err.message });
  }
}

async function handleEventSummary(req, res, url, ip) {
  // Rate limit analytics requests
  if (!checkRateLimit(ip, ANALYTICS_LIMIT_PER_WINDOW)) {
    return sendJson(res, 429, { error: 'Rate limit exceeded' });
  }
  const apiKey = req.headers['x-api-key'] || req.headers['X-API-KEY'];
  if (!apiKey) {
    return sendJson(res, 401, { error: 'Missing API key' });
  }
  const app = await getAppByApiKey(apiKey);
  if (!app || app.revoked || new Date() > new Date(app.expires_at)) {
    return sendJson(res, 401, { error: 'Invalid or expired API key' });
  }

  try {
    const params = url.searchParams;
    const eventType = params.get('event');
    const startDateStr = params.get('startDate');
    const endDateStr = params.get('endDate');
    const appIdParam = params.get('app_id');

    // Compose cache key
    const cacheKey = `eventSummary:${apiKey}:${eventType || 'all'}:${startDateStr || 'null'}:${endDateStr || 'null'}:${appIdParam || 'all'}`;
    const cached = cache[cacheKey];
    if (cached && cached.expiry > Date.now()) {
      return sendJson(res, 200, cached.value);
    }

    // Build dynamic where clauses
    const where = [];
    const values = [];
    let idx = 1;

    // Only include events that belong to the requested app (or app_id param)
    if (appIdParam) {
      where.push(`app_id = $${idx++}`);
      values.push(parseInt(appIdParam, 10));
    } else {
      where.push(`app_id = $${idx++}`);
      values.push(app.id);
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

    // Total count
    const countQ = `SELECT COUNT(*)::int AS cnt FROM events ${whereClause};`;
    const countRes = await pgClient.query(countQ, values);
    const count = (countRes.rows[0] && countRes.rows[0].cnt) || 0;

    // Unique users: distinct coalesce(user_id, ip_address)
    const uniqueQ = `SELECT COUNT(DISTINCT COALESCE(user_id, ip_address))::int AS unique_count FROM events ${whereClause};`;
    const uniqueRes = await pgClient.query(uniqueQ, values);
    const uniqueUsers = (uniqueRes.rows[0] && uniqueRes.rows[0].unique_count) || 0;

    // Device counts
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

    // Cache result
    cache[cacheKey] = { value: result, expiry: Date.now() + CACHE_TTL_MS };

    return sendJson(res, 200, result);
  } catch (err) {
    console.error('handleEventSummary error:', err);
    return sendJson(res, 500, { error: err.message });
  }
}

async function handleUserStats(req, res, url, ip) {
  // Rate limit analytics requests
  if (!checkRateLimit(ip, ANALYTICS_LIMIT_PER_WINDOW)) {
    return sendJson(res, 429, { error: 'Rate limit exceeded' });
  }
  const apiKey = req.headers['x-api-key'] || req.headers['X-API-KEY'];
  if (!apiKey) {
    return sendJson(res, 401, { error: 'Missing API key' });
  }
  const app = await getAppByApiKey(apiKey);
  if (!app || app.revoked || new Date() > new Date(app.expires_at)) {
    return sendJson(res, 401, { error: 'Invalid or expired API key' });
  }
  try {
    const params = url.searchParams;
    const userId = params.get('userId');
    if (!userId) {
      return sendJson(res, 400, { error: 'Missing userId parameter' });
    }

    const q = `
      SELECT id, event_type, url, referrer, device, ip_address, timestamp, metadata, user_id
      FROM events
      WHERE app_id = $1 AND (user_id = $2 OR ip_address = $2)
      ORDER BY timestamp ASC;
    `;
    const r = await pgClient.query(q, [app.id, userId]);
    const rows = r.rows;

    if (rows.length === 0) {
      return sendJson(res, 404, { error: 'No events found for user' });
    }

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
    return sendJson(res, 200, response);
  } catch (err) {
    console.error('handleUserStats error:', err);
    return sendJson(res, 500, { error: err.message });
  }
}

// Main request handler
async function requestHandler(req, res) {
  const ip = req.socket.remoteAddress || 'unknown';
  // Parse URL
  const url = new URL(req.url, 'http://localhost');
  const method = req.method;
  const pathname = url.pathname;

  // CORS support for testing and cross-origin calls
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,X-API-KEY,x-api-key',
      'Access-Control-Max-Age': '86400',
    });
    return res.end();
  }

  // Set CORS headers on all responses
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,X-API-KEY,x-api-key');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');

  try {
    // Routing
    if (method === 'POST' && pathname === '/api/auth/register') {
      return handleRegister(req, res);
    }
    if (method === 'GET' && pathname === '/api/auth/api-key') {
      return handleGetApiKey(req, res, url);
    }
    if (method === 'POST' && pathname === '/api/auth/revoke') {
      return handleRevoke(req, res);
    }
    if (method === 'POST' && pathname === '/api/analytics/collect') {
      return handleCollect(req, res, ip);
    }
    if (method === 'GET' && pathname === '/api/analytics/event-summary') {
      return handleEventSummary(req, res, url, ip);
    }
    if (method === 'GET' && pathname === '/api/analytics/user-stats') {
      return handleUserStats(req, res, url, ip);
    }
    return sendJson(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error('requestHandler error:', err);
    return sendJson(res, 500, { error: 'Internal server error', details: err.message });
  }
}

// Create the HTTP server
function createServer() {
  return http.createServer((req, res) => {
    // requestHandler returns a promise; errors inside are handled
    requestHandler(req, res);
  });
}

// Only start the server automatically if this file is run directly
if (require.main === module) {
  const port = process.env.PORT || 3002;
  const server = createServer();
  server.listen(port, () => {
    console.log(`Analytics API server listening on port ${port}`);
  });
}

// Export server creator, pg client and init promise for tests / external control
module.exports = {createServer,pgClient,initDbPromise,};
