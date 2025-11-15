// server.js
// A minimal analytics backend implemented using Node.js built‑in modules.
//
// This server implements API key management, event ingestion and analytics
// summarisation using in‑memory data structures. It does not persist data
// between restarts. Rate limiting and caching are also implemented
// in‑memory. For production use you should replace these in‑memory stores
// with a durable database (e.g. PostgreSQL) and caching layer (e.g. Redis).

require('dotenv').config();
const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const {Client}= require('pg');
const con=new Client({
  hostname:"localhost",
  user:"postgres",
  port:5433,
  password:"1409",
  database:"dbanalytics",
})

con.connect().then(()=>console.log("db successfully connected"));
// In‑memory stores for apps, events, cache and rate limiting
// apps: apiKey -> appInfo
const apps = {};
let nextAppId = 1;

// events: array of event objects
const events = [];
let nextEventId = 1;

// cache: key -> { value, expiry }
const cache = {};

// rateLimits: ip -> { count, windowStart }
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

// Route handlers
async function handleRegister(req, res) {
  try {
    const body = await parseRequestBody(req);
    const { name, userEmail } = body;
    if (!name || !userEmail) {
      return sendJson(res, 400, { error: 'Missing required fields: name and userEmail' });
    }
    const apiKey = generateApiKey();
    const appId = nextAppId++;
    const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year expiry
    apps[apiKey] = {
      id: appId,
      name,
      userEmail,
      apiKey,
      revoked: false,
      expiresAt,
    };
    return sendJson(res, 201, { appId, apiKey, expiresAt: expiresAt.toISOString() });
  } catch (err) {
    return sendJson(res, 400, { error: err.message });
  }
}

async function handleGetApiKey(req, res, url) {
  const params = url.searchParams;
  const appIdParam = params.get('appId');
  if (!appIdParam) {
    return sendJson(res, 400, { error: 'Missing appId parameter' });
  }
  const appId = parseInt(appIdParam, 10);
  const app = Object.values(apps).find(a => a.id === appId);
  if (!app) {
    return sendJson(res, 404, { error: 'App not found' });
  }
  return sendJson(res, 200, { apiKey: app.apiKey });
}

async function handleRevoke(req, res) {
  try {
    const body = await parseRequestBody(req);
    const apiKey = body.apiKey || req.headers['x-api-key'];
    if (!apiKey) {
      return sendJson(res, 400, { error: 'Missing apiKey' });
    }
    const app = apps[apiKey];
    if (!app) {
      return sendJson(res, 404, { error: 'Invalid API key' });
    }
    app.revoked = true;
    app.revokedAt = new Date();
    return sendJson(res, 200, { message: 'API key revoked' });
  } catch (err) {
    return sendJson(res, 400, { error: err.message });
  }
}

async function handleCollect(req, res, ip) {
  // Rate limit event submissions
  if (!checkRateLimit(ip, EVENT_LIMIT_PER_WINDOW)) {
    return sendJson(res, 429, { error: 'Rate limit exceeded' });
  }
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    return sendJson(res, 401, { error: 'Missing API key' });
  }
  const app = apps[apiKey];
  if (!app || app.revoked || new Date() > app.expiresAt) {
    return sendJson(res, 401, { error: 'Invalid or expired API key' });
  }
  try {
    const body = await parseRequestBody(req);
    const { event, url, referrer, device, ipAddress, timestamp, metadata, userId } = body;
    if (!event) {
      return sendJson(res, 400, { error: 'Missing event type' });
    }
    const eventTime = timestamp ? new Date(timestamp) : new Date();
    const newEvent = {
      id: nextEventId++,
      appId: app.id,
      event,
      url: url || null,
      referrer: referrer || null,
      device: device || null,
      ipAddress: ipAddress || ip,
      timestamp: eventTime,
      metadata: metadata || {},
      userId: userId || (metadata && metadata.userId) || null,
    };
    events.push(newEvent);
    // Invalidate cache keys related to this event
    Object.keys(cache).forEach(key => {
      if (key.startsWith('eventSummary:')) {
        delete cache[key];
      }
    });
    return sendJson(res, 201, { message: 'Event recorded' });
  } catch (err) {
    return sendJson(res, 400, { error: err.message });
  }
}

async function handleEventSummary(req, res, url, ip) {
  // Rate limit analytics requests
  if (!checkRateLimit(ip, ANALYTICS_LIMIT_PER_WINDOW)) {
    return sendJson(res, 429, { error: 'Rate limit exceeded' });
  }
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    return sendJson(res, 401, { error: 'Missing API key' });
  }
  const app = apps[apiKey];
  if (!app || app.revoked || new Date() > app.expiresAt) {
    return sendJson(res, 401, { error: 'Invalid or expired API key' });
  }
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
  let filtered = events;
  if (eventType) {
    filtered = filtered.filter(ev => ev.event === eventType);
  }
  if (startDateStr) {
    const startDate = new Date(startDateStr);
    filtered = filtered.filter(ev => ev.timestamp >= startDate);
  }
  if (endDateStr) {
    const endDate = new Date(endDateStr);
    filtered = filtered.filter(ev => ev.timestamp <= endDate);
  }
  if (appIdParam) {
    const id = parseInt(appIdParam, 10);
    filtered = filtered.filter(ev => ev.appId === id);
  }
  const count = filtered.length;
  const userSet = new Set();
  const deviceCounts = {};
  filtered.forEach(ev => {
    // Count unique userId or ip
    if (ev.userId) {
      userSet.add(ev.userId);
    } else if (ev.ipAddress) {
      userSet.add(ev.ipAddress);
    }
    if (ev.device) {
      deviceCounts[ev.device] = (deviceCounts[ev.device] || 0) + 1;
    }
  });
  const uniqueUsers = userSet.size;
  const result = {
    event: eventType || 'all',
    count,
    uniqueUsers,
    deviceData: deviceCounts,
  };
  // Cache result
  cache[cacheKey] = { value: result, expiry: Date.now() + CACHE_TTL_MS };
  return sendJson(res, 200, result);
}

async function handleUserStats(req, res, url, ip) {
  // Rate limit analytics requests
  if (!checkRateLimit(ip, ANALYTICS_LIMIT_PER_WINDOW)) {
    return sendJson(res, 429, { error: 'Rate limit exceeded' });
  }
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    return sendJson(res, 401, { error: 'Missing API key' });
  }
  const app = apps[apiKey];
  if (!app || app.revoked || new Date() > app.expiresAt) {
    return sendJson(res, 401, { error: 'Invalid or expired API key' });
  }
  const params = url.searchParams;
  const userId = params.get('userId');
  if (!userId) {
    return sendJson(res, 400, { error: 'Missing userId parameter' });
  }
  const userEvents = events.filter(ev => {
    if (ev.userId) {
      return String(ev.userId) === String(userId);
    }
    // fallback: match ipAddress
    return ev.ipAddress === userId;
  });
  if (userEvents.length === 0) {
    return sendJson(res, 404, { error: 'No events found for user' });
  }
  const totalEvents = userEvents.length;
  // Use last event to extract device details and ip
  const lastEvent = userEvents[userEvents.length - 1];
  const deviceDetails = lastEvent.metadata || {};
  const response = {
    userId,
    totalEvents,
    deviceDetails,
    ipAddress: lastEvent.ipAddress,
  };
  return sendJson(res, 200, response);
}

// Main request handler
async function requestHandler(req, res) {
  const ip = req.socket.remoteAddress || 'unknown';
  // Parse URL
  const url = new URL(req.url, 'http://localhost');
  const method = req.method;
  const pathname = url.pathname;
  // CORS support for testing and cross‑origin calls
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
    return sendJson(res, 500, { error: 'Internal server error', details: err.message });
  }
}

// Create the HTTP server
function createServer() {
  return http.createServer((req, res) => {
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

module.exports = { createServer, apps, events, cache, rateLimits };