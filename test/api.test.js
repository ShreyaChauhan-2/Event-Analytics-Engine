// test/api.test.js
// Tests for the analytics API server using Node's built‑in test runner.

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { createServer } = require('../server');

let server;
let baseUrl;
let port;

before(async () => {
  // Start the server on an available port before tests
  server = createServer();
  await new Promise((resolve) => {
    const listener = server.listen(0, () => {
      port = listener.address().port;
      baseUrl = `http://localhost:${port}`;
      resolve();
    });
  });
});

after(() => {
  if (server) server.close();
});

async function fetchJson(url, options) {
  const res = await fetch(url, options);
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = null;
  }
  return { status: res.status, data };
}

test('API key registration and retrieval works', async () => {
  // Register new app
  const registerRes = await fetchJson(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'TestApp', userEmail: 'test@example.com' }),
  });
  assert.strictEqual(registerRes.status, 201);
  assert.ok(registerRes.data.apiKey);
  assert.ok(registerRes.data.appId);

  const { apiKey, appId } = registerRes.data;
  // Retrieve apiKey via GET
  const getRes = await fetchJson(`${baseUrl}/api/auth/api-key?appId=${appId}`, {
    method: 'GET',
  });
  assert.strictEqual(getRes.status, 200);
  assert.strictEqual(getRes.data.apiKey, apiKey);
});

test('Event collection and event summary', async () => {
  // Register app
  const reg = await fetchJson(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'AnalyticsApp', userEmail: 'user@domain.com' }),
  });
  const apiKey = reg.data.apiKey;

  // Submit two events
  for (let i = 0; i < 2; i++) {
    const collectRes = await fetchJson(`${baseUrl}/api/analytics/collect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey },
      body: JSON.stringify({
        event: 'login_form_cta_click',
        url: 'https://example.com/page',
        referrer: 'https://google.com',
        device: 'mobile',
        ipAddress: `192.168.0.${i + 1}`,
        metadata: { browser: 'Chrome', os: 'Android', userId: `user${i}` },
      }),
    });
    assert.strictEqual(collectRes.status, 201);
  }
  // Request summary
  const summaryRes = await fetchJson(`${baseUrl}/api/analytics/event-summary?event=login_form_cta_click`, {
    method: 'GET',
    headers: { 'x-api-key': apiKey },
  });
  assert.strictEqual(summaryRes.status, 200);
  assert.strictEqual(summaryRes.data.event, 'login_form_cta_click');
  assert.strictEqual(summaryRes.data.count >= 2, true);
  assert.strictEqual(summaryRes.data.uniqueUsers >= 2, true);
  assert.ok(summaryRes.data.deviceData.mobile >= 2);
});

test('User stats returns correct data', async () => {
  // Register app
  const reg = await fetchJson(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'UserStatsApp', userEmail: 'user@example.com' }),
  });
  const apiKey = reg.data.apiKey;
  const userId = 'user789';
  // Submit events for this user
  for (let i = 0; i < 3; i++) {
    await fetchJson(`${baseUrl}/api/analytics/collect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey },
      body: JSON.stringify({
        event: 'click',
        device: 'desktop',
        ipAddress: '10.0.0.1',
        metadata: { browser: 'Firefox', os: 'Linux', userId },
      }),
    });
  }
  // Get user stats
  const statsRes = await fetchJson(`${baseUrl}/api/analytics/user-stats?userId=${userId}`, {
    method: 'GET',
    headers: { 'x-api-key': apiKey },
  });
  assert.strictEqual(statsRes.status, 200);
  assert.strictEqual(statsRes.data.userId, userId);
  assert.ok(statsRes.data.totalEvents >= 3);
  assert.strictEqual(statsRes.data.deviceDetails.browser, 'Firefox');
  assert.strictEqual(statsRes.data.deviceDetails.os, 'Linux');
  assert.strictEqual(statsRes.data.ipAddress, '10.0.0.1');
});

test('Revoking API key prevents further use', async () => {
  // Register app
  const reg = await fetchJson(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'RevokeApp', userEmail: 'revoke@domain.com' }),
  });
  const apiKey = reg.data.apiKey;
  // Revoke key
  const revokeRes = await fetchJson(`${baseUrl}/api/auth/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apiKey }),
  });
  assert.strictEqual(revokeRes.status, 200);
  // Attempt to collect event should fail
  const collectRes = await fetchJson(`${baseUrl}/api/analytics/collect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey },
    body: JSON.stringify({ event: 'test', device: 'mobile' }),
  });
  assert.strictEqual(collectRes.status, 401);
});