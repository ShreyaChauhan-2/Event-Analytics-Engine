# Website Analytics API

This project implements a simple yet extensible backend API for collecting analytics events from websites and mobile applications.  It provides endpoints for managing API keys, recording events and retrieving aggregated statistics.  The implementation is designed to be easily containerised and tested, with clear separation of concerns and room for future enhancements.

## Features

* **API key management** – register a new app, retrieve your API key and revoke keys when they are no longer needed.
* **Event collection** – send arbitrary events from your website or app.  Events include metadata such as URL, referrer, device, IP address and user details.
* **Analytics & reporting** – summarise events over a time range with counts, unique users and per‑device breakdown.  Retrieve per‑user statistics including device details and IP address.
* **Rate limiting** – basic rate limiting protects the service from abuse on both event ingestion and analytics endpoints.
* **Caching** – aggregated summaries are cached in memory for a short period to reduce repeated computation.
* **OpenAPI documentation** – a `swagger.json` file describes all available endpoints, their inputs and responses.
* **Testing** – a suite of tests using Node’s built‑in test runner exercises the main functionality.
* **Containerised** – a `Dockerfile` is provided for easy deployment.

## Architecture Overview

This demonstration uses **in‑memory data structures** (plain JavaScript objects and arrays) to store API keys, events, caches and rate‑limit state.  While this satisfies the functional requirements, it is not suitable for production.  In a real deployment you should:

* Replace the in‑memory stores with a **persistent database** such as PostgreSQL or MySQL to guarantee durability and support efficient queries and aggregations.
* Use a **caching layer** such as Redis for caching frequently requested analytics results.
* Integrate **Google OAuth** (via Passport.js) to onboard new apps – registration is currently a simple POST request.
* Consider distributing event ingestion and analytics processing using message queues and worker processes for scalability.

The server is implemented using Node.js built‑in modules only (no external dependencies) to accommodate the restricted environment.  It exposes a RESTful API conforming to the specification described below and in the accompanying OpenAPI document.

## Getting Started

Clone or download this repository and then run the following commands from the project root:

```bash
# Install dependencies (none are required – this is a no‑dependency project)

## Run the server directly
npm start

## The server listens on port 3000 by default
```

### Using Docker

To build and run the service in a container:

```bash
docker build -t analytics-api .
docker run -p 3000:3000 analytics-api
```

### Running Tests

This project uses Node’s built‑in test framework.  To execute the tests run:

```bash
npm test
```

All tests should pass, demonstrating that registration, API key retrieval, event collection, summary analytics, per‑user stats and key revocation function as expected.

## API Endpoints

### 1. API Key Management

#### `POST /api/auth/register`

Register a new website or mobile application.  Requires a JSON body with `name` and `userEmail`.  Returns a unique `apiKey` and an `appId` used in subsequent operations.

Example request:

```http
POST /api/auth/register HTTP/1.1
Content-Type: application/json

{
  "name": "Example Website",
  "userEmail": "owner@example.com"
}
```

Example response:

```json
{
  "appId": 1,
  "apiKey": "eb9c9baf3417403dc11d4d1996e8f1b5",
  "expiresAt": "2025-11-14T17:10:00.000Z"
}
```

#### `GET /api/auth/api-key`

Retrieve the API key for a registered application.  Provide the `appId` as a query parameter.

```
GET /api/auth/api-key?appId=1
```

#### `POST /api/auth/revoke`

Revoke an existing API key.  Supply the key in the request body or in the `X‑API‑KEY` header.  After revocation the key can no longer be used.

### 2. Event Data Collection

#### `POST /api/analytics/collect`

Send a single analytics event.  The request must include your API key in the `X‑API‑KEY` header.  The body accepts arbitrary metadata to describe the event.  The only mandatory field is `event`.  If `timestamp` is omitted the current time is used.

Example request:

```http
POST /api/analytics/collect HTTP/1.1
X-API-KEY: eb9c9baf3417403dc11d4d1996e8f1b5
Content-Type: application/json

{
  "event": "login_form_cta_click",
  "url": "https://example.com/page",
  "referrer": "https://google.com",
  "device": "mobile",
  "ipAddress": "203.0.113.42",
  "timestamp": "2024-02-20T12:34:56Z",
  "metadata": {
    "browser": "Chrome",
    "os": "Android",
    "screenSize": "1080x1920",
    "userId": "user123"
  }
}
```

### 3. Analytics Endpoints

All analytics endpoints require your API key in the `X‑API‑KEY` header.  Rate limits apply to prevent abuse.

#### `GET /api/analytics/event-summary`

Retrieve an aggregate summary for a particular event type over an optional date range.  Optional query parameters include:

* `event` – name of the event to summarise (omit to summarise all events).
* `startDate` – ISO date (`YYYY-MM-DD`) at which to start counting events.
* `endDate` – ISO date at which to stop counting events.
* `app_id` – limit the summary to a particular application.

The response includes:

* `event` – the requested event name or `all` when omitted.
* `count` – total number of events matching the criteria.
* `uniqueUsers` – number of distinct users or IP addresses.
* `deviceData` – counts of events per device type.

#### `GET /api/analytics/user-stats`

Return statistics for a specific user.  Provide the `userId` as a query parameter.  The response contains the total number of events, the latest device details (taken from the event metadata) and the last known IP address.

### OpenAPI Documentation

The full API specification is defined in [swagger.json](swagger.json).  You can feed this file into Swagger UI, Redoc or any OpenAPI viewer to explore and interact with the API.

## Development Notes

* **Persistence** – this implementation keeps all data in memory.  Restarting the server will erase all events and API keys.
* **Google OAuth** – the specification calls for Google authentication during onboarding.  For simplicity this proof of concept replaces it with a direct registration endpoint.  A future version can integrate Passport.js with the Google OAuth strategy and store user accounts in a database.
* **Database schema** – a suitable relational schema would include tables for `users` (Google accounts), `apps` (with `user_id` and `api_key` columns), `events` (with `app_id`, `event_name`, timestamps, metadata etc.).  Indexes on `event_name`, `timestamp` and `app_id` would support efficient aggregation.
* **Caching** – instead of the simple in‑memory cache used here you should use Redis or Memcached in production to share cached results across instances and implement proper eviction policies.
* **Logging & monitoring** – the server currently logs only startup.  Consider integrating a structured logger (e.g. Winston or Pino) and exporting metrics to Prometheus or a similar monitoring system.

## Conclusion

This repository demonstrates the core concepts of a scalable analytics service: API key management, event ingestion, aggregation, caching and rate limiting.  Although the example uses in‑memory stores for simplicity, the architecture is designed with clear boundaries that allow swapping in production‑ready components without altering the public API.