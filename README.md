# Event-Analytics-Engine API

This project implements a **simple yet extensible backend API** for collecting analytics events from websites and mobile applications.
It provides endpoints for:

* Managing API keys
* Recording events
* Retrieving aggregated statistics
* Rate limiting & caching
* Dockerized deployment
* OAuth onboarding
* Automated testing

The system built using **PostgreSQL + Redis** instead of in-memory storage, and includes a **scalable architecture suitable for real deployments**.

---

# Overview of Implemented Features

## Authentication & API Management

* Google OAuth login for secure onboarding
* API key generation
* Retrieve or revoke API keys
* Apps linked to authenticated Google users

## Event Collection

* Record events with metadata (device, browser, url, referrer, IP, timestamps, userId)
* Automatic timestamping
* Supports both web & mobile apps

## Analytics & Reporting

* Total event count
* Unique user count
* Per-device distribution
* Per-user history & metadata
* PostgreSQL efficient queries
* Redis caching for 2-minute summaries

## Security & Rate Limiting

* Redis token bucket
* 100 events/min per IP (ingestion)
* 60 analytics requests/min per IP
* Distributed-safe and horizontally scalable

## Infrastructure & Dev Features

* PostgreSQL for persistence
* Redis for caching & sessions
* Docker & Docker Compose
* Automated tests (Node Test Runner)
* Swagger docs
* Clean architecture, modular design

---

# Architecture Overview

This system uses **PostgreSQL + Redis** instead of in-memory storage, solving durability and scalability issues.

| Component            | Role                                         |
| -------------------- | -------------------------------------------- |
| Express.js           | Main HTTP server                             |
| PostgreSQL           | Persistent store for apps, events, and users |
| Redis                | Cache, rate limiting, OAuth sessions         |
| Lua Token Bucket     | Atomic distributed rate limiting             |
| Passport.js (Google) | OAuth authentication                         |
| Docker Compose       | Development + deployment                     |
| Node Test Runner     | Automated testing                            |

### Data Flow (Simplified)

```
Client → Backend → PostgreSQL (Stores events)
                 → Redis (Cache, rate limiting, OAuth session)
                 → Swagger docs
                 → Test suite
```

---

# Project Structure

```
/server.js               → Main server
/test/api.test.js        → Automated integration tests
/swagger.json            → API documentation
/Dockerfile              → Build backend container
/README.md               → Documentation
```

---

# Instructions to Run the Project

## 1 Clone the Repository

```bash
git clone https://github.com/ShreyaChauhan-2/Event-Analytics-Engine
```

## 2 Install Dependencies

```bash
npm install
```

## 3 Create `.env` File

Create a `.env` file in the project root:

```
PORT=3002

# PostgreSQL
PG_HOST=localhost
PG_PORT=5433
PG_USER=postgres
PG_PASSWORD=postgres
PG_DATABASE=dbanalytics

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

SESSION_SECRET=replace_this_secret

# Google OAuth
GOOGLE_CLIENT_ID=<your-client-id>.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=<your-secret>
OAUTH_CALLBACK_URL=http://localhost:3002/auth/google/callback
```

---

# Running with Docker

Start all services:

```bash
docker-compose up --build
```

Stop:

```bash
docker-compose down
```

Reset completely (remove db/cache):

```bash
docker-compose down -v
```

---

# Running Without Docker

Ensure **PostgreSQL** and **Redis** are running locally.

Start API:

```bash
npm start
```

Runs on:

**[http://localhost:3002](http://localhost:3002)**

---

# 🧪 Running Tests

```bash
npm test
```

Tests automatically:

* Truncate PostgreSQL tables
* Flush Redis
* Validate API key registration
* Validate OAuth-linked registration
* Test event ingestion
* Test event analytics
* Test per-user statistics
* Test key revocation

---

# API Endpoints Overview

## Authentication

### `GET /auth/google`

Start OAuth login.

### `GET /auth/google/callback`

OAuth callback.

### `POST /api/auth/register`

Register an app manually.

### `POST /api/auth/register-for-user`

Register an app for an authenticated Google user.

### `GET /api/auth/api-key`

Retrieve the API key for an app.

### `POST /api/auth/revoke`

Revoke an API key.

---

## Event Collection

### `POST /api/analytics/collect`

Send analytics events with metadata.

Example:

```json
{
  "event": "page_view",
  "url": "/home",
  "device": "desktop",
  "metadata": {
    "browser": "Chrome",
    "os": "Windows",
    "userId": "user123"
  }
}
```

---

## Analytics Endpoints

### `GET /api/analytics/event-summary`

Returns:

* `event`
* `count`
* `uniqueUsers`
* `deviceData`

### `GET /api/analytics/user-stats`

Returns:

* total events
* latest device info
* latest IP
* metadata history

---

# Development Notes

* For production: PostgreSQL replaces in-memory storage
* OAuth login supported
* Redis used for caching + rate limiting
* OpenAPI documentation included
* Automated testing ensures reliability
* Clean architecture supports easy extension

---

# Challenges & Solutions

### **1. In-memory → PostgreSQL migration**

**Solution:**

* Full relational schema
* JSON for metadata
* Indexes for performance

### **2. Race-safe rate limiting**

**Solution:**

* Redis token bucket
* Distributed scale-safe

### **3. Slow summary analytics**

**Solution:**

* Redis caching + 2-minute TTL
* Auto-invalidation on new events

### **4. Secure onboarding**

**Solution:**

* Google OAuth + Redis session store

### **5. Reliable test environment**

**Solution:**

* DB truncation + Redis flush
* Init promises for service readiness

---

# Conclusion

This repository demonstrates API key management, OAuth onboarding, Event ingestion, Aggregation & cssaching, Rate limiting, Persistence with PostgreSQL, Redis caching + sessions, Production-grade architecture.

