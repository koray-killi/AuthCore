# AuthCore

A production-discipline authentication and session management microservice written in Go. I built this to sharpen my understanding of identity and access management by implementing the hard parts from scratch — refresh token rotation, OTP verification, account lockout, audit logging — rather than delegating them to a library.

> **About:** AuthCore is a personal project I built from scratch to practice and consolidate the
> backend and application-security patterns I learned during my internship. It shares no
> code with any proprietary codebase.

---

## Why I Built This

Most auth tutorials hand you a JWT package and call it done. I wanted to see what production auth actually looks like end-to-end: token rotation with reuse detection, enumeration-safe login, Argon2id instead of bcrypt, a two-tier rate limiter that can swap to Redis later, and an append-only audit trail. Clean architecture felt like the right frame — it forced me to think about where each piece of logic actually belongs.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         HTTP Client                              │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                      Middleware Stack                            │
│  RealIP → Rate Limiter → Security Headers → Request Logger       │
│  CORS → Body Limit (1 MB) → JWT Auth (protected routes)         │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                       Handler Layer                              │
│  Route → DTO validation → Service call → Response DTO → JSON    │
│  All errors go through httperr — handlers never write raw errors │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                       Service Layer                              │
│  auth_service · token_service · otp_service · audit_service     │
│  All business rules live here — no SQL, no HTTP knowledge        │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Repository Layer                             │
│  user_repo · session_repo · otp_repo · audit_repo               │
│  Hand-written SQL via pgx/v5 — no ORM, no magic                 │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                      PostgreSQL 16                               │
│  users · refresh_sessions · otp_codes · audit_logs              │
│  golang-migrate — idempotent migrations on startup              │
└──────────────────────────────────────────────────────────────────┘
```

---

## Security Properties

These aren't just documented — they're enforced by the layer boundaries:

| Property | Implementation |
|----------|---------------|
| Passwords & OTPs stored as Argon2id hashes | `golang.org/x/crypto/argon2` |
| Refresh tokens stored as SHA-256 hashes | Raw token never touches the database |
| Refresh token rotation with reuse detection | Revoked token replay → revoke **all** sessions + audit log |
| Enumeration-safe login & resend | Dummy Argon2id verify for non-existent users; resend always returns 202 |
| Account lockout after 5 failed logins | 15-minute lock via `locked_until` column |
| OTP: 6-digit, 10-min TTL, 5 attempts, single-use | Enforced in `OTPService.Validate`; invalidated on resend |
| User ID always from JWT claim, never request body | Enforced by JWT middleware → context |
| Domain structs never serialized directly | Explicit response DTOs for every endpoint |
| Audit log is append-only | No UPDATE/DELETE on `AuditRepository` interface |
| Config injected, no global mutable state | `config.Config` passed through all constructors |
| Three-tier rate limiter (IP + account + email) | In-memory sliding window behind `RateLimiter` interface |
| Email format validated before processing | RFC-5322 regex in `middleware.ValidateEmail()` |

---

## Quick Start

### Prerequisites

- Go 1.23+
- Docker & Docker Compose

### Run with Docker Compose

```bash
# Copy the example environment file and set your JWT secret
cp .env.example .env

# Start Postgres, MailHog, and the app
docker compose up --build -d

# Verify it's healthy
curl -s localhost:8080/healthz | jq
```

MailHog (for catching verification emails in development) is available at **http://localhost:8025**.

### Run Locally

```bash
# Start backing services only
docker compose up postgres mailhog -d

# Export required environment variables
export DATABASE_URL="postgres://authcore:authcore@localhost:5432/authcore?sslmode=disable"
export JWT_SECRET="replace-with-a-long-random-string"
export SMTP_HOST=localhost
export SMTP_PORT=1025

make run
```

---

## Environment Variables

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `DATABASE_URL` | — | ✅ | PostgreSQL connection string |
| `JWT_SECRET` | — | ✅ | HMAC-SHA256 signing key |
| `SERVER_PORT` | `8080` | | HTTP listen port |
| `SERVER_READ_TIMEOUT` | `10s` | | |
| `SERVER_WRITE_TIMEOUT` | `10s` | | |
| `SERVER_SHUTDOWN_TIMEOUT` | `15s` | | Graceful shutdown window |
| `JWT_ACCESS_EXPIRY` | `15m` | | Access token lifetime |
| `JWT_REFRESH_EXPIRY` | `168h` | | Refresh token lifetime (7 days) |
| `SMTP_HOST` | `localhost` | | |
| `SMTP_PORT` | `1025` | | |
| `SMTP_FROM` | `noreply@authcore.local` | | |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000` | | Comma-separated |
| `RATE_LIMIT_IP_REQUESTS` | `60` | | Max requests per IP per window |
| `RATE_LIMIT_IP_WINDOW` | `1m` | | IP rate limit window |
| `RATE_LIMIT_ACCOUNT_REQUESTS` | `10` | | Max login attempts per email per window |
| `RATE_LIMIT_ACCOUNT_WINDOW` | `1m` | | Account rate limit window |
| `RATE_LIMIT_EMAIL_REQUESTS` | `3` | | Max email-sending actions per address per window |
| `RATE_LIMIT_EMAIL_WINDOW` | `10m` | | Email rate limit window (register, resend, forgot-password) |

---

## API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/healthz` | Public | Health check with DB ping |
| `POST` | `/api/v1/auth/register` | Public | Register; sends email verification OTP. Re-sends OTP if account is inactive. |
| `POST` | `/api/v1/auth/verify-email` | Public | Confirm OTP, activate account |
| `POST` | `/api/v1/auth/resend-verification` | Public | Request a fresh OTP; always returns 202 (enumeration-safe) |
| `POST` | `/api/v1/auth/login` | Public | Returns access token + sets refresh cookie |
| `POST` | `/api/v1/auth/refresh` | Cookie | Rotates refresh token |
| `POST` | `/api/v1/auth/logout` | Bearer | Revokes current session |
| `POST` | `/api/v1/auth/logout-all` | Bearer | Revokes all user sessions |
| `POST` | `/api/v1/auth/forgot-password` | Public | Always returns 202 (enumeration-safe) |
| `POST` | `/api/v1/auth/reset-password` | Public | OTP + new password; revokes all sessions |
| `GET` | `/api/v1/auth/me` | Bearer | Authenticated user profile |
| `GET` | `/api/v1/admin/audit-logs` | Bearer + admin | Paginated audit log |

Full request/response examples are in [`docs/api.md`](docs/api.md).

---

## Try It with curl

```bash
BASE=http://localhost:8080/api/v1

# Register
curl -s -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"supersecure1"}' | jq

# Grab the OTP from MailHog
OTP=$(curl -s http://localhost:8025/api/v2/messages \
  | python3 -c "import sys,json,re; d=json.load(sys.stdin); [print(m.group(1)) for i in d['items'] for m in [re.search(r'\\b([0-9]{6})\\b', i['Content']['Body'])] if m]" | head -1)

# Verify email
curl -s -X POST "$BASE/auth/verify-email" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"you@example.com\",\"code\":\"$OTP\"}" | jq

# Login (saves the refresh cookie)
ACCESS=$(curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"supersecure1"}' \
  -c cookies.txt | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Get your profile
curl -s "$BASE/auth/me" -H "Authorization: Bearer $ACCESS" | jq

# Rotate the refresh token
curl -s -X POST "$BASE/auth/refresh" -b cookies.txt -c cookies.txt | jq

# Forgot your OTP limit? Request a new one
curl -s -X POST "$BASE/auth/resend-verification" \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com"}' | jq

# Logout
curl -s -X POST "$BASE/auth/logout" \
  -H "Authorization: Bearer $ACCESS" -b cookies.txt | jq
```

---

## Testing

```bash
# Unit tests with race detector and coverage
make test

# View coverage as HTML
make coverage-html && open coverage.html

# Integration test against a real Postgres + MailHog
make docker-test-up
make test-integration
make docker-test-down
```

The unit test suite covers the service layer with fake repositories (~78% coverage). The integration test in `internal/e2e/` runs a full register → verify → login → refresh → logout cycle against a containerized database.

---

## Project Layout

```
AuthCore/
├── cmd/authcore/main.go          # Wires everything together, starts the server
├── internal/
│   ├── config/                   # Loads config from environment
│   ├── database/                 # pgxpool connection + golang-migrate runner
│   ├── domain/                   # Entities (User, RefreshSession) + typed errors
│   ├── repository/               # SQL access — pure data, no business logic
│   ├── service/                  # All business rules live here
│   ├── handler/                  # HTTP handlers, DTOs, chi router
│   ├── middleware/               # JWT auth, rate limiting, request logging
│   ├── httperr/                  # Typed error → JSON response mapping
│   └── mailer/                   # Mailer interface + SMTP implementation
├── migrations/                   # Up/down SQL files
├── docs/                         # Architecture, ADRs, API reference
├── Dockerfile                    # Multi-stage build (~20 MB final image)
├── docker-compose.yml            # Dev: Postgres + MailHog + app
├── docker-compose.test.yml       # Test: isolated Postgres + MailHog
└── Makefile                      # build, test, lint, docker targets
```

---

## Roadmap

- [ ] Redis-backed rate limiter (interface is already in place)
- [ ] TOTP two-factor authentication
- [ ] OAuth2 provider integration (Google, GitHub)
- [ ] Password history (block reuse of last N passwords)
- [ ] OpenTelemetry tracing

---

## License

MIT
