# AuthCore

**A production-discipline authentication and session management service built from scratch in Go.**

> AuthCore is a personal project I built from scratch to practice and consolidate the
> backend and application-security patterns I learned during my internship. It shares no
> code with any proprietary codebase.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HTTP Client                              │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Middleware Stack                              │
│  ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌──────────────────┐  │
│  │ RealIP   │→│ Rate     │→│ Security  │→│ Request Logger   │  │
│  │          │ │ Limiter  │ │ Headers   │ │ (zap structured) │  │
│  └──────────┘ └──────────┘ └───────────┘ └──────────────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌───────────┐                       │
│  │ CORS     │→│ Body     │→│ JWT Auth  │ (protected routes)    │
│  │          │ │ Limit 1MB│ │ Middleware │                       │
│  └──────────┘ └──────────┘ └───────────┘                       │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Handler Layer                              │
│  Routes → Request DTO → calls Service → Response DTO → JSON    │
│  ┌────────────────┐ ┌──────────────────┐                        │
│  │ auth_handler   │ │ health_handler   │                        │
│  └────────────────┘ └──────────────────┘                        │
│                          │                                      │
│                    httperr (central error→JSON mapper)           │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Service Layer                              │
│  Business logic, security rules, token management               │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────┐ ┌───────────┐  │
│  │ auth_service │ │ token_service│ │ otp_svc  │ │ audit_svc │  │
│  └──────────────┘ └──────────────┘ └──────────┘ └───────────┘  │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Repository Layer                              │
│  Data access only — no business logic, hand-written SQL         │
│  ┌───────────┐ ┌──────────────┐ ┌──────────┐ ┌──────────────┐  │
│  │ user_repo │ │ session_repo │ │ otp_repo │ │ audit_repo   │  │
│  └───────────┘ └──────────────┘ └──────────┘ └──────────────┘  │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PostgreSQL 16                                │
│  pgx/v5 + golang-migrate — no ORM                              │
│  ┌────────┐ ┌──────────────────┐ ┌───────────┐ ┌────────────┐  │
│  │ users  │ │ refresh_sessions │ │ otp_codes │ │ audit_logs │  │
│  └────────┘ └──────────────────┘ └───────────┘ └────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Rules That Are Enforced, Not Just Documented

| Rule | Enforcement |
|------|-------------|
| Handler never touches SQL | Layer boundary: no `pgx` imports in handler package |
| Repository never makes business decisions | No auth logic, no flow control in repos |
| Raw passwords/tokens never stored | Argon2id for passwords & OTPs, SHA-256 for refresh tokens |
| Sensitive fields never in API responses | DTOs explicitly exclude `password_hash`, `otp_hash`, `token_hash` |
| User ID comes from JWT, never from request body | `middleware.Auth` sets `userID` in context |
| Enumeration-safe login | Dummy Argon2id hash computed for non-existent users |
| Refresh token reuse → full session revocation | Revoked token replay triggers `RevokeAllByUserID` + audit log |
| Account lock after 5 failures | `IncrementFailedLogin` → `LockUntil` in service layer |
| OTP: hash-only, max 5 attempts, 10min expiry | Enforced in `OTPService.Validate` |
| No global mutable state | Config injected as parameter through all layers |
| Audit logs are append-only | No UPDATE/DELETE methods on `AuditRepository` |

## Quick Start

### Prerequisites

- Go 1.23+
- Docker & Docker Compose

### Run with Docker Compose

```bash
# Copy and configure environment variables
cp .env.example .env
# Edit .env: set JWT_SECRET to a strong random string

# Start all services (Postgres + MailHog + AuthCore)
docker compose up --build -d

# Check health
curl -s localhost:8080/healthz | jq
```

### Run Locally (development)

```bash
# Start only Postgres and MailHog
docker compose up postgres mailhog -d

# Set environment variables
export DATABASE_URL="postgres://authcore:authcore@localhost:5432/authcore?sslmode=disable"
export JWT_SECRET="change-me-to-a-long-random-string"
export SMTP_HOST=localhost
export SMTP_PORT=1025

# Build and run
make run
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PORT` | `8080` | HTTP listen port |
| `SERVER_READ_TIMEOUT` | `10s` | HTTP read timeout |
| `SERVER_WRITE_TIMEOUT` | `10s` | HTTP write timeout |
| `SERVER_SHUTDOWN_TIMEOUT` | `15s` | Graceful shutdown timeout |
| `DATABASE_URL` | — | **Required.** PostgreSQL connection string |
| `JWT_SECRET` | — | **Required.** HMAC signing key for JWTs |
| `JWT_ACCESS_EXPIRY` | `15m` | Access token lifetime |
| `JWT_REFRESH_EXPIRY` | `168h` | Refresh token lifetime (7 days) |
| `SMTP_HOST` | `localhost` | SMTP server host |
| `SMTP_PORT` | `1025` | SMTP server port |
| `SMTP_FROM` | `noreply@authcore.local` | Sender email address |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated CORS origins |
| `RATE_LIMIT_IP_REQUESTS` | `60` | Max requests per IP per window |
| `RATE_LIMIT_IP_WINDOW` | `1m` | IP rate limit sliding window |
| `RATE_LIMIT_ACCOUNT_REQUESTS` | `10` | Max requests per account per window |
| `RATE_LIMIT_ACCOUNT_WINDOW` | `1m` | Account rate limit sliding window |

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/healthz` | Public | Health check with DB ping |
| `POST` | `/api/v1/auth/register` | Public | Register with email + password |
| `POST` | `/api/v1/auth/verify-email` | Public | Verify email with OTP code |
| `POST` | `/api/v1/auth/login` | Public | Login → access token + refresh cookie |
| `POST` | `/api/v1/auth/refresh` | Cookie | Rotate refresh token |
| `POST` | `/api/v1/auth/logout` | Bearer | Revoke current session |
| `POST` | `/api/v1/auth/logout-all` | Bearer | Revoke all sessions |
| `POST` | `/api/v1/auth/forgot-password` | Public | Request password reset (always 202) |
| `POST` | `/api/v1/auth/reset-password` | Public | Reset password with OTP |
| `GET` | `/api/v1/auth/me` | Bearer | Get authenticated user profile |
| `GET` | `/api/v1/admin/audit-logs` | Admin | Paginated audit log listing |

## Demo Flow (curl)

```bash
BASE=http://localhost:8080/api/v1

# 1. Register
curl -s -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@example.com","password":"supersecure1"}' | jq

# 2. Get verification code from MailHog
OTP=$(curl -s http://localhost:8025/api/v2/messages | jq -r '.items[0].Content.Body' | grep -oP '\d{6}')
echo "OTP: $OTP"

# 3. Verify email
curl -s -X POST "$BASE/auth/verify-email" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"demo@example.com\",\"code\":\"$OTP\"}" | jq

# 4. Login (save cookies)
curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@example.com","password":"supersecure1"}' \
  -c cookies.txt | jq
ACCESS_TOKEN=$(curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@example.com","password":"supersecure1"}' \
  -c cookies.txt | jq -r '.access_token')

# 5. Get profile
curl -s "$BASE/auth/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq

# 6. Refresh token
curl -s -X POST "$BASE/auth/refresh" \
  -b cookies.txt -c cookies.txt | jq

# 7. Logout
curl -s -X POST "$BASE/auth/logout" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -b cookies.txt | jq
```

## Testing

```bash
# Unit tests with race detection and coverage
make test

# Or directly
go test ./... -race -cover

# Generate HTML coverage report
make coverage-html
open coverage.html
```

## Project Structure

```
AuthCore/
├── cmd/authcore/main.go          # Application entrypoint
├── internal/
│   ├── config/                   # Environment-based configuration
│   ├── database/                 # PostgreSQL connection + migrations
│   ├── domain/                   # Business entities + typed errors
│   ├── repository/               # Data access interfaces + pgx implementations
│   ├── service/                  # Business logic (auth, token, otp, audit)
│   ├── handler/                  # HTTP handlers + DTOs + router
│   ├── middleware/               # Auth, rate limiting, logging, validation
│   ├── httperr/                  # Centralized error-to-JSON mapping
│   └── mailer/                   # Email sending interface + SMTP implementation
├── migrations/                   # SQL migration files (golang-migrate)
├── docs/                         # Architecture, decisions, API reference
├── Dockerfile                    # Multi-stage build
├── docker-compose.yml            # Dev stack (Postgres + MailHog + app)
└── Makefile                      # Build, test, lint, docker commands
```

## Roadmap

- [ ] Redis-backed rate limiter implementation
- [ ] OAuth2 provider integration (Google, GitHub)
- [ ] TOTP-based two-factor authentication
- [ ] Password history (prevent reuse of last N passwords)
- [ ] Session management UI
- [ ] Webhook notifications for security events
- [ ] OpenTelemetry tracing

## License

MIT

---

> **Note:** This project is for learning and portfolio purposes. Replace `<REPO_URL>` with
> your actual repository URL after pushing. The `<LIVE_DEMO_URL>` placeholder is for a
> future deployment.
