# Architecture

## Overview

AuthCore follows a strict **Handler → Service → Repository → PostgreSQL** layered architecture.
Each layer has a single, well-defined responsibility and communicates through interfaces.

## Layer Responsibilities

### Handler Layer (`internal/handler/`)
- HTTP request parsing and response formatting
- Input validation (empty fields, format checks)
- Maps domain models to response DTOs (never exposes internal fields)
- Delegates all business logic to the Service layer
- Sets HTTP cookies for refresh tokens
- **Never**: writes SQL, accesses repositories, makes business decisions

### Service Layer (`internal/service/`)
- Contains all business logic and security rules
- Orchestrates between multiple repositories
- Manages authentication flows (registration, login, token rotation)
- Enforces security policies (account lock, enumeration safety, reuse detection)
- Returns domain errors (never HTTP status codes)
- **Never**: formats HTTP responses, accesses `http.Request/Response`

### Repository Layer (`internal/repository/`)
- Pure data access with hand-written SQL via `pgx/v5`
- Each repository is defined as an interface (testable, swappable)
- Translates between domain structs and database rows
- **Never**: contains business logic, makes authorization decisions

### Domain Layer (`internal/domain/`)
- Core business entities (`User`, `RefreshSession`, `OTPCode`, `AuditLog`)
- Typed error definitions with HTTP status mappings
- Constants for audit actions, OTP purposes, limits

## Security Architecture

```
                ┌──────────────┐
                │   Client     │
                └──────┬───────┘
                       │
              ┌────────▼────────┐
              │  Rate Limiter   │ ← IP-based + Account-based
              │  (per-IP/acct)  │   sliding window
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │  JWT Middleware  │ ← Validates access tokens
              │  (Bearer auth)  │   Sets userID in context
              └────────┬────────┘
                       │
         ┌─────────────┼─────────────┐
         │             │             │
   ┌─────▼─────┐ ┌────▼────┐ ┌─────▼─────┐
   │  Argon2id  │ │ SHA-256 │ │  Argon2id │
   │  Password  │ │ Refresh │ │   OTP     │
   │  Hashing   │ │ Token   │ │  Hashing  │
   │            │ │ Hashing │ │           │
   └───────────┘ └─────────┘ └───────────┘
```

### Key Security Measures

1. **Enumeration Safety**: Login with non-existent email still runs Argon2id comparison against a dummy hash
2. **Refresh Token Rotation**: Old token revoked, new token issued, linked via `replaced_by`
3. **Reuse Detection**: Replaying a revoked refresh token revokes ALL user sessions
4. **Account Lockout**: 5 failed attempts → 15-minute lock
5. **OTP Security**: 6-digit, Argon2id hashed, max 5 attempts, 10-minute expiry, single-use
6. **No Raw Secrets Stored**: Passwords → Argon2id, refresh tokens → SHA-256, OTPs → Argon2id

## Data Flow: Login

```
Client                Handler              Service              Repository         PostgreSQL
  │                      │                     │                     │                  │
  │ POST /auth/login     │                     │                     │                  │
  │─────────────────────>│                     │                     │                  │
  │                      │ Login(email,pwd)     │                     │                  │
  │                      │────────────────────>│                     │                  │
  │                      │                     │ GetByEmail(email)   │                  │
  │                      │                     │───────────────────>│                  │
  │                      │                     │                     │ SELECT FROM users │
  │                      │                     │                     │─────────────────>│
  │                      │                     │                     │<─────────────────│
  │                      │                     │<───────────────────│                  │
  │                      │                     │                     │                  │
  │                      │                     │ Argon2id.Verify()   │                  │
  │                      │                     │ (constant-time)     │                  │
  │                      │                     │                     │                  │
  │                      │                     │ IssueTokenPair()    │                  │
  │                      │                     │───────────────────>│                  │
  │                      │                     │                     │ INSERT session   │
  │                      │                     │                     │─────────────────>│
  │                      │                     │<───────────────────│                  │
  │                      │                     │                     │                  │
  │                      │                     │ AuditLog("login")   │                  │
  │                      │                     │───────────────────>│                  │
  │                      │<────────────────────│                     │                  │
  │                      │                     │                     │                  │
  │  TokenResponse +     │                     │                     │                  │
  │  refresh_token cookie│                     │                     │                  │
  │<─────────────────────│                     │                     │                  │
```
