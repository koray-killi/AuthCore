# Architectural Decision Records

## ADR-001: UUID vs Serial for Primary Keys

**Decision:** Use UUID v4 (`gen_random_uuid()`) for all primary keys.

**Alternatives considered:**
- `BIGSERIAL` auto-increment — simpler, smaller, naturally ordered

**Rationale:**
- UUIDs are globally unique without coordination — essential for distributed systems and future multi-database scenarios
- Prevents information leakage: sequential IDs expose record count and creation rate
- Enables safe client-side ID generation if needed
- No enumeration attack surface through predictable IDs

**Trade-off:** Slightly larger storage (16 bytes vs 8 bytes), no natural ordering (mitigated by `created_at` timestamps and explicit indexes).

---

## ADR-002: Argon2id vs bcrypt for Password Hashing

**Decision:** Use Argon2id with configurable parameters (64MB memory, 3 iterations, 4 threads, 32-byte key).

**Alternatives considered:**
- bcrypt — well-established, widely supported
- scrypt — memory-hard but less tunable

**Rationale:**
- Argon2id is the winner of the Password Hashing Competition (2015) and recommended by OWASP
- Hybrid approach: resistant to both side-channel attacks (Argon2i) and GPU attacks (Argon2d)
- Configurable memory, time, and parallelism parameters allow tuning for hardware
- Used for both passwords AND OTP codes (with lighter parameters for OTPs since they're short-lived)

**Trade-off:** Slightly more complex implementation than bcrypt. Requires explicit parameter management and custom encoding format.

---

## ADR-003: Refresh Token in httpOnly Cookie vs Response Body

**Decision:** Deliver refresh tokens as `httpOnly`, `Secure`, `SameSite=Strict` cookies. Access tokens are returned in the response body.

**Alternatives considered:**
- Both tokens in response body — client stores in localStorage
- Both tokens as cookies

**Rationale:**
- `httpOnly` cookies are inaccessible to JavaScript, eliminating XSS-based token theft
- `SameSite=Strict` prevents CSRF-based token submission
- `Secure` ensures transmission only over HTTPS
- Access tokens in body allow SPAs to include them in `Authorization` headers without cookie-based CSRF concerns
- Cookie scoped to `/api/v1/auth` path minimizes exposure surface

**Trade-off:** Requires cookie handling in the client, slightly more complex CORS configuration. Mobile apps need to handle cookies or use a token-in-body variant (future enhancement).

---

## ADR-004: ORM-less SQL with pgx/v5

**Decision:** Use `pgx/v5` with hand-written SQL queries. No ORM (GORM, ent, sqlc) used.

**Alternatives considered:**
- GORM — popular Go ORM, auto-migration support
- sqlc — generates type-safe Go from SQL
- ent — Facebook's entity framework for Go

**Rationale:**
- Full control over query optimization and database features (INET type, JSONB, partial indexes)
- Explicit SQL is easier to audit for security issues (SQL injection, N+1 queries)
- `pgx/v5` provides native PostgreSQL features (connection pooling, prepared statements, LISTEN/NOTIFY)
- Repository interfaces provide the same testability benefits as an ORM
- Avoids ORM-specific DSL learning curve and debugging overhead

**Trade-off:** More boilerplate for CRUD operations. Schema changes require manual migration writing. No automatic model-to-table mapping.

---

## ADR-005: Rate Limit Store Abstraction

**Decision:** Define a `RateLimiter` interface with an in-memory sliding window implementation. The interface is designed for future Redis swap.

**Alternatives considered:**
- Directly use Redis from the start
- No abstraction — inline rate limiting logic

**Rationale:**
- In-memory implementation is sufficient for single-instance deployment (this project's scope)
- Interface allows seamless Redis swap for multi-instance deployments without changing middleware code
- Sliding window algorithm provides smoother rate limiting than fixed window (no burst at window boundaries)
- Two-tier rate limiting (per-IP + per-account) addresses both DDoS and credential stuffing

**Trade-off:** In-memory store is lost on restart and doesn't work across multiple instances. Background cleanup goroutine adds minimal complexity. Redis implementation deferred to roadmap.

---

## ADR-006: Soft Delete (revoked_at) vs Hard Delete for Sessions

**Decision:** Use soft delete (`revoked_at` timestamp) for refresh sessions. Never hard-delete session records.

**Alternatives considered:**
- Hard DELETE on revocation — simpler, less storage
- Separate archive table for revoked sessions

**Rationale:**
- Soft delete enables **refresh token reuse detection**: when a revoked token is replayed, we can identify the original session and revoke all sessions for that user
- The `replaced_by` chain provides a complete audit trail of token rotations
- Enables forensic analysis of token usage patterns
- Consistent with the append-only audit log philosophy

**Trade-off:** Table grows over time. Mitigated by periodic cleanup of expired+revoked sessions (not implemented yet — roadmap item). Queries must filter on `revoked_at IS NULL` for active sessions.

---

## ADR-007: TIMESTAMPTZ for All Time Columns

**Decision:** Use `TIMESTAMPTZ` (timestamp with time zone) for every time column, never `TIMESTAMP`.

**Alternatives considered:**
- `TIMESTAMP` (without timezone) — stores local time, simpler for single-timezone apps

**Rationale:**
- `TIMESTAMPTZ` stores the absolute point in time, avoiding ambiguity across timezones
- PostgreSQL converts to UTC on storage and back to the session timezone on retrieval
- Prevents subtle bugs when the server's timezone changes or when comparing times from different sources
- Industry best practice for any application that may serve users across timezones

**Trade-off:** None significant. `TIMESTAMPTZ` is 8 bytes, same as `TIMESTAMP`. The only difference is awareness of timezone context.

---

## ADR-008: Centralized Error Model with Typed Domain Errors

**Decision:** Define all errors as typed `*AppError` constants in `internal/domain/errors.go`. A single `httperr.Write()` function maps domain errors to JSON responses.

**Alternatives considered:**
- Inline error construction in handlers — `http.Error(w, "...", 400)`
- Error middleware that wraps handlers and catches panics
- gRPC-style status codes

**Rationale:**
- Single source of truth for all error codes and messages — no scattered string literals
- `errors.As()` pattern allows service layer to return rich errors without importing `net/http`
- Unknown errors are automatically mapped to 500 with no detail leak (prevents information disclosure)
- Error codes are machine-readable (`INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`) — clients can programmatically handle them
- Consistent error envelope: `{"error": {"code": "...", "message": "..."}}`

**Trade-off:** Requires discipline to define new errors in the domain package instead of ad-hoc construction. Not suitable for errors that need dynamic messages (mitigated by wrapping with `fmt.Errorf`).

---

## ADR-009: Audit Log as Append-Only Table

**Decision:** The `audit_logs` table is strictly append-only. The `AuditRepository` interface exposes only `Insert` and `List` methods — no `Update` or `Delete`.

**Alternatives considered:**
- Mutable audit logs with soft delete — simpler cleanup
- External audit service (ELK stack, cloud logging)

**Rationale:**
- Immutable audit trail is a compliance requirement for most security-sensitive applications
- Append-only constraint is enforced at the application layer (no `UPDATE`/`DELETE` methods exist)
- JSONB `metadata` field provides flexible schema for different event types without table-per-event-type proliferation
- Indexes on `user_id`, `action`, and `created_at` support common query patterns

**Trade-off:** Table size grows unbounded. Production deployments should implement time-based partitioning or archival to cold storage (out of scope for this project).

---

## ADR-010: OTP Design — Hash-Only Storage with Attempt Limiting

**Decision:** OTP codes are 6-digit, cryptographically random, hashed with Argon2id before storage. The plain code is returned once to the service layer for email sending and never persisted.

**Alternatives considered:**
- Store OTP in plaintext — simpler to debug and verify
- Use JWT-based verification tokens (signed, self-contained)
- TOTP (time-based one-time passwords) — standard RFC 6238

**Rationale:**
- Hash-only storage means a database breach doesn't expose usable OTPs
- 6-digit codes are user-friendly for email/SMS copy-paste
- Attempt limit (5 attempts) prevents online brute-force (only 100,000 possible codes)
- 10-minute expiry limits the attack window
- Single-use (`consumed_at`) prevents replay attacks
- Argon2id with lighter parameters than passwords balances security and performance for short-lived codes

**Trade-off:** More complex than plaintext storage. TOTP would eliminate the need for email delivery but requires an authenticator app (out of scope — roadmap item).
