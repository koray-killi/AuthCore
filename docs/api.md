# API Reference

Base URL: `http://localhost:8080`

All API endpoints are prefixed with `/api/v1` unless otherwise noted.

## Authentication

Protected endpoints require a valid JWT access token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

Admin endpoints additionally require the authenticated user to have the `admin` role.

---

## Error Response Format

All errors follow a consistent envelope:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable description."
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_CREDENTIALS` | 401 | Wrong email or password |
| `ACCOUNT_LOCKED` | 403 | Account temporarily locked (too many failed logins) |
| `EMAIL_NOT_VERIFIED` | 403 | Email verification required before login |
| `EMAIL_ALREADY_EXISTS` | 409 | Registration with existing email |
| `USER_NOT_FOUND` | 404 | User does not exist |
| `WEAK_PASSWORD` | 400 | Password does not meet minimum requirements |
| `TOKEN_EXPIRED` | 401 | Access or refresh token has expired |
| `TOKEN_INVALID` | 401 | Token is malformed or has invalid signature |
| `TOKEN_REVOKED` | 401 | Token has been revoked (possible reuse attack) |
| `OTP_EXPIRED` | 400 | Verification code has expired (>10 minutes) |
| `OTP_INVALID` | 400 | Wrong verification code |
| `OTP_MAX_ATTEMPTS` | 429 | Maximum OTP verification attempts exceeded |
| `RATE_LIMITED` | 429 | Too many requests (includes `Retry-After` header) |
| `UNAUTHORIZED` | 401 | Missing or invalid authentication |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `BAD_REQUEST` | 400 | Invalid or missing request body fields |
| `INTERNAL_ERROR` | 500 | Unexpected server error (no details exposed) |

---

## Endpoints

### GET /healthz

Health check endpoint. Excluded from rate limiting.

**Request:**
```
GET /healthz
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "db": "ok"
}
```

**Response (503 Service Unavailable):**
```json
{
  "status": "degraded",
  "db": "unavailable"
}
```

---

### POST /api/v1/auth/register

Create a new user account. Sends a verification OTP to the provided email.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "securepassword1"
}
```

**Response (201 Created):**
```json
{
  "message": "Registration successful. Please check your email for the verification code."
}
```

**Errors:** `WEAK_PASSWORD` (400), `EMAIL_ALREADY_EXISTS` (409), `BAD_REQUEST` (400)

---

### POST /api/v1/auth/verify-email

Verify email address using the OTP code sent during registration.

**Request:**
```json
{
  "email": "user@example.com",
  "code": "123456"
}
```

**Response (200 OK):**
```json
{
  "message": "Email verified successfully."
}
```

**Errors:** `OTP_INVALID` (400), `OTP_EXPIRED` (400), `OTP_MAX_ATTEMPTS` (429)

---

### POST /api/v1/auth/resend-verification

Request a new email verification OTP. Always returns 202 regardless of whether the email exists or is already active (enumeration safety).

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response (202 Accepted):**
```json
{
  "message": "If your account is pending verification, a new code has been sent."
}
```

---

### POST /api/v1/auth/login

Authenticate with email and password. Returns an access token in the body and sets a refresh token as an httpOnly cookie.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "securepassword1"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Headers set:**
```
Set-Cookie: refresh_token=<token>; Path=/api/v1/auth; HttpOnly; Secure; SameSite=Strict
```

**Errors:** `INVALID_CREDENTIALS` (401), `ACCOUNT_LOCKED` (403), `EMAIL_NOT_VERIFIED` (403)

**Security notes:**
- Non-existent user: performs dummy Argon2id hash for constant timing
- 5 failed attempts: account locked for 15 minutes
- Locked account: still performs hash comparison to prevent timing leak

---

### POST /api/v1/auth/refresh

Rotate the refresh token. Requires the `refresh_token` cookie.

**Request:**
```
POST /api/v1/auth/refresh
Cookie: refresh_token=<current_token>
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Headers set:**
```
Set-Cookie: refresh_token=<new_token>; Path=/api/v1/auth; HttpOnly; Secure; SameSite=Strict
```

**Errors:** `TOKEN_INVALID` (401), `TOKEN_EXPIRED` (401), `TOKEN_REVOKED` (401)

**Security notes:**
- Old refresh token is immediately revoked and linked to the new session via `replaced_by`
- If a revoked token is reused, ALL user sessions are revoked (reuse detection)
- An `audit_log` entry with action `refresh_reuse_detected` is created

---

### POST /api/v1/auth/logout

**Auth:** Bearer token required.

Revoke the current refresh session.

**Request:**
```
POST /api/v1/auth/logout
Authorization: Bearer <access_token>
Cookie: refresh_token=<token>
```

**Response (200 OK):**
```json
{
  "message": "Logged out."
}
```

---

### POST /api/v1/auth/logout-all

**Auth:** Bearer token required.

Revoke all refresh sessions for the authenticated user.

**Request:**
```
POST /api/v1/auth/logout-all
Authorization: Bearer <access_token>
```

**Response (200 OK):**
```json
{
  "message": "All sessions revoked."
}
```

---

### POST /api/v1/auth/forgot-password

Request a password reset OTP. **Always returns 202 regardless of whether the email exists** (enumeration safety).

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response (202 Accepted):**
```json
{
  "message": "If an account with that email exists, a password reset code has been sent."
}
```

---

### POST /api/v1/auth/reset-password

Reset password using the OTP code. Revokes all existing sessions.

**Request:**
```json
{
  "email": "user@example.com",
  "code": "123456",
  "new_password": "mynewsecurepassword"
}
```

**Response (200 OK):**
```json
{
  "message": "Password has been reset successfully. Please log in with your new password."
}
```

**Errors:** `OTP_INVALID` (400), `OTP_EXPIRED` (400), `OTP_MAX_ATTEMPTS` (429), `WEAK_PASSWORD` (400)

---

### GET /api/v1/auth/me

**Auth:** Bearer token required.

Returns the authenticated user's profile. **Never includes password_hash or other sensitive fields.**

**Request:**
```
GET /api/v1/auth/me
Authorization: Bearer <access_token>
```

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "role": "user",
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

**Errors:** `UNAUTHORIZED` (401)

---

### GET /api/v1/admin/audit-logs

**Auth:** Bearer token + admin role required.

Returns a paginated list of all audit log entries.

**Request:**
```
GET /api/v1/admin/audit-logs?page=1&page_size=20
Authorization: Bearer <admin_access_token>
```

**Response (200 OK):**
```json
{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "user_id": "660e8400-e29b-41d4-a716-446655440000",
      "action": "login",
      "ip": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "metadata": {},
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 150,
  "page": 1,
  "page_size": 20,
  "total_pages": 8
}
```

**Query Parameters:**
- `page` (int, default: 1) — Page number
- `page_size` (int, default: 20, max: 100) — Items per page

**Errors:** `UNAUTHORIZED` (401), `FORBIDDEN` (403)

**Audit Actions:**

| Action | Description |
|--------|-------------|
| `register` | New user registration |
| `login` | Successful login |
| `login_failed` | Failed login attempt |
| `logout` | User logged out |
| `logout_all` | All sessions revoked |
| `refresh_token` | Refresh token rotated |
| `refresh_reuse_detected` | Revoked refresh token replayed |
| `verify_email` | Email verified via OTP |
| `forgot_password` | Password reset requested |
| `reset_password` | Password successfully reset |
| `account_locked` | Account locked after failed attempts |
