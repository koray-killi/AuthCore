CREATE TABLE otp_codes (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose       TEXT NOT NULL CHECK (purpose IN ('verify_email', 'reset_password')),
    code_hash     TEXT NOT NULL,
    attempt_count INT NOT NULL DEFAULT 0,
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_otp_codes_user_id_purpose ON otp_codes (user_id, purpose);
