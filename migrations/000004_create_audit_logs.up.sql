CREATE TABLE audit_logs (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    action     TEXT NOT NULL,
    ip         INET NOT NULL DEFAULT '0.0.0.0',
    user_agent TEXT NOT NULL DEFAULT '',
    metadata   JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Append-only by convention: application code never issues UPDATE or DELETE on this table.
CREATE INDEX idx_audit_logs_user_id ON audit_logs (user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs (action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at);
