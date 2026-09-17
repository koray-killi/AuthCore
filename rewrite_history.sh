#!/bin/bash
set -e

rm -rf .git
git init
git checkout -b main

# 1. chore: init go module, Makefile, Dockerfile, docker-compose
git add go.mod go.sum Makefile Dockerfile docker-compose.yml docker-compose.test.yml .gitignore .dockerignore .env.example .github/workflows/ci.yml
git commit -m "chore: init go module, Makefile, Dockerfile, docker-compose"

# 2. feat: config loader and postgres connection pool
git add internal/config/ internal/database/
git commit -m "feat: config loader and postgres connection pool"

# 3. feat: sql migrations for users, sessions, otp_codes, audit_logs
git add migrations/
git commit -m "feat: sql migrations for users, sessions, otp_codes, audit_logs"

# 4. feat: domain models and typed error constants
git add internal/domain/
git commit -m "feat: domain models and typed error constants"

# 5. feat: httperr package
git add internal/httperr/
git commit -m "feat: httperr package for centralized error responses"

# 6. feat: repository layer
git add internal/repository/
git commit -m "feat: repository layer — user, session, otp, audit"

# 7. feat: smtp mailer interface
git add internal/mailer/
git commit -m "feat: smtp mailer interface"

# 8. feat: audit service fire-and-forget logging
git add internal/service/audit_service.go
git commit -m "feat: audit service fire-and-forget logging"

# 9. feat: token service and session logic
git add internal/service/token_service.go
git commit -m "feat: token service and session rotation logic"

# 10. feat: otp service and hashing
git add internal/service/otp_service.go
git commit -m "feat: otp service and secure hashing"

# 11. feat: auth service core business logic
git add internal/service/auth_service.go internal/service/fakes.go
git commit -m "feat: auth service core business logic"

# 12. feat: jwt auth middleware and two-tier rate limiter
git add internal/middleware/
git commit -m "feat: jwt auth middleware and two-tier rate limiter"

# 13. feat: chi router, auth handlers, security headers
git add internal/handler/
git commit -m "feat: chi router, auth handlers, security headers"

# 14. feat: app entrypoint
git add cmd/
git commit -m "feat: application entrypoint and dependency wiring"

# 15. test: unit tests for service layer
git add internal/service/*_test.go
git commit -m "test: unit tests for auth, token, otp services"

# 16. test: integration e2e flow against real postgres
git add internal/e2e/
git commit -m "test: integration e2e flow against real postgres"

# 17. docs: readme, architecture, adrs, api reference
git add README.md docs/
git commit -m "docs: readme, architecture, 10 adrs, api reference"

# Catchall
git add -A
git commit -m "chore: final cleanup and formatting" || true

