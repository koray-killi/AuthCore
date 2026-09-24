# ---- Build Stage ----
FROM golang:alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/authcore ./cmd/authcore

# ---- Runtime Stage ----
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -u 1001 authcore

COPY --from=builder /bin/authcore /usr/local/bin/authcore

# Create /app and transfer ownership before switching to non-root user.
RUN mkdir -p /app && chown authcore:authcore /app
COPY --from=builder /src/migrations/ /app/migrations/

WORKDIR /app

# Run as non-root — principle: security is a day-one concern, not a deployment afterthought.
USER authcore

EXPOSE 8080

ENTRYPOINT ["authcore"]
