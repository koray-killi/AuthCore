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

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /bin/authcore /usr/local/bin/authcore
COPY migrations/ /app/migrations/

WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["authcore"]
