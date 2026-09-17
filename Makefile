.PHONY: build run test lint vet tidy clean docker-up docker-down migrate-up migrate-down

APP_NAME := authcore
BUILD_DIR := bin

build:
	@echo "==> Building $(APP_NAME)..."
	go build -o $(BUILD_DIR)/$(APP_NAME) ./cmd/authcore

run: build
	@echo "==> Running $(APP_NAME)..."
	./$(BUILD_DIR)/$(APP_NAME)

test:
	@echo "==> Running tests..."
	go test ./... -race -cover -coverprofile=coverage.out
	@go tool cover -func=coverage.out | tail -1

test-integration:
	@echo "==> Running integration tests..."
	go test ./internal/e2e/... -tags=integration -v

lint: vet
	@echo "==> Lint passed (go vet)"

vet:
	@echo "==> Running go vet..."
	go vet ./...

tidy:
	@echo "==> Tidying modules..."
	go mod tidy

clean:
	@echo "==> Cleaning..."
	rm -rf $(BUILD_DIR) coverage.out coverage.html

docker-up:
	@echo "==> Starting Docker services..."
	docker compose up --build -d

docker-down:
	@echo "==> Stopping Docker services..."
	docker compose down -v

docker-test-up:
	@echo "==> Starting test Docker services..."
	docker compose -f docker-compose.test.yml up --build -d

docker-test-down:
	@echo "==> Stopping test Docker services..."
	docker compose -f docker-compose.test.yml down -v

coverage-html: test
	@echo "==> Generating coverage report..."
	go tool cover -html=coverage.out -o coverage.html

check: tidy vet build test
	@echo "==> All checks passed!"
