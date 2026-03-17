.PHONY: build dev test test-integration lint fmt generate docs clean help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS  = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

## build: Compile binary to ./bin/pentestswarm
build:
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/pentestswarm ./cmd/pentestswarm/

## dev: Start full local development stack
dev: build
	@echo "Starting development environment..."
	docker compose -f deploy/docker-compose.dev.yml up -d
	@echo "Running pentestswarm..."
	./bin/pentestswarm

## test: Run unit tests with race detector
test:
	go test -race -count=1 ./...

## test-integration: Run integration tests (requires running services)
test-integration:
	go test -race -count=1 -tags=integration ./tests/integration/...

## test-e2e: Run end-to-end tests
test-e2e:
	go test -race -count=1 -tags=e2e ./tests/e2e/...

## test-coverage: Run tests with coverage report
test-coverage:
	go test -race -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## fmt: Format code with gofmt and goimports
fmt:
	gofmt -s -w .
	goimports -w -local github.com/Armur-Ai/Pentest-Swarm-AI .

## generate: Run code generation (sqlc, etc.)
generate:
	@echo "Running code generation..."
	@command -v sqlc >/dev/null 2>&1 && sqlc generate || echo "sqlc not installed, skipping"

## docs: Generate API documentation
docs:
	@echo "Generating API docs..."
	@command -v swag >/dev/null 2>&1 && swag init -g internal/api/server.go -o docs/swagger || echo "swag not installed, skipping"

## clean: Remove build artifacts
clean:
	rm -rf bin/ coverage.txt coverage.html dist/

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':' | sed 's/^/  /'
