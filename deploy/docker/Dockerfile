# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /pentestswarm ./cmd/pentestswarm/

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /pentestswarm /usr/local/bin/pentestswarm

EXPOSE 8080

ENTRYPOINT ["pentestswarm"]
CMD ["serve"]
