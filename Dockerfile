# ---- Build Stage ----
FROM golang:1.24.6-alpine AS builder

WORKDIR /app

# Install build deps (git for go mod)
RUN apk add --no-cache git

# Cache go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build binary
RUN go build -o globalproxy .

# ---- Runtime Stage ----
FROM alpine:3.20

WORKDIR /app

# Copy binary only
COPY --from=builder /app/globalproxy .

# Create autocert cache dir
RUN mkdir -p /app/pb_data/.autocert_cache

# Expose ports
EXPOSE 8445 50050

ENTRYPOINT ["./globalproxy"]