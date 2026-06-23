# Multi-stage build for both Go binaries in this module.
# Pick which one with: --build-arg CMD=gateway   (or CMD=worker, scheduler)
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG CMD=gateway
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/app ./internal/${CMD}

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/app /app
# Runtime config is mounted from the repo root (see config.yaml.example).
# Viper loads /config/config.yaml at container start.
ENTRYPOINT ["/app"]
