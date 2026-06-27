# Build from repo root (docker-compose build.context: .).
# gateway/go.mod: replace github.com/thinkonmay/thinkshare-daemon => ../worker/daemon
FROM golang:1.26 AS build

WORKDIR /src

COPY worker/daemon/go.mod worker/daemon/go.sum ./worker/daemon/
COPY gateway/go.mod gateway/go.sum ./gateway/

WORKDIR /src/gateway
RUN go mod download

COPY worker/daemon /src/worker/daemon
COPY gateway /src/gateway

ARG CMD=gateway
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/app ./internal/${CMD}

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/app /app
# Runtime config is mounted from the repo root (see config.yaml.example).
# Viper loads /config/config.yaml at container start.
ENTRYPOINT ["/app"]
