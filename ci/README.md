# Gateway CI

Run from the `gateway/` directory (Go module root):

```bash
chmod +x ./ci/local.sh
./ci/local.sh all
```

## Stages

| Stage | Command | What it runs |
|-------|---------|--------------|
| Default | `./ci/local.sh` | `go mod download`, test-file gate, unit tests, build three binaries |
| Full | `./ci/local.sh all` | Default + `go vet` + optional NATS conformance |
| Tests only | `./ci/local.sh test` | Unit tests + test-file gate |
| Vet | `./ci/local.sh vet` | `go vet` on config, internal, pkg, shared |
| Build | `./ci/local.sh build` | `gateway`, `worker`, `relay` binaries under `artifacts/local/` |

## NATS conformance (optional)

Bus conformance tests spin up NATS via testcontainers and need Docker:

```bash
WITH_NATS_CONFORMANCE=1 ./ci/local.sh all
```

Without Docker, memory-bus tests still run; NATS backend is skipped inside `pkg/bus/conformance_test.go`.

## Monorepo

The thinkmay root workflow [`.github/workflows/gateway.yml`](../../.github/workflows/gateway.yml) initializes the `gateway` submodule and runs `./ci/local.sh all` on pushes that touch `gateway/**`.
