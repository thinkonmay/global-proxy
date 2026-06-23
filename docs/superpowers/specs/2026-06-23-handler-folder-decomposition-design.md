# Handler folder decomposition — design

**Date:** 2026-06-23
**Repo:** global-proxy (gateway)
**Goal:** Stop `internal/gateway/handler/` and `internal/worker/handler/` from bloating. Reorganize into one folder per domain plus a thin shared foundation. Pure structural reorg — no behavior change, no new abstraction layer.

## Background

- **Gateway** `internal/gateway/handler/` is a flat package with one `XxxHandler` struct per domain (good bones) but fat files: `billing.go` 683 LOC, `catalog.go` 584, `pwa.go` 457. Cross-cutting helpers (`writeJSON`, `requireUser`, error writers, cluster-URL resolvers) live scattered across `handler.go`, `auth.go`, `pwa_auth.go`, `node_proxy.go` and are shared package-wide.
- **Worker** `internal/worker/handler/` has one God `Handler` struct that subscribes to 3 topics (volume job, usage batch, payment event) and carries inline closures (`settleRPC`, `listPending`, `saveCard`). Domains (volume/payment/usage/grant/persona) are entangled in one struct.

**Rejected alternative — repository layer (`shared/repo`):** considered and dropped. Complex logic already lives in Postgres RPC/db functions; handler data access is a thin `pr.RPC` / `pb.CreateRecord` call. A repo layer would add indirection with no payoff.

## Target structure

### Gateway — `internal/gateway/handler/`

```
handler/
  httpx/        foundation — response/request/header helpers (exported)
  auth/         requireUser, ConfigureAuth, issuerFromRequest, cluster URL resolve
  billing/      billing.go split by feature -> checkout.go / methods.go / refund.go / ...
  catalog/      catalog.go split + store.go (preorder)
  pwa/          pwa.go + pwa_auth.go + pwa_search.go
  gamification/ gamification.go + mission_usage.go
  persona/      persona.go
  files/        files.go
  node/         node_proxy.go + node_runtime.go
  ota/          ota.go
  grant/        grant.go
  payment/      payment_webhook.go
  handler.go    root — thin Handler (health/jobs) only
```

**`httpx` (exported foundation):** `WriteJSON`, `ReadJSONBody`, `ContextWithTimeout`, `WriteAuthErr`, `WritePostgrestErr`, `CopyHeader`. Imported by every domain. Imports no domain package (one-way dependency, no cycles).

**`auth` foundation:** `RequireUser`, `ConfigureAuth`, `IssuerFromRequest`, `ResolveClusterURL`, `ClusterBaseURL`, `ClusterHost`. May depend on `httpx`. Holds the existing package-global auth/issuer-registry state — single owner.

**Domain-specific error writers** (`writeBillingErr`, `writeGamificationErr`, `writeNodeRuntimeErr`) move into their own domain package and may stay unexported there.

### Worker — `internal/worker/handler/`

```
handler/
  volume/       volume.go + volumeHandler (already self-contained)
  payment/      payment.go + payment_poll.go (settleRPC/listPending/saveCard become methods)
  usage/        usage.go + usage_collector.go
  grant/        grant_jobs.go
  persona/      persona_worker.go
  handler.go    root — composes sub-handlers, calls each .Init()
```

Each domain package exposes a constructor (`New(...)`) and an `Init()` that registers its own `bus.Subscribe` / `bus.SubscribeBatch`. Root `handler.go` keeps a thin composite that builds each sub-handler and fans `Init()` out. Inline closures on the God struct (`settleRPC`, `listPending`, `saveCard`) become methods on the `payment` package.

## Data flow / dependencies

- Dependency direction is strictly one-way: domain packages → `httpx`/`auth` (gateway) and domain packages → `pkg/*` (worker). Foundation packages never import domains. No import cycles.
- `main.go` wiring (`newMux`, worker `New`/`Init`) changes only import paths and constructor call sites; the runtime route table and subscription set are identical.

## Testing

- Each `*_test.go` moves with its domain into the new package.
- Shared test helpers (`testUserJWT`, `testIssuerRegistry`, `testPWAConfig`) move to a small `internal/gateway/handler/testutil` (or per-package copies if a helper is single-use).
- Acceptance: `go build ./...` and `go test ./...` green before and after; route list and bus subscription set unchanged (diff the registration sites).
- Per testing policy: no new logic, so no new test cases required — existing tests must keep passing in their new packages.

## Risks

- Import-path churn across `main.go` and moved test files (mechanical).
- Helper rename on export (`writeJSON` -> `httpx.WriteJSON`) touches every call site — do per-helper with a global replace.
- Hidden package-global coupling in `auth` (issuer registry, `ConfigureAuth` side effects) — keep all of it in one `auth` package so init order is preserved.

## Out of scope

- No repository/data-access abstraction.
- No change to `pkg/*`, `shared/model`, routing semantics, or bus topics.
- Non-handler bloat (e.g. `pkg/pocketbase/pocketbase.go` 492) untouched.
