#!/usr/bin/env bash
# Local CI for gateway — same steps as .github/workflows/ci.yml
#
# Usage:
#   ./ci/local.sh              # default: mod + unit tests + build
#   ./ci/local.sh test         # unit tests only
#   ./ci/local.sh vet          # go vet
#   ./ci/local.sh build        # compile gateway/worker/relay
#   ./ci/local.sh all          # tests + vet + build + test-file gate
#
# Options (env):
#   SKIP_BUILD=1               skip compile steps
#   WITH_NATS_CONFORMANCE=1    run pkg/bus conformance (needs Docker)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

# shellcheck source=ci/lib.sh
source "${ROOT}/ci/lib.sh"

STAGE="${1:-default}"

step_mod() {
  ci_log "go mod download"
  go mod download
}

step_assert_tests() {
  ci_log "verify every module has *_test.go"
  ci_assert_test_files "${ROOT}"
}

step_unit_tests() {
  ci_log "unit tests"
  local list_file
  list_file="$(mktemp)"
  trap "rm -f '${list_file}'" RETURN
  ci_gateway_test_packages > "${list_file}"
  ci_run_go_test_packages "${list_file}"
}

step_nats_conformance() {
  if [[ "${WITH_NATS_CONFORMANCE:-0}" != "1" ]]; then
    ci_log "skip NATS conformance (set WITH_NATS_CONFORMANCE=1; requires Docker)"
    return 0
  fi
  ci_log "NATS bus conformance (Docker)"
  go test ./pkg/bus -count=1 -timeout=20m -run Conformance
}

step_vet() {
  ci_log "go vet"
  go vet ./config/... ./internal/... ./pkg/... ./shared/...
}

step_build() {
  if [[ "${SKIP_BUILD:-0}" == "1" ]]; then
    ci_log "skip build (SKIP_BUILD=1)"
    return 0
  fi
  ci_log "build gateway"
  go build -trimpath -o "${ROOT}/artifacts/local/gateway" ./internal/gateway
  ci_log "build worker"
  go build -trimpath -o "${ROOT}/artifacts/local/worker" ./internal/worker
  ci_log "build relay"
  go build -trimpath -o "${ROOT}/artifacts/local/relay" ./internal/relay
}

run_default() {
  step_mod
  step_assert_tests
  step_unit_tests
  mkdir -p "${ROOT}/artifacts/local"
  step_build
}

run_all() {
  run_default
  step_nats_conformance
  step_vet
}

case "${STAGE}" in
  default|"") run_default ;;
  all)        run_all ;;
  mod)        step_mod ;;
  test)       step_mod; step_assert_tests; step_unit_tests ;;
  vet)        step_mod; step_vet ;;
  build)      step_mod; mkdir -p "${ROOT}/artifacts/local"; step_build ;;
  *)
    echo "unknown stage: ${STAGE}" >&2
    echo "usage: $0 [default|all|mod|test|vet|build]" >&2
    exit 2
    ;;
esac

ci_log "local CI finished OK ($(ci_os)/$(ci_arch))"
