#!/usr/bin/env bash
# Shared helpers for gateway local CI (sourced, not executed directly).
set -euo pipefail

ci_log() {
  printf '\n==> %s\n' "$*"
}

ci_os() {
  uname -s
}

ci_arch() {
  uname -m
}

# Go packages that must have unit tests (excludes cmd-only mains without logic).
ci_gateway_test_packages() {
  cat <<'EOF'
./config
./internal/gateway
./internal/gateway/handler
./internal/outbox
./internal/worker/handler
./pkg/bus
./pkg/bus/memory
./pkg/bus/nats
./pkg/cache
./pkg/cache/memory
./pkg/guard
./pkg/idempotency
./pkg/memo
./pkg/postgrest
./pkg/rpc
./pkg/validator
./shared/model
EOF
}

ci_run_go_test_packages() {
  local list_file="$1"
  shift
  local -a pkgs=()
  while IFS= read -r pkg; do
    [[ -z "${pkg}" ]] && continue
    pkgs+=("${pkg}")
  done < "${list_file}"
  go test "${pkgs[@]}" -count=1 -timeout=15m "$@"
}

# Fail if any registered package lacks a *_test.go file.
ci_assert_test_files() {
  local root="$1"
  local missing=0
  while IFS= read -r pkg; do
    [[ -z "${pkg}" ]] && continue
    local dir="${pkg#./}"
    if ! compgen -G "${root}/${dir}/*_test.go" > /dev/null; then
      echo "missing unit tests: ${pkg}" >&2
      missing=1
    fi
  done < <(ci_gateway_test_packages)
  return "${missing}"
}
