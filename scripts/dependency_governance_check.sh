#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STRICT_OUTDATED="${STRICT_OUTDATED:-0}"

if [[ -d "${HOME}/.cargo/bin" ]]; then
  export PATH="${HOME}/.cargo/bin:${PATH}"
fi

SCHED_PREFIX=()
if command -v ionice >/dev/null 2>&1; then
  SCHED_PREFIX+=(ionice -c3)
fi
if command -v nice >/dev/null 2>&1; then
  SCHED_PREFIX+=(nice -n 19)
fi

run_cmd() {
  if [[ ${#SCHED_PREFIX[@]} -gt 0 ]]; then
    "${SCHED_PREFIX[@]}" "$@"
  else
    "$@"
  fi
}

cd "${ROOT_DIR}"

for cmd in cargo cargo-deny cargo-audit cargo-outdated; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}" >&2
    exit 2
  fi
done

echo "[1/3] cargo deny (advisories + licenses + bans + sources)"
run_cmd cargo deny check advisories licenses bans sources

echo "[2/3] cargo audit (RustSec)"
run_cmd cargo audit --deny warnings

echo "[3/3] cargo outdated (direct dependency stale-risk)"
if [[ "${STRICT_OUTDATED}" == "1" ]]; then
  run_cmd cargo outdated --root-deps-only --depth 1 --exit-code 1
else
  run_cmd cargo outdated --root-deps-only --depth 1     || echo "cargo outdated report unavailable; continuing because STRICT_OUTDATED=0" >&2
fi

echo "dependency governance checks passed"
