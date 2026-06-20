#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/generate-release-provenance.sh --binary <path> [--output <path>]

Generates a secret-free JSON manifest tying a cloudflare-mcp binary to the
source checkout, registered tool inventory, schema snapshot, API catalog, and
pinned mcp-toolkit-rs revision.
USAGE
}

binary_path=""
output_path=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      binary_path="${2:-}"
      shift 2
      ;;
    --output)
      output_path="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$binary_path" ]]; then
  echo "--binary is required" >&2
  usage >&2
  exit 2
fi

if [[ ! -x "$binary_path" ]]; then
  echo "binary is not executable: $binary_path" >&2
  exit 1
fi

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required command not found: $1" >&2
    exit 1
  fi
}

need git
need jq
need sha256sum

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

source_sha="$(git rev-parse HEAD)"
source_dirty="$(if git diff --quiet --ignore-submodules -- && git diff --cached --quiet --ignore-submodules --; then echo false; else echo true; fi)"
binary_realpath="$(realpath "$binary_path")"
binary_sha256="$(sha256sum "$binary_realpath" | awk '{print $1}')"
binary_size_bytes="$(wc -c < "$binary_realpath" | tr -d ' ')"

tool_inventory_json="$(mktemp)"
normalized_tool_inventory_json="$(mktemp)"
trap 'rm -f "$tool_inventory_json" "$normalized_tool_inventory_json"' EXIT

CLOUDFLARE_MCP_AUTH_MODE=off "$binary_realpath" --print-tools > "$tool_inventory_json"
jq -e 'type == "array" and all(.[]; type == "string")' "$tool_inventory_json" >/dev/null
jq -cS 'sort' "$tool_inventory_json" > "$normalized_tool_inventory_json"
tool_count="$(jq 'length' "$normalized_tool_inventory_json")"
tool_inventory_sha256="$(sha256sum "$normalized_tool_inventory_json" | awk '{print $1}')"

schema_snapshot_sha256="$(sha256sum spec/tool_schema_snapshot.v1.json | awk '{print $1}')"
api_catalog_sha256="$(sha256sum spec/cloudflare_api_catalog.v1.json | awk '{print $1}')"
toolkit_revision="$(
  grep -E -m 1 'rev = "[0-9a-f]+"' Cargo.toml |
    sed -E 's/.*"([0-9a-f]+)".*/\1/'
)"

if [[ -z "$toolkit_revision" ]]; then
  echo "failed to extract mcp-toolkit-rs revision from Cargo.toml" >&2
  exit 1
fi

manifest="$(
  jq -n \
    --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg source_sha "$source_sha" \
    --argjson source_dirty "$source_dirty" \
    --arg binary_path "$binary_realpath" \
    --arg binary_sha256 "$binary_sha256" \
    --argjson binary_size_bytes "$binary_size_bytes" \
    --argjson tool_count "$tool_count" \
    --arg tool_inventory_sha256 "$tool_inventory_sha256" \
    --arg schema_snapshot_sha256 "$schema_snapshot_sha256" \
    --arg api_catalog_sha256 "$api_catalog_sha256" \
    --arg toolkit_revision "$toolkit_revision" \
    '{
      schema_version: 1,
      generated_at: $generated_at,
      source: {
        repository: "sednalabs/cloudflare-mcp",
        commit: $source_sha,
        dirty: $source_dirty
      },
      binary: {
        path: $binary_path,
        sha256: $binary_sha256,
        size_bytes: $binary_size_bytes
      },
      tools: {
        count: $tool_count,
        inventory_sha256: $tool_inventory_sha256
      },
      contracts: {
        tool_schema_snapshot_sha256: $schema_snapshot_sha256,
        cloudflare_api_catalog_sha256: $api_catalog_sha256
      },
      dependencies: {
        mcp_toolkit_rs_revision: $toolkit_revision
      }
    }'
)"

if [[ -n "$output_path" ]]; then
  mkdir -p "$(dirname "$output_path")"
  printf '%s\n' "$manifest" > "$output_path"
else
  printf '%s\n' "$manifest"
fi
