#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_REPOSITORY="sednalabs/cloudflare-mcp"
readonly EXPECTED_WORKFLOW_NAME="Rust Validation"
readonly EXPECTED_WORKFLOW_PATH=".github/workflows/rust-validation.yml"

usage() {
  echo "usage: $0 --run-id ID --sha SHA --arch x86_64|aarch64 --destination DIR" >&2
  exit 64
}

run_id=""
sha=""
arch=""
destination=""

while (($#)); do
  case "$1" in
    --run-id) (($# >= 2)) || usage; run_id="$2"; shift 2 ;;
    --sha) (($# >= 2)) || usage; sha="$2"; shift 2 ;;
    --arch) (($# >= 2)) || usage; arch="$2"; shift 2 ;;
    --destination) (($# >= 2)) || usage; destination="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[[ "$run_id" =~ ^[1-9][0-9]*$ ]] || usage
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || usage
case "$arch" in
  x86_64|aarch64) ;;
  *) usage ;;
esac
[[ -n "$destination" ]] || usage

command -v gh >/dev/null || { echo "gh is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

run_json="$(gh api "/repos/${EXPECTED_REPOSITORY}/actions/runs/${run_id}")"
if ! jq -e \
  --arg repository "$EXPECTED_REPOSITORY" \
  --arg workflow_name "$EXPECTED_WORKFLOW_NAME" \
  --arg workflow_path "$EXPECTED_WORKFLOW_PATH" \
  --arg sha "$sha" '
    .status == "completed" and
    .conclusion == "success" and
    .event == "push" and
    .head_branch == "main" and
    .head_sha == $sha and
    .repository.full_name == $repository and
    .name == $workflow_name and
    .path == $workflow_path
  ' <<<"$run_json" >/dev/null; then
  echo "refusing artifact download: GitHub Actions run does not match the trusted main-push contract" >&2
  exit 1
fi

artifact="cloudflare-mcp-linux-${arch}-stdio-${sha}"
mkdir -p "$destination"
gh run download "$run_id" \
  --repo "$EXPECTED_REPOSITORY" \
  --name "$artifact" \
  --dir "$destination"
