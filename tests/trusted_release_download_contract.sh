#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helper="$repo_root/scripts/download-trusted-release-bundle.sh"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

mkdir -p "$scratch/bin"
cat >"$scratch/bin/gh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == "api /repos/sednalabs/cloudflare-mcp/actions/runs/12345" ]]; then
  cat "$MOCK_RUN_JSON"
  exit 0
fi
if [[ "$1 $2" == "run download" ]]; then
  printf '%s\n' "$*" >>"$MOCK_DOWNLOAD_LOG"
  exit 0
fi
echo "unexpected gh invocation: $*" >&2
exit 2
MOCK
chmod 0755 "$scratch/bin/gh"

export PATH="$scratch/bin:$PATH"
export MOCK_RUN_JSON="$scratch/run.json"
export MOCK_DOWNLOAD_LOG="$scratch/download.log"
readonly sha="0123456789abcdef0123456789abcdef01234567"

write_run() {
  jq -n \
    --arg status "${status:-completed}" \
    --arg conclusion "${conclusion:-success}" \
    --arg event "${event:-push}" \
    --arg head_branch "${head_branch:-main}" \
    --arg head_sha "${head_sha:-$sha}" \
    --arg repository "${repository:-sednalabs/cloudflare-mcp}" \
    --arg name "${workflow_name:-Rust Validation}" \
    --arg path "${workflow_path:-.github/workflows/rust-validation.yml}" \
    '{status:$status, conclusion:$conclusion, event:$event, head_branch:$head_branch,
      head_sha:$head_sha, repository:{full_name:$repository}, name:$name, path:$path}' >"$MOCK_RUN_JSON"
}

invoke() {
  "$helper" --run-id 12345 --sha "$sha" --arch aarch64 --destination "$scratch/out"
}

assert_refused() {
  local label="$1"
  rm -f "$MOCK_DOWNLOAD_LOG"
  if invoke >/dev/null 2>&1; then
    echo "expected refusal for $label" >&2
    exit 1
  fi
  [[ ! -e "$MOCK_DOWNLOAD_LOG" ]] || {
    echo "download was invoked for refused case: $label" >&2
    exit 1
  }
}

write_run
invoke
grep -Fx "run download 12345 --repo sednalabs/cloudflare-mcp --name cloudflare-mcp-linux-aarch64-stdio-${sha} --dir $scratch/out" "$MOCK_DOWNLOAD_LOG"

for field in status conclusion event head_branch head_sha repository workflow_name workflow_path; do
  unset status conclusion event head_branch head_sha repository workflow_name workflow_path
  case "$field" in
    status) status="in_progress" ;;
    conclusion) conclusion="failure" ;;
    event) event="pull_request" ;;
    head_branch) head_branch="release-candidate" ;;
    head_sha) head_sha="ffffffffffffffffffffffffffffffffffffffff" ;;
    repository) repository="example/cloudflare-mcp" ;;
    workflow_name) workflow_name="Other Validation" ;;
    workflow_path) workflow_path=".github/workflows/other.yml" ;;
  esac
  write_run
  assert_refused "$field mismatch"
done

printf '%s\n' '{not-json' >"$MOCK_RUN_JSON"
assert_refused "malformed API response"

echo "trusted release download contract: ok"
