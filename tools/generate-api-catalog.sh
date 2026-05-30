#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_url="${CLOUDFLARE_API_SCHEMA_URL:-https://raw.githubusercontent.com/cloudflare/api-schemas/main/openapi.json}"
generated_at="${CLOUDFLARE_API_CATALOG_GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
tmp="$(mktemp)"
headers="${tmp}.headers"
trap 'rm -f "$tmp" "$headers"' EXIT

curl -fsSLD "$headers" "$source_url" -o "$tmp"
sha="$(sha256sum "$tmp" | awk '{print $1}')"
etag="$(awk 'tolower($1)=="etag:" {gsub("\r",""); print $2}' "$headers" | tail -1)"

jq \
  --arg url "$source_url" \
  --arg sha "$sha" \
  --arg etag "$etag" \
  --arg generated "$generated_at" \
  '
  def scope_for($path):
    if ($path|test("\\{account_id\\}")) and ($path|test("\\{zone_id\\}")) then "mixed"
    elif ($path|test("\\{account_id\\}")) then "account"
    elif ($path|test("\\{zone_id\\}")) then "zone"
    elif ($path|test("/user(/|$)")) then "user"
    elif ($path|test("/organizations(/|$)")) then "organization"
    elif ($path|test("^/(accounts|zones)(/|$)")) then "global"
    else "unknown" end;

  def preferred_tool($op; $path; $method; $tag):
    ($op // "") as $id |
    if $id == "cloudflare-tunnel-list-cloudflare-tunnels" then "list_tunnels"
    elif $id == "cloudflare-tunnel-create-a-cloudflare-tunnel" then "ensure_tunnel"
    elif $id == "dns-records-for-a-zone-list-dns-records" then "list_dns_records"
    elif ($id|test("dns-records-for-a-zone-(create|update|overwrite)-dns-record")) then "upsert_dns_cname"
    elif ($path|test("/access/apps")) and $method == "get" then "list_access_apps"
    elif ($path|test("/access/apps/.*/policies")) and $method == "get" then "list_access_policies"
    elif ($tag == "Worker Script") and $method == "get" then "list_workers"
    elif ($path|test("/workers/scripts/.*/settings")) and $method == "get" then "get_worker_settings"
    elif ($path|test("/workers/scripts/.*/settings")) and ($method|test("put|patch")) then "patch_worker_settings"
    elif ($path|test("/purge_cache")) then "cache_purge"
    elif ($tag|ascii_downcase|test("cache|zone settings|zone rulesets")) then "cache_zone_setting"
    else null end;

  def risk_for($path; $method; $tag; $summary):
    ($path + " " + $tag + " " + ($summary // "") | ascii_downcase) as $text |
    if $method == "get" then "read"
    elif ($text|test("account deletion|delete account|billing|payment|subscription|registrar|domain transfer|api token|api key|user service key|membership|members|role|permission|delete zone|zone deletion")) then "denied_by_default"
    elif $method == "delete" then "high_risk"
    else "mutating" end;

  [ .paths | to_entries[] as $p |
    $p.value | to_entries[] |
    select(.key|IN("get","post","put","patch","delete")) |
    .key as $method |
    .value as $op |
    (($op.operationId // ($method + " " + $p.key)) | gsub("[^A-Za-z0-9_-]+"; "-")) as $id |
    {
      operation_id: $id,
      method: ($method|ascii_upcase),
      path: $p.key,
      tag: (($op.tags[0]) // "untagged"),
      summary: ($op.summary // null),
      deprecated: ($op.deprecated // false),
      scope: scope_for($p.key),
      risk: risk_for($p.key; $method; (($op.tags[0]) // "untagged"); ($op.summary // "")),
      path_params: ([($op.parameters // [])[] | select(.in == "path") | .name] | unique),
      query_params: ([($op.parameters // [])[] | select(.in == "query") | .name] | unique),
      required_query_params: ([($op.parameters // [])[] | select(.in == "query" and .required == true) | .name] | unique),
      has_request_body: ($op.requestBody != null),
      preferred_tool: preferred_tool($id; $p.key; $method; (($op.tags[0]) // "untagged"))
    }
  ] | sort_by(.tag, .operation_id) as $ops |
  {
    schema: "cloudflare_api_catalog.v1",
    source: {
      url: $url,
      etag: (if $etag == "" then null else $etag end),
      sha256: $sha,
      generated_at: $generated
    },
    operation_count: ($ops|length),
    operations: $ops
  }
  ' "$tmp" > "$repo_root/spec/cloudflare_api_catalog.v1.json"

echo "wrote spec/cloudflare_api_catalog.v1.json"
echo "source_sha256=$sha"
