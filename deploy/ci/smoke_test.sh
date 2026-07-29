#!/usr/bin/env bash
# End-to-end smoke test of the audit service, driven through nginx.
# Assumes the stack is already up (see .github/workflows/ci.yml) with the CI
# overlay, so the crawler is the fake one and no tokens/network are needed.
#
# Exercises: health, input validation (400), enqueue (202), the worker running
# the job to `succeeded`, the graph result, the SPDX zip, and 404 on unknown id.
set -euo pipefail

BASE="${BASE:-http://localhost:8080}"

pass() { echo "  ✓ $1"; }
fail() { echo "  ✗ $1"; exit 1; }

# --- helpers ---------------------------------------------------------------
# code_of METHOD URL [json] -> prints HTTP status code
code_of() {
  local method="$1" url="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -s -o /dev/null -w '%{http_code}' -X "$method" "$url" \
      -H 'Content-Type: application/json' -d "$body"
  else
    curl -s -o /dev/null -w '%{http_code}' -X "$method" "$url"
  fi
}

echo "== waiting for nginx -> web to answer /health =="
for i in $(seq 1 30); do
  if [[ "$(code_of GET "$BASE/health")" == "200" ]]; then break; fi
  sleep 2
  [[ $i -eq 30 ]] && fail "service never became healthy"
done
pass "GET /health -> 200"

echo "== input validation =="
[[ "$(code_of POST "$BASE/audit" '{"name":"x"}')" == "400" ]] \
  && pass "missing repo -> 400" || fail "missing repo should be 400"
[[ "$(code_of POST "$BASE/audit" '{"repo":"a/b","name":"x","bogus":1}')" == "400" ]] \
  && pass "unknown field -> 400" || fail "unknown field should be 400"
# 415 requires a non-JSON content type (Flask's request.is_json keys off it).
non_json_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/audit" \
  -H 'Content-Type: text/plain' --data 'not json')"
[[ "$non_json_code" == "415" ]] \
  && pass "non-json content-type -> 415" || fail "non-json should be 415 (got $non_json_code)"

echo "== submit a job =="
SUBMIT="$(curl -s -X POST "$BASE/audit" -H 'Content-Type: application/json' \
  -d '{"repo":"LLNL/zfp","name":"zfp","depth":1}')"
echo "  submit response: $SUBMIT"
JOB_ID="$(echo "$SUBMIT" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')"
[[ -n "$JOB_ID" ]] && pass "enqueued id=$JOB_ID" || fail "no job id returned"

echo "== poll to terminal state =="
STATUS=""
for i in $(seq 1 30); do
  STATUS="$(curl -s "$BASE/jobs/$JOB_ID" | python3 -c 'import sys,json; print(json.load(sys.stdin)["status"])')"
  echo "  status: $STATUS"
  [[ "$STATUS" == "succeeded" || "$STATUS" == "failed" || "$STATUS" == "timeout" ]] && break
  sleep 2
done
[[ "$STATUS" == "succeeded" ]] && pass "job succeeded" || fail "job ended as '$STATUS'"

echo "== fetch the graph =="
GRAPH="$(curl -s "$BASE/jobs/$JOB_ID/graph")"
echo "  graph: $GRAPH"
echo "$GRAPH" | python3 -c '
import sys,json
g=json.load(sys.stdin)
assert g["meta"]["root"]=="LLNL/zfp", g["meta"]
assert g["nodes"][0]["data"]["packageName"]=="zfp", g["nodes"]
print("  graph shape OK")
' || fail "graph content unexpected"
pass "GET /jobs/<id>/graph returns the dependency graph"

echo "== fetch spdx zip =="
[[ "$(code_of GET "$BASE/jobs/$JOB_ID/spdx")" == "200" ]] \
  && pass "GET /jobs/<id>/spdx -> 200" || fail "spdx should be 200"

echo "== unknown job -> 404 =="
[[ "$(code_of GET "$BASE/jobs/does-not-exist")" == "404" ]] \
  && pass "unknown job -> 404" || fail "unknown job should be 404"

echo ""
echo "ALL ENDPOINT SMOKE CHECKS PASSED"
