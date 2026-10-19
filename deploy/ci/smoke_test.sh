#!/usr/bin/env bash
# End-to-end smoke test of the audit service, driven through nginx.
# Assumes the stack is already up (see .github/workflows/ci.yml) with the CI
# overlay, so the crawler is the fake one and no tokens/network are needed.
#
# Exercises: health, input validation (400/415), enqueue (202), live progress
# over SSE (unbuffered through nginx, resumable, terminal 204), the worker
# running the job to `succeeded`, the graph/SPDX/log results, the legacy
# aliases, and the SPA being served with client-route fallback.
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
json_field() { python3 -c "import sys,json; print(json.load(sys.stdin)$1)"; }
submit() {
  curl -s -X POST "$BASE/api/jobs" -H 'Content-Type: application/json' -d "$1" | json_field '["id"]'
}

echo "== waiting for nginx -> web to answer /health =="
for i in $(seq 1 30); do
  if [[ "$(code_of GET "$BASE/health")" == "200" ]]; then break; fi
  sleep 2
  [[ $i -eq 30 ]] && fail "service never became healthy"
done
pass "GET /health -> 200"
for i in $(seq 1 15); do
  ALIVE="$(curl -s "$BASE/api/health" | json_field '["worker"]["alive"]')"
  [[ "$ALIVE" == "True" ]] && break
  sleep 2
done
[[ "$ALIVE" == "True" ]] && pass "GET /api/health reports the worker alive" || fail "worker never reported alive"

echo "== frontend (SPA) =="
curl -s "$BASE/" | grep -q '<div id="root">' && pass "GET / serves the app" || fail "/ is not the SPA"
curl -s "$BASE/audits/anything" | grep -q '<div id="root">' \
  && pass "client route /audits/<id> falls back to the app" || fail "SPA fallback missing"
curl -s "$BASE/view?url=x" | grep -q '<div id="root">' && pass "GET /view serves the app" || fail "/view not served"
ASSET="$(curl -s "$BASE/" | grep -o '/assets/[^"]*\.js' | head -1)"
[[ -n "$ASSET" && "$(code_of GET "$BASE$ASSET")" == "200" ]] \
  && pass "hashed JS asset $ASSET -> 200" || fail "asset not served"
[[ "$(code_of GET "$BASE/api/options")" == "200" ]] && pass "GET /api/options -> 200" || fail "options"

echo "== input validation =="
[[ "$(code_of POST "$BASE/api/jobs" '{"name":"x"}')" == "400" ]] \
  && pass "missing repo -> 400" || fail "missing repo should be 400"
[[ "$(code_of POST "$BASE/api/jobs" '{"repo":"a/b","name":"x","bogus":1}')" == "400" ]] \
  && pass "unknown field -> 400" || fail "unknown field should be 400"
# 415 requires a non-JSON content type (Flask's request.is_json keys off it).
non_json_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/jobs" \
  -H 'Content-Type: text/plain' --data 'not json')"
[[ "$non_json_code" == "415" ]] \
  && pass "non-json content-type -> 415" || fail "non-json should be 415 (got $non_json_code)"

echo "== submit a job and watch it live =="
JOB_ID="$(submit '{"repo":"LLNL/zfp","name":"zfp","depth":1}')"
[[ -n "$JOB_ID" ]] && pass "enqueued id=$JOB_ID" || fail "no job id returned"

# Unbuffered: with nginx buffering the first events would sit in a buffer until
# the stream ends; we must see data within 2s while the job is still running.
EARLY="$(curl -sN --max-time 2 "$BASE/api/jobs/$JOB_ID/events" || true)"
echo "$EARLY" | grep -q '^data: ' && pass "SSE delivers events immediately (unbuffered)" \
  || fail "no SSE data within 2s — is nginx buffering the stream?"

STREAM="$(curl -sN --max-time 60 "$BASE/api/jobs/$JOB_ID/events" || true)"
echo "$STREAM" | python3 -c '
import sys, json
ids, events = [], []
for block in sys.stdin.read().split("\n\n"):
    fields = dict(l.split(": ", 1) for l in block.splitlines() if ": " in l and not l.startswith(":"))
    if "data" in fields:
        ids.append(int(fields["id"])); events.append(json.loads(fields["data"]))
assert ids == sorted(set(ids)) and ids[0] == 0, ids
types = [e["type"] for e in events]
for t in ("run_started", "search_progress", "candidates", "node", "edge", "result"):
    assert t in types, (t, types)
last = events[-1]
assert last["type"] == "job" and last["data"]["status"] == "succeeded", last
print(f"  stream: {len(events)} events, ids 0..{ids[-1]}")
' || fail "SSE stream content unexpected"
pass "SSE stream carries the full catalogue and ends at 'succeeded'"
LAST_ID="$(echo "$STREAM" | grep '^id: ' | tail -1 | cut -d' ' -f2)"

FIRST_RESUMED="$(curl -sN --max-time 10 -H 'Last-Event-ID: 2' "$BASE/api/jobs/$JOB_ID/events" \
  | grep '^id: ' | head -1 | cut -d' ' -f2)"
[[ "$FIRST_RESUMED" == "3" ]] && pass "Last-Event-ID: 2 resumes at id 3" \
  || fail "resume started at '$FIRST_RESUMED', expected 3"
DONE_CODE="$(curl -s -o /dev/null -w '%{http_code}' -H "Last-Event-ID: $LAST_ID" \
  "$BASE/api/jobs/$JOB_ID/events")"
[[ "$DONE_CODE" == "204" ]] && pass "caught-up finished stream -> 204" || fail "expected 204, got $DONE_CODE"

STATUS="$(curl -s "$BASE/api/jobs/$JOB_ID" | json_field '["status"]')"
[[ "$STATUS" == "succeeded" ]] && pass "job succeeded" || fail "job ended as '$STATUS'"

echo "== fetch results =="
curl -s "$BASE/api/jobs/$JOB_ID/graph" | python3 -c '
import sys,json
g=json.load(sys.stdin)
assert g["meta"]["root"]=="LLNL/zfp", g["meta"]
assert g["nodes"][0]["data"]["packageName"]=="zfp", g["nodes"][0]
assert len(g["edges"]) >= 1, g["edges"]
print("  graph shape OK:", len(g["nodes"]), "nodes,", len(g["edges"]), "edges")
' || fail "graph content unexpected"
pass "GET /api/jobs/<id>/graph returns the dependency graph"
curl -s -D - -o /dev/null "$BASE/api/jobs/$JOB_ID/graph?download=1" | grep -qi '^content-disposition: attachment' \
  && pass "?download=1 is an attachment" || fail "download header missing"
[[ "$(code_of GET "$BASE/api/jobs/$JOB_ID/spdx")" == "200" ]] \
  && pass "GET /api/jobs/<id>/spdx -> 200" || fail "spdx should be 200"
curl -s "$BASE/api/jobs/$JOB_ID/log" | grep -q 'COMPLETE' \
  && pass "GET /api/jobs/<id>/log returns the crawler log" || fail "log tail missing"

echo "== cancel a queued/running job =="
CANCEL_ID="$(submit '{"repo":"a/b","name":"b"}')"
curl -s -X POST "$BASE/api/jobs/$CANCEL_ID/cancel" >/dev/null
for i in $(seq 1 20); do
  CSTATUS="$(curl -s "$BASE/api/jobs/$CANCEL_ID" | json_field '["status"]')"
  [[ "$CSTATUS" == "cancelled" ]] && break
  sleep 1
done
[[ "$CSTATUS" == "cancelled" ]] && pass "cancel -> cancelled" || fail "cancel ended as '$CSTATUS'"

echo "== legacy aliases =="
LEGACY_HEADERS="$(curl -s -D - -o /dev/null "$BASE/jobs/$JOB_ID")"
echo "$LEGACY_HEADERS" | grep -q '^HTTP/1.1 200' && echo "$LEGACY_HEADERS" | grep -qi '^deprecation: true' \
  && pass "GET /jobs/<id> still works, marked deprecated" || fail "legacy alias broken"
[[ "$(code_of POST "$BASE/audit" '{"name":"x"}')" == "400" ]] && pass "POST /audit still validates" \
  || fail "legacy submit broken"

echo "== unknown job -> 404 =="
[[ "$(code_of GET "$BASE/api/jobs/does-not-exist")" == "404" ]] \
  && pass "unknown job -> 404" || fail "unknown job should be 404"

echo ""
echo "ALL ENDPOINT SMOKE CHECKS PASSED"
