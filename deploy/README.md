# Dependent-audit service (web UI + API)

A Docker Compose stack that serves `audit_dependents.py` as a web application:
a browser UI to submit audits, **watch them run live**, and explore/download the
results, backed by an **asynchronous job API** with a Server-Sent Events stream
for progress. The crawl runs in a separate worker container, so deep or long
searches never tie up a request thread.

```
browser ──▶ nginx (:8080) ── static SPA (frontend/, built into the nginx image)
                 │
                 ├── /api/*             ──▶ gunicorn/flask web API ──┐
                 └── /api/jobs/*/events ──▶ (same, unbuffered SSE)    ├─ shared jobs volume
                                            worker ──Popen──▶ crawler ┘
```

The web tier and the worker communicate only through a shared volume (a
filesystem-backed job store — no broker or database). Each job directory holds
the request, its status, an append-only **progress event log**
(`events.jsonl`), the crawler log, and the results. There is no history
database: results live until deleted (or `JOB_TTL` expires them).

## Quick start

```bash
cp deploy/.env.example .env      # fill in SG_TOKEN / GH_TOKEN
docker compose up --build
```

Open **http://localhost:8080**:

- **New audit** — repository + name, depth, match cap, "skip papers"; the
  advanced sections (identifier tuning, citations) are generated from
  `GET /api/options`, so every crawler flag the service exposes is there.
- **Audit page** — live phase timeline, Sourcegraph match counter, dependents
  table that fills in as they're found and enriched, warnings, cancel. When the
  audit finishes it becomes the results view: dependents table (sort/filter by
  confidence, relationship, evidence layer, depth), interactive graph, papers,
  per-repo detail drawer, and downloads (graph JSON, SPDX zip, CSV).
- **Open graph** (`/view`) — render any `dependency_graph.json` from a URL
  (`/view?url=…`, e.g. `raw.githubusercontent.com`) or a local file — including
  the GitHub Action's artifact `.zip`, whose SPDX snippets then show in the
  detail drawer. Files are read in the browser; nothing is uploaded. Use it for
  README badges:

  ```markdown
  [![Dependency Graph](https://img.shields.io/badge/dependencies-graph-007bff)](https://YOUR_HOST/view?url=https://raw.githubusercontent.com/ORG/REPO/main/dependency_graph.json)
  ```

  The graph URL's host must allow cross-origin reads (GitHub raw does).

### From the command line

```bash
ID=$(curl -sS http://localhost:8080/api/jobs -H 'Content-Type: application/json' \
      -d '{"repo": "LLNL/zfp", "name": "zfp", "depth": 1, "no_citations": true}' | jq -r .id)
curl -sN http://localhost:8080/api/jobs/$ID/events          # live progress (SSE)
curl -sS http://localhost:8080/api/jobs/$ID                 # status
curl -sS http://localhost:8080/api/jobs/$ID/graph           # {meta,nodes,edges}, once succeeded
curl -sSOJ http://localhost:8080/api/jobs/$ID/spdx          # SPDX snippets zip
```

## Endpoints

| Method | Path                         | Purpose |
|--------|------------------------------|---------|
| POST   | `/api/jobs`                  | Enqueue an audit. `202` with `{id, status, links}`; `400` bad payload, `415` not JSON. |
| GET    | `/api/jobs?limit=N`          | Recent jobs; running ones include `lastEvent` (latest progress event). |
| GET    | `/api/jobs/<id>`             | Status/metadata, the (redacted) `params`, `hasGraph`/`hasSpdx`, `links`. |
| GET    | `/api/jobs/<id>/events`      | **Live progress**, `text/event-stream` (see below). |
| GET    | `/api/jobs/<id>/graph`       | The dependency graph (`409` until succeeded). `?download=1` → attachment. |
| GET    | `/api/jobs/<id>/spdx`        | Per-edge SPDX snippets as a zip (`404` if none). |
| GET    | `/api/jobs/<id>/spdx/<file>` | One snippet by its `snippetPath` basename (shown in the UI's detail drawer). |
| GET    | `/api/jobs/<id>/log?tail=N`  | Tail of the crawler's log (text), written live. |
| POST   | `/api/jobs/<id>/cancel`      | Cancel: a queued job ends immediately, a running crawl is stopped. `409` if finished. |
| DELETE | `/api/jobs/<id>`             | Discard a finished/queued job and its artifacts (`409` while running — cancel first). |
| GET    | `/api/options`               | The submit-form schema (the payload spec below, minus secrets/server-only keys). |
| GET    | `/api/health`                | Web status + worker liveness, concurrency, and whether tokens are configured (booleans only). |
| GET    | `/health`                    | Liveness (container healthcheck). |

**Deprecated aliases** (kept for existing clients; responses carry
`Deprecation: true` and a `Link: <…>; rel="successor-version"` header):
`POST /audit`, `GET /jobs`, `GET|DELETE /jobs/<id>`, `GET /jobs/<id>/graph`,
`GET /jobs/<id>/spdx`.

### Job lifecycle

`queued → running → succeeded | failed | timeout | cancelled`

On `failed`, `error` and `returncode` are populated; the crawler's log is in
`/api/jobs/<id>/log`. A job whose worker disappears (container killed) is marked
`failed` with `error: "worker lost"` once its per-job heartbeat is older than
`STALE_AFTER`.

## Live progress (Server-Sent Events)

`GET /api/jobs/<id>/events` replays the job's event log from the start and then
follows it until the job finishes. Every message is
`id: <n>\ndata: <json>\n\n`, where `n` is the event's index in the log.

- **Resume**: send `Last-Event-ID: <n>` (browsers' `EventSource` does this
  automatically on reconnect) or `?lastEventId=<n>`; the stream continues at
  `n+1`. A finished job with nothing left to send returns `204`, which stops
  `EventSource` from reconnecting.
- Streams are bounded (`SSE_MAX_SECONDS`, default 60) and heartbeated (`: hb`
  comments); clients simply reconnect and resume. When the per-process stream
  cap (`SSE_MAX_STREAMS`) is reached the server answers with an empty stream and
  `retry: 10000`, so browsers back off instead of failing.

Each event is `{"seq", "ts", "type", "src", "data"}` (`src` = `web` | `worker`
| `crawler`). Catalogue (`eventsVersion` 1):

| type | from | data |
|------|------|------|
| `job` | web, worker | `status` (`queued` → `running` → terminal), plus `returncode`, `error`, `elapsedSec` on the terminal event. The terminal event is written **after** the job status, so `/graph` is ready when a client sees `succeeded`. |
| `run_started` | crawler | `runId`, `root`, `name`, `depth`, `ecosystem`, `citations`, `sgCount`, `eventsVersion` |
| `phase` | crawler | `phase` (`root_metadata`, `declared`, `identifiers`, `specificity`, `search`, `scoring`, `enrich`, `write`), `state` (`start`/`end`), `repo`, `detail` (counts) |
| `node_start` | crawler | a queue node begins discovery: `repo`, `depth`, `chain`, `processed`, `queued` |
| `search_progress` | crawler | live Sourcegraph counters, ≤1/s: `repo`, `matches`, `lines`, `consumers`, `elapsedSec`, `final` |
| `candidates` | crawler | scored consumers of `parent`, strongest first, before enrichment: `batch[] {id, confidence, confidenceScore, relationship, evidenceLayer, matchCount}` (batches of 500) |
| `enrich_progress` | crawler | `parent`, `done`, `total`, `repo` (fetching metadata/citations for dependent N of M) |
| `node` | crawler | slim node summary (stars, license, fork, description ≤280 chars, confidence, paper counts by tier) — full records come from `/graph` |
| `edge` | crawler | `source`, `target`, `relationship`, `confidence`, `confidenceScore`, `evidenceLayer`, `layers`, `matchCount`, `evidence`, `identifiers` (≤20), `identifiersTotal` |
| `incomplete` | crawler | a partial-search signal: `scope` (`discovery`/`citations`), `repo`, `reason` |
| `log` | crawler | every WARNING+ crawler log record: `level`, `message`, `repo`, `depth`, `extra` |
| `result` | crawler | `complete`, `warnings`, `nodes`, `edges`, `elapsedSec`, `completeness` (= `meta.completeness`) |
| `error` | crawler | the crawl raised: `message`, `excType` |

The crawler writes these with `--events-file` (see `usage.md`); without that
flag it emits nothing, so the CLI and GitHub Action are unaffected.

## Payload schema

Every field maps to the identically-named CLI flag (`--repo` → `"repo"`, etc.);
keys may use hyphens or underscores. `repo` and `name` are required; everything
else uses the CLI default. Malformed payloads are rejected at submit with `400`.
The authoritative list, with types, defaults and help text, is
`GET /api/options` (declared once in `deploy/service/auditlib.py:OPTION_SPEC`,
and unit-tested against the crawler's argparse parser so the two can't drift).

- **basic:** `repo`\*, `name`\*, `depth` (int; `0` = root metadata/citations
  only), `no_citations` (bool), `sg_count` (int or `"all"`)
- **discovery:** `ecosystem` (`cpp`), `no_defaults`, `custom_string`,
  `custom_file`, `declared_sources`, `forks`, `include_archived`,
  `include_vendored`, `no_idf`, `idf_cap` (int), `sg_delay` (float s)
- **citations:** `email`, `academic_keyword`, `citation_depth` (int),
  `paper_relevance_floor` (`low`|`medium`|`high`), `no_paper_filter`,
  `no_paper_relevance`, `citation_graph_depth` (int), `openalex_delay` (float s)
  — the last two default to the worker's `CITATION_GRAPH_DEPTH` /
  `OPENALEX_DELAY` when omitted
- **advanced:** `verbose`

**Secrets** — `sg_token`, `gh_token`, `openalex_api_key`: forwarded to the
crawler via the environment (never the command line), falling back to the
worker's `SG_TOKEN` / `GH_TOKEN` / `OPENALEX_API_KEY`. Only accepted when
`ALLOW_PAYLOAD_TOKENS=1`; set it to `0` in production so only server tokens are
ever used. Secrets are masked (`***`) in `GET /api/jobs/<id>`.

**Server-only** — `idf_cache`, `paper_cache`, `config`, `repo_checkout`,
`relevance_llm_url`, `relevance_llm_model` are accepted for backwards
compatibility but **ignored**: they are filesystem paths or an outbound URL,
which a client must not control. The worker always passes the caches (inside
the job directory) and the relevance-LLM settings (from its own environment)
explicitly, so an auto-fetched `.dependent-audit.toml` in the *audited* repo
can't redirect them either. `out` is ignored (the service owns the output path).

### Fuller example

```jsonc
{
  "repo": "RobotLocomotion/drake",
  "name": "drake",
  "depth": 1,
  "no_defaults": true,
  "custom_string": "(include\\s*[<\"]drake/|find_package\\s*\\(\\s*drake[\\s)]|@drake//|RobotLocomotion/drake)",
  "no_citations": true,
  "sg_count": "all"
}
```

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install requests flask gunicorn
# API (port 8000) and a worker; the fake crawler needs no tokens or network
JOBS_DIR=$PWD/.jobs .venv/bin/python deploy/service/app.py &
JOBS_DIR=$PWD/.jobs AUDIT_SCRIPT=$PWD/deploy/ci/fake_audit.py FAKE_AUDIT_DELAY=0.5 \
  SG_TOKEN=fake .venv/bin/python deploy/service/worker.py &
# UI with hot reload on http://localhost:5173 (proxies /api to :8000)
cd frontend && npm ci && npm run dev
```

Drop `AUDIT_SCRIPT`/`SG_TOKEN=fake` and export real tokens to run real audits.
Tests: `python tests/test_progress_events.py`, `python
deploy/service/tests/test_{auditlib,events,app}.py`, and in `frontend/`:
`npm run lint && npm run typecheck && npm test`. `deploy/ci/smoke_test.sh` runs
end-to-end against the compose stack (see `.github/workflows/ci.yml`).

## Scaling & operations

- **Parallel audits** = `WORKER_CONCURRENCY` (thread pool inside the worker).
  Raise it, or run more worker replicas — `docker compose up --scale worker=3`.
  Claiming is atomic (a sentinel `rename` on the shared volume), so replicas
  never double-process a job.
- **Live viewers**: each open progress stream holds a gunicorn thread;
  `WEB_THREADS` (default 16) and `SSE_MAX_STREAMS` (default 12 per process)
  budget them. See `DEPLOY.md` for tuning and the gevent upgrade path.
- **Per-audit ceiling** = `AUDIT_TIMEOUT` (default 3600s); a job that exceeds it
  ends as `timeout`. Raise it for very deep crawls.
- **Retention**: set `JOB_TTL` (seconds) to auto-delete finished jobs; `0` keeps
  them until you delete them.
- **Durability**: jobs persist on the `jobs` named volume across restarts. A job
  that was `running` when its worker died is marked `failed` ("worker lost")
  after `STALE_AFTER` seconds — re-submit it.
- Tune everything through `.env` (see `deploy/.env.example`).
