# Dependent-audit tool as an async service

A Docker Compose stack that serves `audit_dependents.py` over HTTP as an
**asynchronous job API** — submit an audit, get a job id back immediately, then
poll for the result. The crawl runs in a separate worker container, so deep or
long searches never hold an HTTP connection open.

```
client ──HTTP──▶ nginx (:8080) ──▶ gunicorn/flask web API ──┐
                 reverse proxy       (validate + enqueue)    ├─ shared jobs volume
                                     worker (runs crawler) ──┘
```

The web tier and the worker communicate only through a shared volume (a
filesystem-backed job store — no broker or database dependency). The request
payload mirrors the `audit_dependents.py` CLI flags one-for-one.

## Quick start

```bash
cp deploy/.env.example .env      # fill in SG_TOKEN / GH_TOKEN
docker compose up --build
```

Submit a job:

```bash
curl -sS http://localhost:8080/audit \
  -H 'Content-Type: application/json' \
  -d '{"repo": "LLNL/zfp", "name": "zfp", "depth": 2}'
# 202 -> {"id": "…", "status": "queued", "links": {...}}
```

Poll it:

```bash
curl -sS http://localhost:8080/jobs/<id>          # status: queued|running|succeeded|failed|timeout
curl -sS http://localhost:8080/jobs/<id>/graph    # the {meta,nodes,edges} graph, once succeeded
curl -sSO http://localhost:8080/jobs/<id>/spdx    # SPDX snippets as a zip, if any
```

## Endpoints

| Method | Path                 | Purpose                                              |
|--------|----------------------|------------------------------------------------------|
| GET    | `/health`            | Liveness.                                            |
| POST   | `/audit`             | Enqueue an audit. `202` with `{id, status, links}`.  |
| GET    | `/jobs`              | List recent jobs (`?limit=N`).                       |
| GET    | `/jobs/<id>`         | Poll one job's status/metadata.                      |
| GET    | `/jobs/<id>/graph`   | The dependency graph JSON (`409` until succeeded).   |
| GET    | `/jobs/<id>/spdx`    | The per-edge SPDX snippets as a zip (`404` if none). |
| DELETE | `/jobs/<id>`         | Discard a job and its artifacts.                     |

### Job lifecycle

`queued → running → succeeded | failed | timeout`

`GET /jobs/<id>` returns, e.g.:

```json
{
  "id": "9f3c…",
  "status": "running",
  "repo": "LLNL/zfp",
  "depth": 2,
  "created_at": 1753699200.0,
  "started_at": 1753699201.4,
  "finished_at": null,
  "error": null,
  "returncode": null,
  "links": { "self": "...", "graph": "...", "spdx": "..." }
}
```

On `failed`, `error` and `returncode` are populated (the crawler's stderr tail
is kept in the job dir as `stderr.log`).

## Payload schema

Every field maps to the identically-named CLI flag (`--repo` → `"repo"`, etc.).
Keys may use hyphens or underscores. `repo` and `name` are required; everything
else uses the CLI default. Malformed payloads are rejected at submit with `400`.

**String options:** `repo`*, `name`*, `ecosystem` (`cpp` only implemented),
`email`, `academic_keyword`, `sg_count`, `idf_cache`, `declared_sources`,
`custom_string`, `custom_file`.

**Numeric options:** `depth` (int; `0` = root metadata/citations only),
`idf_cap` (int), `sg_delay` (float seconds).

**Boolean flags:** `verbose`, `forks`, `include_archived`, `include_vendored`,
`no_idf`, `no_defaults`.

**Secrets** (kept off the command line — forwarded to the worker subprocess via
env, and fall back to the container's `SG_TOKEN` / `GH_TOKEN`): `sg_token`,
`gh_token`.

`out` is ignored (the service owns the output path). SPDX snippets are always
retrievable via `/jobs/<id>/spdx` when the crawl produced them.

### Fuller example

```jsonc
{
  "repo": "LLNL/zfp",
  "name": "zfp",
  "depth": 3,
  "ecosystem": "cpp",
  "declared_sources": "spack",
  "academic_keyword": "zfp,compression",
  "include_vendored": false,
  "no_idf": false,
  "sg_count": "5000",
  "sg_token": "sgp_…"          // optional; else uses container SG_TOKEN
}
```

## Scaling & operations

- **Parallel audits** = `WORKER_CONCURRENCY` (thread pool inside the worker).
  Raise it, or run more worker replicas — `docker compose up --scale worker=3`.
  Claiming is atomic (a sentinel `rename` on the shared volume), so replicas
  never double-process a job.
- **Per-audit ceiling** = `AUDIT_TIMEOUT` (default 3600s); a job that exceeds it
  ends as `timeout`. Raise it for very deep crawls.
- **Retention**: set `JOB_TTL` (seconds) to auto-delete finished jobs; `0` keeps
  them until you `DELETE` them.
- **Durability**: jobs persist on the `jobs` named volume across restarts. A job
  that was `running` when the worker was killed stays claimed and will not be
  retried — re-submit it. (Add crash-recovery / requeue if you need it.)
- Tune everything through `.env` (see `deploy/.env.example`).
