# Deploying the dependent-audit service

This guide covers standing up the audit service — web UI, API and live-progress
stream (nginx → gunicorn/flask → worker) — with Docker Compose, from a local
trial to a single-host production deployment. For the UI and API themselves,
see [`README.md`](README.md).

---

## 1. Prerequisites

- **Docker Engine 24+** with the **Compose v2** plugin (`docker compose version`).
- Outbound HTTPS from the host — the worker calls Sourcegraph, GitHub,
  Crossref, OpenAlex, and OpenCitations.
- **Tokens:**
  - A **Sourcegraph** access token (`https://sourcegraph.com/user/settings/tokens`).
    Required for dependent discovery at `depth ≥ 1`.
  - A **GitHub** personal access token (public-repo / read scope is enough) for
    repo metadata and `CITATION.cff`/`codemeta` reads (this gates citation
    discovery — see the dyninst case: no GH token ⇒ no seminal DOIs ⇒ no papers).
- Roughly 1 vCPU + 1 GB RAM per concurrent audit as a starting point. Audits are
  I/O-bound (waiting on external APIs), so you can oversubscribe CPU.

---

## 2. Configure

From the repository root:

```bash
cp deploy/.env.example .env
```

Edit `.env` and set at least:

```ini
SG_TOKEN=sgp_...           # Sourcegraph token (the full sgp_<instance>_<secret> value)
GH_TOKEN=ghp_...           # GitHub PAT
AUDIT_EMAIL=you@org.example
HTTP_PORT=8080             # host port nginx publishes
```

Tuning knobs (safe defaults shown in `.env.example`):

| Var | Tier | Meaning |
|-----|------|---------|
| `WEB_CONCURRENCY` / `WEB_THREADS` | web | gunicorn processes / threads per process (each open progress stream holds a thread) |
| `SSE_MAX_STREAMS` | web | live-progress streams per process (keep below `WEB_THREADS`) |
| `SSE_MAX_SECONDS` | web | lifetime of one stream; browsers then resume transparently |
| `ALLOW_PAYLOAD_TOKENS` | web + worker | accept `sg_token`/`gh_token` in requests (`0` in production) |
| `WORKER_CONCURRENCY` | worker | max audits running at once |
| `AUDIT_TIMEOUT` | worker | per-audit hard limit (s); a slower crawl ends as `timeout` |
| `POLL_INTERVAL` | worker | queue scan interval (s) |
| `JOB_TTL` | worker | auto-delete finished jobs older than N seconds (`0` = keep) |
| `STALE_AFTER` | worker | mark a `running` job `failed` when its worker stopped heart-beating (s) |
| `RELEVANCE_LLM_*` | worker | optional paper-relevance LLM tie-breaker (server-side only) |

> **Token handling:** tokens live in `.env` (git-ignored) and reach the worker
> as environment variables — never on a command line, and never in the browser.
> The UI only learns *whether* tokens are configured (`/api/health`). API
> callers may override per-request with `sg_token`/`gh_token` in the JSON
> payload (also forwarded via env, masked in responses) while
> `ALLOW_PAYLOAD_TOKENS=1`; set it to `0` to accept server tokens only.

---

## 3. Launch

```bash
docker compose up --build -d
```

This builds two images and starts three containers:

| Container | Image | Role | Exposed |
|-----------|-------|------|---------|
| `nginx`   | `dependent-audit-nginx` (multi-stage: node builds `frontend/`, nginx serves it) | web UI + reverse proxy | `:${HTTP_PORT}` on the host |
| `audit`   | `dependent-audit-service` | gunicorn/flask API + SSE | internal `:8000` only |
| `worker`  | `dependent-audit-service` | drains the queue, runs crawls | none |

The `audit` and `worker` share a Docker named volume (`jobs`) as the job
store — that is the only channel between them (including live progress, via
each job's `events.jsonl`), so there is no broker to run.

Verify:

```bash
curl -sS http://localhost:${HTTP_PORT:-8080}/api/health   # web ok + worker alive/tokens
docker compose ps                                         # all Up / healthy
```

Then open `http://localhost:${HTTP_PORT:-8080}` and submit an audit (e.g.
`dyninst/dyninst`, depth 1). The audit page streams progress live. From a shell:

```bash
ID=$(curl -sS localhost:${HTTP_PORT:-8080}/api/jobs -H 'Content-Type: application/json' \
      -d '{"repo":"dyninst/dyninst","name":"dyninst","depth":1}' | jq -r .id)
curl -sN localhost:${HTTP_PORT:-8080}/api/jobs/$ID/events    # live events until done
curl -sS localhost:${HTTP_PORT:-8080}/api/jobs/$ID/graph | jq '.meta, (.nodes|length), (.edges|length)'
```

---

## 4. Scaling

- **More parallel audits:** raise `WORKER_CONCURRENCY`, or run multiple worker
  containers:

  ```bash
  docker compose up -d --scale worker=3
  ```

  Job claiming is atomic (a sentinel `rename` on the shared volume), so replicas
  never double-process a job. Because the queue is a shared *volume*, all worker
  replicas must run on the **same host** (single-node deployment).

- **More API throughput:** raise `WEB_CONCURRENCY`. The web tier only validates,
  enqueues, and serves results off the volume, so it is cheap.

- **More live viewers:** every browser watching a running audit holds one
  gunicorn thread for its progress stream. Capacity is roughly
  `WEB_CONCURRENCY × SSE_MAX_STREAMS` concurrent streams (24 by default); past
  that, browsers are told to retry in 10 s rather than failing, and ordinary
  API requests keep `WEB_THREADS − SSE_MAX_STREAMS` threads per process. Raise
  `WEB_THREADS` and `SSE_MAX_STREAMS` together for a few dozen viewers. Beyond
  ~50 concurrent viewers, switch gunicorn to `worker_class = "gevent"` (add
  `gevent` to `deploy/service/requirements.txt`), which makes idle streams
  nearly free.

- **Multi-host / HA** is out of scope for this compose setup: the filesystem job
  store is single-node by design. To go multi-host, replace `JobStore` with a
  shared broker/object store — the web and worker already talk only through that
  interface.

---

## 5. Production hardening

**TLS.** Terminate HTTPS at nginx (or an upstream load balancer). To do it in
nginx, add a `443` server block and mount your certs, e.g.:

```yaml
# docker-compose.override.yml
services:
  nginx:
    ports:
      - "443:443"
    volumes:
      - ./deploy/nginx/tls.conf:/etc/nginx/conf.d/default.conf:ro
      - /etc/letsencrypt/live/YOURHOST:/etc/nginx/certs:ro
```

Base the `tls.conf` on `deploy/nginx/nginx.conf` (baked into the nginx image;
mounting a file over it overrides it), adding `listen 443 ssl;`,
`ssl_certificate`/`ssl_certificate_key`, and a redirect from `:80`. Keep the
`/api/jobs/<id>/events` location's `proxy_buffering off` / long
`proxy_read_timeout` — without them live progress arrives in bursts or not at
all. If a load balancer or CDN sits in front, disable response buffering and
raise its idle timeout above `SSE_MAX_SECONDS` for that path as well.

**Authentication.** The UI and API have no built-in auth. Do **not** expose
them to an untrusted network as-is — anyone who can reach the service can start
audits that spend your token quota, and read or delete any job's results. Put
the whole site (the UI, `/api/*`, and the legacy routes) behind one of: an
nginx `auth_basic` / `auth_request`, an SSO proxy (e.g. oauth2-proxy), a VPN, or
firewall rules. Browsers send basic-auth/cookie credentials on the progress
stream automatically, so these work without UI changes. Set
`ALLOW_PAYLOAD_TOKENS=0` so only the server's tokens are ever used.

**Resource limits.** Cap the worker so a deep crawl can't exhaust the host:

```yaml
services:
  worker:
    deploy:
      resources:
        limits: { cpus: "2.0", memory: 2g }
```

**Retention.** Set `JOB_TTL` so finished jobs are swept automatically; otherwise
they accumulate on the `jobs` volume until deleted (UI, or
`DELETE /api/jobs/<id>`).

---

## 6. Operations

**Logs**

```bash
docker compose logs -f worker        # crawl progress, per-job start/finish
docker compose logs -f audit nginx   # requests
```

**Update to a new build**

```bash
git pull
docker compose up -d --build         # rebuilds image, recreates containers
```

Jobs persist on the `jobs` volume across restarts. A job that was `running` when
a worker was killed is **not** retried: once its per-job heartbeat is older than
`STALE_AFTER` (default 300 s) the next worker marks it `failed` ("worker lost").
Re-submit it. The frontend is rebuilt into the nginx image by the same
`docker compose up -d --build`.

**Back up / inspect the job store**

```bash
docker run --rm -v dependent-searcher_jobs:/data -v "$PWD":/backup alpine \
  tar czf /backup/jobs-backup.tgz -C /data .
```

(The volume is named `<project>_jobs`; confirm with `docker volume ls`.)

**Stop**

```bash
docker compose down            # keep the jobs volume
docker compose down -v         # also delete all jobs
```

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Jobs end `failed`, logs show `401 Invalid access token` | bad/expired Sourcegraph token | refresh `SG_TOKEN`, `docker compose up -d` |
| Graph has empty stars/license, no papers | bad/expired GitHub token | refresh `GH_TOKEN` |
| Jobs stay `queued` forever | worker not running/healthy | `docker compose ps`; check `docker compose logs worker` |
| Jobs end `timeout` | crawl slower than `AUDIT_TIMEOUT` | raise `AUDIT_TIMEOUT` (deep crawls) or lower `depth` |
| `image ... already exists` during build | building the shared image twice | already handled — only `audit` declares `build:`; run `docker compose build` first if customizing |
| `/api/jobs/<id>/graph` returns 409 | job not `succeeded` yet | follow `/api/jobs/<id>/events` (or poll `/api/jobs/<id>`) until terminal |
| Audit page shows "reconnecting…" or progress arrives in bursts | a proxy/LB in front buffers or times out the SSE stream | disable buffering and raise the idle timeout for `/api/jobs/*/events` (see §5 TLS) |
| UI banner "No audit worker has checked in recently" | worker down, or it can't write the shared volume | `docker compose ps`; `docker compose logs worker` |
| Running job ends `failed` with "worker lost" | its worker container was killed/restarted mid-crawl | re-submit; give the worker more memory (see Resource limits) |
