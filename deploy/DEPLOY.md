# Deploying the dependent-audit service

This guide covers standing up the async audit service (nginx → gunicorn/flask →
worker) with Docker Compose, from a local trial to a single-host production
deployment. For the request/response API itself, see [`README.md`](README.md).

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
| `WEB_CONCURRENCY` / `WEB_THREADS` | web | gunicorn workers/threads (fast requests) |
| `WORKER_CONCURRENCY` | worker | max audits running at once |
| `AUDIT_TIMEOUT` | worker | per-audit hard limit (s); a slower crawl ends as `timeout` |
| `POLL_INTERVAL` | worker | queue scan interval (s) |
| `JOB_TTL` | worker | auto-delete finished jobs older than N seconds (`0` = keep) |

> **Token handling:** tokens live in `.env` (git-ignored) and reach the worker
> as environment variables — never on a command line. Callers *may* override
> per-request by putting `sg_token`/`gh_token` in the JSON payload; those also
> travel via the subprocess environment, not `argv`. Prefer the env default and
> reserve per-request tokens for multi-tenant use.

---

## 3. Launch

```bash
docker compose up --build -d
```

This builds one image (the `audit` service) and starts three containers:

| Container | Role | Exposed |
|-----------|------|---------|
| `nginx`   | reverse proxy | `:${HTTP_PORT}` on the host |
| `audit`   | gunicorn/flask web API | internal `:8000` only |
| `worker`  | drains the queue, runs crawls | none |

The `audit` and `worker` share a Docker named volume (`jobs`) as the job
store — that is the only channel between them, so there is no broker to run.

Verify:

```bash
curl -sS http://localhost:${HTTP_PORT:-8080}/health      # {"status":"ok"}
docker compose ps                                         # all Up / healthy
```

Smoke-test a real audit (needs a valid Sourcegraph token):

```bash
ID=$(curl -sS localhost:${HTTP_PORT:-8080}/audit -H 'Content-Type: application/json' \
      -d '{"repo":"dyninst/dyninst","name":"dyninst","depth":1}' | jq -r .id)
watch -n3 "curl -sS localhost:${HTTP_PORT:-8080}/jobs/$ID | jq .status"
curl -sS localhost:${HTTP_PORT:-8080}/jobs/$ID/graph | jq '.meta, (.nodes|length), (.edges|length)'
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

Base the `tls.conf` on `deploy/nginx/nginx.conf`, adding `listen 443 ssl;`,
`ssl_certificate`/`ssl_certificate_key`, and a redirect from `:80`.

**Authentication.** The API has no built-in auth. Do **not** expose it to an
untrusted network as-is — anyone who can reach it can spend your API-token quota
and read any job's results. Put it behind one of: an nginx `auth_basic` /
`auth_request`, an API gateway, a VPN, or firewall rules. If you support
per-request tokens, require an auth layer so callers cannot read each other's
jobs.

**Resource limits.** Cap the worker so a deep crawl can't exhaust the host:

```yaml
services:
  worker:
    deploy:
      resources:
        limits: { cpus: "2.0", memory: 2g }
```

**Retention.** Set `JOB_TTL` so finished jobs are swept automatically; otherwise
they accumulate on the `jobs` volume until you `DELETE /jobs/<id>`.

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
a worker was killed stays claimed and is **not** auto-retried — re-submit it.

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
| `/jobs/<id>/graph` returns 409 | job not `succeeded` yet | poll `/jobs/<id>` until terminal |
