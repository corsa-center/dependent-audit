"""Background worker: drains queued audit jobs and runs the crawler.

Polls the shared :class:`auditlib.JobStore`, atomically claims queued jobs, and
runs ``audit_dependents.py`` as a subprocess with the job directory as its cwd
(so the crawler's cwd-relative artifacts — ``dependency_graph.json``,
``spdx_snippets/``, ``.idf_cache.json`` — land inside that job's directory).
A bounded thread pool caps how many audits run concurrently.

Config (env):
    JOBS_DIR            shared job directory              (default /data/jobs)
    WORKER_CONCURRENCY  max audits in flight              (default 2)
    POLL_INTERVAL       seconds between queue scans        (default 2.0)
    AUDIT_TIMEOUT       per-audit hard limit, seconds      (default 3600)
    JOB_TTL             delete finished jobs older than N seconds; 0 disables
    HEARTBEAT_FILE      touched each loop for healthchecks (default /tmp/worker.alive)
"""

import logging
import os
import signal
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import auditlib
from auditlib import JobStore

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s worker %(message)s",
)
log = logging.getLogger("worker")

JOBS_DIR = os.environ.get("JOBS_DIR", "/data/jobs")
CONCURRENCY = int(os.environ.get("WORKER_CONCURRENCY", "2"))
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "2.0"))
AUDIT_TIMEOUT = int(os.environ.get("AUDIT_TIMEOUT", "3600"))
JOB_TTL = int(os.environ.get("JOB_TTL", "0"))
HEARTBEAT_FILE = os.environ.get("HEARTBEAT_FILE", "/tmp/worker.alive")

_stop = threading.Event()


def _run_job(store, job_id):
    """Run one claimed job to a terminal state. Never raises."""
    payload = store.get_payload(job_id)
    if payload is None:
        store.update_meta(
            job_id,
            status=auditlib.STATUS_FAILED,
            error="payload missing",
            finished_at=time.time(),
        )
        return

    job_dir = store.job_dir(job_id)
    out_path = store.graph_path(job_id)
    try:
        argv = auditlib.build_argv(payload, out_path)
    except ValueError as exc:
        # Should have been caught at submit, but stay defensive.
        store.update_meta(
            job_id,
            status=auditlib.STATUS_FAILED,
            error=str(exc),
            finished_at=time.time(),
        )
        return

    env = auditlib.build_env(payload)
    log.info("start job=%s repo=%s depth=%s", job_id, payload.get("repo"), payload.get("depth"))
    started = time.time()
    try:
        proc = subprocess.run(
            argv,
            cwd=job_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=AUDIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        log.warning("timeout job=%s after %ss", job_id, AUDIT_TIMEOUT)
        store.write_stderr(job_id, f"audit exceeded {AUDIT_TIMEOUT}s time limit")
        store.update_meta(
            job_id,
            status=auditlib.STATUS_TIMEOUT,
            error=f"exceeded {AUDIT_TIMEOUT}s",
            finished_at=time.time(),
        )
        return
    except Exception as exc:  # pragma: no cover - defensive
        log.exception("crash job=%s", job_id)
        store.update_meta(
            job_id,
            status=auditlib.STATUS_FAILED,
            error=f"worker error: {exc}",
            finished_at=time.time(),
        )
        return

    if proc.returncode != 0:
        log.warning("fail job=%s rc=%s", job_id, proc.returncode)
        store.write_stderr(job_id, proc.stderr or "")
        store.update_meta(
            job_id,
            status=auditlib.STATUS_FAILED,
            error="crawler exited non-zero",
            returncode=proc.returncode,
            finished_at=time.time(),
        )
        return

    if not os.path.isfile(out_path):
        store.write_stderr(job_id, proc.stderr or "")
        store.update_meta(
            job_id,
            status=auditlib.STATUS_FAILED,
            error="crawler produced no graph",
            returncode=0,
            finished_at=time.time(),
        )
        return

    elapsed = round(time.time() - started, 1)
    log.info("done job=%s in %ss", job_id, elapsed)
    store.update_meta(
        job_id,
        status=auditlib.STATUS_SUCCEEDED,
        returncode=0,
        finished_at=time.time(),
    )


def _sweep_expired(store):
    if JOB_TTL <= 0:
        return
    now = time.time()
    for meta in store.list_metas(limit=10000):
        if meta.get("status") in auditlib.TERMINAL_STATUSES:
            finished = meta.get("finished_at") or 0
            if now - finished > JOB_TTL:
                store.delete(meta["id"])
                log.info("swept expired job=%s", meta["id"])


def _touch_heartbeat():
    try:
        with open(HEARTBEAT_FILE, "w") as f:
            f.write(str(time.time()))
    except OSError:
        pass


def main():
    store = JobStore(JOBS_DIR)
    log.info(
        "worker up jobs_dir=%s concurrency=%s timeout=%ss",
        JOBS_DIR, CONCURRENCY, AUDIT_TIMEOUT,
    )

    signal.signal(signal.SIGTERM, lambda *_: _stop.set())
    signal.signal(signal.SIGINT, lambda *_: _stop.set())

    inflight = set()
    lock = threading.Lock()

    def _done(job_id, fut):
        with lock:
            inflight.discard(job_id)

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        last_sweep = 0.0
        while not _stop.is_set():
            _touch_heartbeat()

            # Claim up to the remaining capacity.
            with lock:
                capacity = CONCURRENCY - len(inflight)
            if capacity > 0:
                for job_id in store.iter_queued_ids():
                    with lock:
                        if len(inflight) >= CONCURRENCY:
                            break
                        if job_id in inflight:
                            continue
                    if store.try_claim(job_id):
                        with lock:
                            inflight.add(job_id)
                        fut = pool.submit(_run_job, store, job_id)
                        fut.add_done_callback(
                            lambda f, jid=job_id: _done(jid, f)
                        )

            if JOB_TTL > 0 and time.time() - last_sweep > max(JOB_TTL, 60):
                _sweep_expired(store)
                last_sweep = time.time()

            _stop.wait(POLL_INTERVAL)

        log.info("draining: waiting for %d in-flight job(s)", len(inflight))
    log.info("worker stopped")


if __name__ == "__main__":
    main()
