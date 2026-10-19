"""Background worker: drains queued audit jobs and runs the crawler.

Polls the shared :class:`auditlib.JobStore`, atomically claims queued jobs, and
runs ``audit_dependents.py`` as a subprocess with the job directory as its cwd
(so the crawler's cwd-relative artifacts — ``dependency_graph.json``,
``spdx_snippets/``, ``.idf_cache.json`` — land inside that job's directory).
A bounded thread pool caps how many audits run concurrently.

Progress: the crawler is launched with ``--events-file <job>/events.jsonl`` and
appends structured progress events there; the worker appends the lifecycle
events (``running`` before launch, the terminal status after the crawler has
exited). The writers never overlap in time, so the file needs no locking. The
crawler's log streams to ``<job>/stderr.log`` while it runs.

Config (env):
    JOBS_DIR            shared job directory              (default /data/jobs)
    WORKER_CONCURRENCY  max audits in flight              (default 2)
    POLL_INTERVAL       seconds between queue scans        (default 2.0)
    AUDIT_TIMEOUT       per-audit hard limit, seconds      (default 3600)
    JOB_TTL             delete finished jobs older than N seconds; 0 disables
    STALE_AFTER         mark a running job failed when its per-job heartbeat is
                        older than N seconds (worker died)  (default 300)
    HEARTBEAT_FILE      touched each loop for healthchecks (default /tmp/worker.alive)
"""

import logging
import os
import signal
import socket
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
STALE_AFTER = int(os.environ.get("STALE_AFTER", "300"))
HEARTBEAT_FILE = os.environ.get("HEARTBEAT_FILE", "/tmp/worker.alive")
# How often the wait loop checks for cancel/timeout and refreshes the per-job
# heartbeat. Seconds; overridable for tests.
WAIT_TICK = float(os.environ.get("WAIT_TICK", "1.0"))
KILL_GRACE = float(os.environ.get("KILL_GRACE", "10"))

_stop = threading.Event()


def _finish(store, job_id, status, started=None, **fields):
    """Record a terminal state: meta FIRST (so /graph is already servable when
    a client sees the event), then the terminal lifecycle event."""
    now = time.time()
    store.update_meta(job_id, status=status, finished_at=now, **fields)
    store.append_event(
        job_id,
        "job",
        "worker",
        status=status,
        returncode=fields.get("returncode"),
        error=fields.get("error"),
        elapsedSec=round(now - started, 1) if started else None,
    )


def _kill_group(proc):
    """Stop the crawler and anything it spawned (it runs in its own session)."""
    for sig, grace in ((signal.SIGTERM, KILL_GRACE), (signal.SIGKILL, None)):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            continue


def _run_job(store, job_id):
    """Run one claimed job to a terminal state. Never raises."""
    payload = store.get_payload(job_id)
    if payload is None:
        _finish(store, job_id, auditlib.STATUS_FAILED, error="payload missing")
        return

    job_dir = store.job_dir(job_id)
    out_path = store.graph_path(job_id)
    try:
        argv = auditlib.build_argv(
            payload, out_path, events_file=store.events_path(job_id)
        )
    except ValueError as exc:
        # Should have been caught at submit, but stay defensive.
        _finish(store, job_id, auditlib.STATUS_FAILED, error=str(exc))
        return

    env = auditlib.build_env(payload)
    log.info(
        "start job=%s repo=%s depth=%s",
        job_id,
        payload.get("repo"),
        payload.get("depth"),
    )
    started = time.time()
    store.append_event(
        job_id, "job", "worker", status=auditlib.STATUS_RUNNING, startedAt=started
    )
    deadline = started + AUDIT_TIMEOUT
    outcome = None  # None | "timeout" | "cancelled"
    try:
        with open(store.log_path(job_id), "ab", buffering=0) as logf:
            proc = subprocess.Popen(
                argv,
                cwd=job_dir,
                env=env,
                stdout=logf,
                stderr=logf,
                start_new_session=True,
            )
            while True:
                try:
                    proc.wait(timeout=WAIT_TICK)
                    break
                except subprocess.TimeoutExpired:
                    pass
                store.touch_claim(job_id)
                if store.cancel_requested(job_id):
                    outcome = "cancelled"
                elif time.time() > deadline:
                    outcome = "timeout"
                if outcome:
                    _kill_group(proc)
                    break
    except Exception as exc:  # pragma: no cover - defensive
        log.exception("crash job=%s", job_id)
        _finish(
            store, job_id, auditlib.STATUS_FAILED, started, error=f"worker error: {exc}"
        )
        return

    if outcome == "cancelled":
        log.info("cancelled job=%s", job_id)
        _finish(
            store,
            job_id,
            auditlib.STATUS_CANCELLED,
            started,
            error="cancelled by request",
        )
        return
    if outcome == "timeout":
        log.warning("timeout job=%s after %ss", job_id, AUDIT_TIMEOUT)
        store.write_stderr(job_id, f"\naudit exceeded {AUDIT_TIMEOUT}s time limit\n")
        _finish(
            store,
            job_id,
            auditlib.STATUS_TIMEOUT,
            started,
            error=f"exceeded {AUDIT_TIMEOUT}s",
        )
        return

    if proc.returncode != 0:
        log.warning("fail job=%s rc=%s", job_id, proc.returncode)
        _finish(
            store,
            job_id,
            auditlib.STATUS_FAILED,
            started,
            error="crawler exited non-zero",
            returncode=proc.returncode,
        )
        return

    if not os.path.isfile(out_path):
        _finish(
            store,
            job_id,
            auditlib.STATUS_FAILED,
            started,
            error="crawler produced no graph",
            returncode=0,
        )
        return

    log.info("done job=%s in %ss", job_id, round(time.time() - started, 1))
    _finish(store, job_id, auditlib.STATUS_SUCCEEDED, started, returncode=0)


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


def _sweep_stale(store, inflight):
    """Fail `running` jobs whose worker died (per-job heartbeat went stale).

    The heartbeat is the claimed sentinel's mtime, refreshed every WAIT_TICK by
    whichever worker replica owns the job, so this is safe with replicas. A
    dead worker means its crawler is dead too (single host), so appending the
    terminal event cannot race a live writer."""
    for meta in store.list_metas(limit=10000):
        job_id = meta.get("id")
        if meta.get("status") != auditlib.STATUS_RUNNING or job_id in inflight:
            continue
        age = store.claim_age(job_id)
        if age is not None and age > STALE_AFTER:
            log.warning(
                "stale job=%s (heartbeat %ss old); marking failed", job_id, int(age)
            )
            _finish(
                store,
                job_id,
                auditlib.STATUS_FAILED,
                meta.get("started_at"),
                error="worker lost",
            )


def _touch_heartbeat(store, inflight_count):
    try:
        with open(HEARTBEAT_FILE, "w") as f:
            f.write(str(time.time()))
    except OSError:
        pass
    # Shared liveness/config summary for the web tier's /api/health. Token
    # *presence* only — the values never leave the worker.
    store.write_worker_state(
        {
            "lastSeen": time.time(),
            "host": socket.gethostname(),
            "concurrency": CONCURRENCY,
            "inflight": inflight_count,
            "sgToken": bool(os.environ.get("SG_TOKEN")),
            "ghToken": bool(os.environ.get("GH_TOKEN")),
            "auditTimeout": AUDIT_TIMEOUT,
        }
    )


def main():
    store = JobStore(JOBS_DIR)
    log.info(
        "worker up jobs_dir=%s concurrency=%s timeout=%ss",
        JOBS_DIR,
        CONCURRENCY,
        AUDIT_TIMEOUT,
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
            with lock:
                _touch_heartbeat(store, len(inflight))
                capacity = CONCURRENCY - len(inflight)

            # Claim up to the remaining capacity.
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
                        fut.add_done_callback(lambda f, jid=job_id: _done(jid, f))

            if time.time() - last_sweep > 60:
                with lock:
                    snapshot = set(inflight)
                _sweep_stale(store, snapshot)
                _sweep_expired(store)
                last_sweep = time.time()

            _stop.wait(POLL_INTERVAL)

        log.info("draining: waiting for %d in-flight job(s)", len(inflight))
    log.info("worker stopped")


if __name__ == "__main__":
    main()
