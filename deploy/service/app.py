"""HTTP API for the dependent-audit service.

Submit an audit as a job, follow its live progress over Server-Sent Events,
then fetch/download the result. The crawl runs in a separate worker container,
so deep/long searches never hold a request thread for the crawl itself.

    POST   /api/jobs               -> 202 {id, status, links}      (enqueue)
    GET    /api/jobs               -> {jobs: [...]}                (recent jobs)
    GET    /api/jobs/<id>          -> {meta, params, links}        (status)
    GET    /api/jobs/<id>/events   -> text/event-stream            (live progress)
    GET    /api/jobs/<id>/graph    -> dependency graph JSON         (?download=1)
    GET    /api/jobs/<id>/spdx     -> SPDX snippets zip
    GET    /api/jobs/<id>/spdx/<f> -> one SPDX snippet
    GET    /api/jobs/<id>/log      -> crawler log tail (text)
    POST   /api/jobs/<id>/cancel   -> 202
    DELETE /api/jobs/<id>          -> 204
    GET    /api/options            -> the submit-form schema
    GET    /api/health             -> web + worker liveness

The pre-/api routes (POST /audit, /jobs/...) remain as deprecated aliases. The
request payload mirrors the ``audit_dependents.py`` CLI flags (see
deploy/README.md). The web tier only validates, enqueues and serves files; the
worker runs the crawler. They share an :class:`auditlib.JobStore` volume.
"""

import io
import os
import re
import threading
import time
import zipfile

import auditlib
from auditlib import JobStore
from flask import Flask, Response, jsonify, request, send_file, url_for

app = Flask(__name__)

JOBS_DIR = os.environ.get("JOBS_DIR", "/data/jobs")
store = JobStore(JOBS_DIR)

# SSE budget (gunicorn gthread): each open stream holds one thread. Cap streams
# per process so ordinary requests always have threads left, and bound each
# stream's lifetime — EventSource reconnects with Last-Event-ID and resumes.
SSE_MAX_STREAMS = int(os.environ.get("SSE_MAX_STREAMS", "12"))
SSE_MAX_SECONDS = float(os.environ.get("SSE_MAX_SECONDS", "60"))
SSE_HEARTBEAT = float(os.environ.get("SSE_HEARTBEAT", "15"))
SSE_POLL = float(os.environ.get("SSE_POLL", "0.5"))
_sse_slots = threading.BoundedSemaphore(SSE_MAX_STREAMS)

WORKER_STALE_SECONDS = 60
_JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _links(job_id):
    return {
        "self": url_for("get_job", job_id=job_id),
        "events": url_for("job_events", job_id=job_id),
        "graph": url_for("get_job_graph", job_id=job_id),
        "spdx": url_for("get_job_spdx", job_id=job_id),
        "log": url_for("get_job_log", job_id=job_id),
    }


def _meta_or_404(job_id):
    if not _JOB_ID_RE.match(job_id or ""):
        return None
    return store.get_meta(job_id)


def _not_found():
    return jsonify(error="unknown job"), 404


def _worker_health():
    state = store.read_worker_state() or {}
    last = state.get("lastSeen")
    alive = bool(last) and time.time() - last < WORKER_STALE_SECONDS
    return {
        "alive": alive,
        "lastSeen": last,
        "concurrency": state.get("concurrency"),
        "inflight": state.get("inflight"),
        "sgToken": bool(state.get("sgToken")),
        "ghToken": bool(state.get("ghToken")),
        "auditTimeout": state.get("auditTimeout"),
    }


# ---------------------------------------------------------------------------
# Health / options
# ---------------------------------------------------------------------------


@app.get("/health")
def health():
    ok = os.path.isfile(auditlib.AUDIT_SCRIPT) and os.path.isdir(JOBS_DIR)
    return jsonify(status="ok" if ok else "degraded"), (200 if ok else 503)


@app.get("/api/health")
def api_health():
    ok = os.path.isfile(auditlib.AUDIT_SCRIPT) and os.path.isdir(JOBS_DIR)
    body = {"status": "ok" if ok else "degraded", "worker": _worker_health()}
    return jsonify(body), (200 if ok else 503)


@app.get("/api/options")
def get_options():
    return jsonify(
        options=auditlib.public_options(),
        allowPayloadTokens=auditlib.payload_tokens_allowed(),
    )


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


def submit_audit():
    if not request.is_json:
        return jsonify(error="request body must be application/json"), 415

    payload = auditlib.normalize(request.get_json(silent=True) or {})
    try:
        auditlib.validate(payload)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    # Server-only keys are accepted for back-compat but never stored/forwarded.
    payload = {k: v for k, v in payload.items() if k not in auditlib.SERVER_ONLY}

    meta = store.create(payload)
    body = {**meta, "links": _links(meta["id"])}
    resp = jsonify(body)
    resp.status_code = 202
    resp.headers["Location"] = url_for("get_job", job_id=meta["id"])
    return resp


def list_jobs():
    limit = max(1, min(request.args.get("limit", default=100, type=int), 1000))
    jobs = []
    for meta in store.list_metas(limit=limit):
        entry = dict(meta)
        if meta.get("status") not in auditlib.TERMINAL_STATUSES:
            entry["lastEvent"] = store.last_event(meta["id"])
        jobs.append(entry)
    return jsonify(jobs=jobs)


def get_job(job_id):
    meta = _meta_or_404(job_id)
    if meta is None:
        return _not_found()
    body = {
        **meta,
        "params": auditlib.redact(store.get_payload(job_id) or {}),
        "hasGraph": os.path.isfile(store.graph_path(job_id)),
        "hasSpdx": _has_snippets(job_id),
        "links": _links(job_id),
    }
    return jsonify(body)


def get_job_graph(job_id):
    meta = _meta_or_404(job_id)
    if meta is None:
        return _not_found()
    if meta["status"] != auditlib.STATUS_SUCCEEDED:
        # 409: the resource isn't ready in this state (still running, or failed).
        return jsonify(error="graph not available", status=meta["status"]), 409
    path = store.graph_path(job_id)
    if not os.path.isfile(path):
        return jsonify(error="graph missing"), 500
    download = auditlib.truthy(request.args.get("download", ""))
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", meta.get("repo") or job_id)
    return send_file(
        path,
        mimetype="application/json",
        as_attachment=download,
        download_name=f"{slug}_dependency_graph.json",
    )


def _has_snippets(job_id):
    snippets = store.snippets_dir(job_id)
    return os.path.isdir(snippets) and bool(os.listdir(snippets))


def get_job_spdx(job_id):
    meta = _meta_or_404(job_id)
    if meta is None:
        return _not_found()
    if not _has_snippets(job_id):
        return jsonify(
            error="no spdx snippets for this job", status=meta["status"]
        ), 404
    snippets = store.snippets_dir(job_id)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(snippets):
            for fname in files:
                full = os.path.join(root, fname)
                arc = os.path.join(
                    auditlib.SNIPPETS_DIR, os.path.relpath(full, snippets)
                )
                zf.write(full, arc)
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"spdx_snippets_{job_id}.zip",
    )


_SNIPPET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.spdx\.json$")


@app.get("/api/jobs/<job_id>/spdx/<name>")
def get_job_spdx_snippet(job_id, name):
    """One edge's SPDX snippet (a node's `snippetPath` basename)."""
    if _meta_or_404(job_id) is None:
        return _not_found()
    if not _SNIPPET_RE.match(name):
        return jsonify(error="invalid snippet name"), 400
    path = os.path.join(store.snippets_dir(job_id), name)
    if not os.path.isfile(path):
        return jsonify(error="no such snippet"), 404
    return send_file(
        path, mimetype="application/json", as_attachment=False, download_name=name
    )


@app.get("/api/jobs/<job_id>/log")
def get_job_log(job_id):
    if _meta_or_404(job_id) is None:
        return _not_found()
    lines = max(1, min(request.args.get("tail", default=200, type=int), 5000))
    text = store.read_log_tail(job_id, lines=lines)
    return Response(text or "", mimetype="text/plain")


@app.post("/api/jobs/<job_id>/cancel")
def cancel_job(job_id):
    meta = _meta_or_404(job_id)
    if meta is None:
        return _not_found()
    status = meta.get("status")
    if status in auditlib.TERMINAL_STATUSES:
        return jsonify(error="job already finished", status=status), 409
    # Still queued: claim it ourselves so no worker picks it up, and finish it.
    if store.try_claim(job_id, status=auditlib.STATUS_CANCELLED):
        store.update_meta(job_id, finished_at=time.time(), error="cancelled by request")
        store.append_event(
            job_id,
            "job",
            "web",
            status=auditlib.STATUS_CANCELLED,
            error="cancelled by request",
        )
        return jsonify(id=job_id, status=auditlib.STATUS_CANCELLED), 202
    # Running: ask the owning worker to stop the crawl.
    store.request_cancel(job_id)
    return jsonify(id=job_id, status="cancelling"), 202


def delete_job(job_id):
    meta = _meta_or_404(job_id)
    if meta is None:
        return _not_found()
    if meta.get("status") == auditlib.STATUS_RUNNING:
        return jsonify(error="job is running; cancel it first"), 409
    store.delete(job_id)
    return "", 204


# ---------------------------------------------------------------------------
# Live progress (Server-Sent Events)
# ---------------------------------------------------------------------------


def _resume_from():
    """Index of the first event the client has not seen yet."""
    raw = request.headers.get("Last-Event-ID") or request.args.get("lastEventId")
    try:
        return int(raw) + 1
    except (TypeError, ValueError):
        return 0


@app.get("/api/jobs/<job_id>/events")
def job_events(job_id):
    meta = _meta_or_404(job_id)
    if meta is None:
        return _not_found()
    start = _resume_from()
    if meta.get("status") in auditlib.TERMINAL_STATUSES and start >= store.event_count(
        job_id
    ):
        # Nothing left to send. 204 tells EventSource to stop reconnecting.
        return "", 204

    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    if not _sse_slots.acquire(blocking=False):
        # Over budget: an empty stream with a long retry, so the browser backs
        # off and resumes later (a non-200 would make EventSource give up).
        return Response(
            "retry: 10000\n\n", mimetype="text/event-stream", headers=headers
        )

    path = store.events_path(job_id)

    def gen():
        try:
            yield "retry: 3000\n\n"
            for item in auditlib.tail_events(
                path,
                start,
                poll=SSE_POLL,
                heartbeat=SSE_HEARTBEAT,
                max_seconds=SSE_MAX_SECONDS,
            ):
                if item is auditlib.HEARTBEAT:
                    yield ": hb\n\n"
                    continue
                idx, raw, ev = item
                if ev is None:
                    continue  # corrupt line: skip, but its index is consumed
                yield f"id: {idx}\ndata: {raw}\n\n"
                if auditlib.is_terminal_event(ev):
                    return
        finally:
            _sse_slots.release()

    return Response(gen(), mimetype="text/event-stream", headers=headers)


# ---------------------------------------------------------------------------
# Routing: /api (current) + legacy aliases (deprecated).
# ---------------------------------------------------------------------------

app.add_url_rule("/api/jobs", "submit_audit", submit_audit, methods=["POST"])
app.add_url_rule("/api/jobs", "list_jobs", list_jobs, methods=["GET"])
app.add_url_rule("/api/jobs/<job_id>", "get_job", get_job, methods=["GET"])
app.add_url_rule("/api/jobs/<job_id>", "delete_job", delete_job, methods=["DELETE"])
app.add_url_rule("/api/jobs/<job_id>/graph", "get_job_graph", get_job_graph)
app.add_url_rule("/api/jobs/<job_id>/spdx", "get_job_spdx", get_job_spdx)

_LEGACY = [
    ("/audit", submit_audit, ["POST"], "/api/jobs"),
    ("/jobs", list_jobs, ["GET"], "/api/jobs"),
    ("/jobs/<job_id>", get_job, ["GET"], "/api/jobs/{job_id}"),
    ("/jobs/<job_id>", delete_job, ["DELETE"], "/api/jobs/{job_id}"),
    ("/jobs/<job_id>/graph", get_job_graph, ["GET"], "/api/jobs/{job_id}/graph"),
    ("/jobs/<job_id>/spdx", get_job_spdx, ["GET"], "/api/jobs/{job_id}/spdx"),
]
_SUCCESSORS = {}
for _rule, _view, _methods, _successor in _LEGACY:
    _endpoint = f"legacy_{_view.__name__}"
    app.add_url_rule(_rule, _endpoint, _view, methods=_methods)
    _SUCCESSORS[_endpoint] = _successor


@app.after_request
def _mark_deprecated(resp):
    successor = _SUCCESSORS.get(request.endpoint or "")
    if successor:
        resp.headers["Deprecation"] = "true"
        resp.headers["Link"] = (
            f"<{successor.format(**(request.view_args or {}))}>; "
            'rel="successor-version"'
        )
    return resp


if __name__ == "__main__":
    # Dev entrypoint only; production is served by gunicorn.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), threaded=True)
