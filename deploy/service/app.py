"""Async HTTP API for the dependent-audit tool.

Submit an audit as a job, then poll for its result — the crawl runs in a
separate worker container, so deep/long searches never hold an HTTP connection
open.

    POST /audit            -> 202 {id, status, links}         (enqueue)
    GET  /jobs             -> [ {meta}, ... ]                  (recent jobs)
    GET  /jobs/<id>        -> {meta}                           (poll status)
    GET  /jobs/<id>/graph  -> the dependency graph JSON        (when succeeded)
    GET  /jobs/<id>/spdx   -> the SPDX snippets as a zip       (when present)
    DELETE /jobs/<id>      -> 204                              (discard a job)
    GET  /health           -> liveness

The request payload mirrors the ``audit_dependents.py`` CLI flags one-for-one
(see deploy/README.md). The web tier only validates and enqueues; the worker
runs the crawler. They share a :class:`auditlib.JobStore` on a common volume.
"""

import io
import os
import zipfile

from flask import Flask, jsonify, request, send_file, url_for

import auditlib
from auditlib import JobStore

app = Flask(__name__)

JOBS_DIR = os.environ.get("JOBS_DIR", "/data/jobs")
store = JobStore(JOBS_DIR)


def _links(job_id):
    return {
        "self": url_for("get_job", job_id=job_id),
        "graph": url_for("get_job_graph", job_id=job_id),
        "spdx": url_for("get_job_spdx", job_id=job_id),
    }


@app.get("/health")
def health():
    ok = os.path.isfile(auditlib.AUDIT_SCRIPT) and os.path.isdir(JOBS_DIR)
    return jsonify(status="ok" if ok else "degraded"), (200 if ok else 503)


@app.post("/audit")
def submit_audit():
    if not request.is_json:
        return jsonify(error="request body must be application/json"), 415

    payload = auditlib.normalize(request.get_json(silent=True) or {})
    try:
        auditlib.validate(payload)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    meta = store.create(payload)
    body = {**meta, "links": _links(meta["id"])}
    resp = jsonify(body)
    resp.status_code = 202
    resp.headers["Location"] = url_for("get_job", job_id=meta["id"])
    return resp


@app.get("/jobs")
def list_jobs():
    limit = request.args.get("limit", default=100, type=int)
    return jsonify(jobs=store.list_metas(limit=limit))


@app.get("/jobs/<job_id>")
def get_job(job_id):
    meta = store.get_meta(job_id)
    if meta is None:
        return jsonify(error="unknown job"), 404
    return jsonify({**meta, "links": _links(job_id)})


@app.get("/jobs/<job_id>/graph")
def get_job_graph(job_id):
    meta = store.get_meta(job_id)
    if meta is None:
        return jsonify(error="unknown job"), 404
    if meta["status"] != auditlib.STATUS_SUCCEEDED:
        # 409: the resource isn't ready in this state (still running, or failed).
        return jsonify(error="graph not available", status=meta["status"]), 409
    path = store.graph_path(job_id)
    if not os.path.isfile(path):
        return jsonify(error="graph missing"), 500
    return send_file(path, mimetype="application/json", as_attachment=False)


@app.get("/jobs/<job_id>/spdx")
def get_job_spdx(job_id):
    meta = store.get_meta(job_id)
    if meta is None:
        return jsonify(error="unknown job"), 404
    snippets = store.snippets_dir(job_id)
    if not os.path.isdir(snippets) or not os.listdir(snippets):
        return jsonify(error="no spdx snippets for this job", status=meta["status"]), 404
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


@app.delete("/jobs/<job_id>")
def delete_job(job_id):
    if store.get_meta(job_id) is None:
        return jsonify(error="unknown job"), 404
    store.delete(job_id)
    return "", 204


if __name__ == "__main__":
    # Dev entrypoint only; production is served by gunicorn.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
