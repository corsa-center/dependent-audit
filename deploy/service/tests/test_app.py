"""HTTP-level tests for app.py (Flask test client).

Covers the /api routes, the SSE stream (framing, resume, terminal 204), the
legacy aliases' deprecation headers, cancel/delete rules, redaction, and that
/api/options never exposes secrets or server-only keys.

Skipped (not failed) when flask is not installed. Run directly:
    python deploy/service/tests/test_app.py
(also importable by pytest as test_* functions.)
"""

import json
import os
import sys
import tempfile

_SVC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.dirname(os.path.dirname(_SVC))
sys.path.insert(0, _SVC)

try:
    import flask
except ImportError:  # pragma: no cover
    flask = None

if flask is not None:
    os.environ["JOBS_DIR"] = tempfile.mkdtemp()
    os.environ["SSE_MAX_SECONDS"] = "2"
    os.environ["SSE_POLL"] = "0.05"
    os.environ["WAIT_TICK"] = "0.05"
    os.environ["FAKE_AUDIT_DELAY"] = "0"
    import app as appmod
    import auditlib
    import worker

    auditlib.AUDIT_SCRIPT = os.path.join(_ROOT, "deploy", "ci", "fake_audit.py")
    client = appmod.app.test_client()


def _skip():
    if flask is None:
        print("SKIP (flask not installed)")
        return True
    return False


def _submit(body=None):
    resp = client.post(
        "/api/jobs",
        json=body or {"repo": "LLNL/zfp", "name": "zfp", "sg_token": "SECRET"},
    )
    assert resp.status_code == 202, resp.get_json()
    return resp.get_json()["id"]


def _run(job_id):
    assert appmod.store.try_claim(job_id)
    worker._run_job(appmod.store, job_id)


def _sse(resp):
    """Parse an SSE body into [(id, data_dict)] (comments/retry skipped)."""
    out = []
    for block in resp.get_data(as_text=True).split("\n\n"):
        fields = dict(
            line.split(": ", 1)
            for line in block.splitlines()
            if ": " in line and not line.startswith(":")
        )
        if "data" in fields:
            out.append((int(fields["id"]), json.loads(fields["data"])))
    return out


def test_submit_get_and_redaction():
    if _skip():
        return
    jid = _submit()
    body = client.get(f"/api/jobs/{jid}").get_json()
    assert body["status"] == "queued" and body["params"]["sg_token"] == "***"
    assert body["links"]["events"] == f"/api/jobs/{jid}/events"
    assert client.get(f"/api/jobs/{jid}/graph").status_code == 409
    listing = client.get("/api/jobs").get_json()["jobs"]
    assert listing[0]["id"] == jid and listing[0]["lastEvent"]["type"] == "job"
    assert client.get("/api/jobs/not-a-real-id").status_code == 404
    assert client.post("/api/jobs", json={"name": "x"}).status_code == 400
    assert (
        client.post("/api/jobs", data="x", content_type="text/plain").status_code == 415
    )
    print("PASS test_submit_get_and_redaction")


def test_sse_stream_resume_and_terminal():
    if _skip():
        return
    jid = _submit()
    _run(jid)
    resp = client.get(f"/api/jobs/{jid}/events")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/event-stream")
    assert resp.headers["X-Accel-Buffering"] == "no"
    events = _sse(resp)
    ids = [i for i, _ in events]
    assert ids == list(range(len(ids))), ids
    types = [e["type"] for _, e in events]
    assert "edge" in types and events[-1][1]["data"]["status"] == "succeeded"
    # Resume from id 2 -> first event is 3.
    resumed = _sse(
        client.get(f"/api/jobs/{jid}/events", headers={"Last-Event-ID": "2"})
    )
    assert resumed[0][0] == 3
    # Query-param resume (manual reconnect path) works too.
    assert _sse(client.get(f"/api/jobs/{jid}/events?lastEventId=4"))[0][0] == 5
    # Fully caught up on a finished job: 204 stops EventSource reconnecting.
    last = ids[-1]
    assert (
        client.get(
            f"/api/jobs/{jid}/events", headers={"Last-Event-ID": str(last)}
        ).status_code
        == 204
    )
    print("PASS test_sse_stream_resume_and_terminal")


def test_graph_download_and_spdx():
    if _skip():
        return
    jid = _submit()
    _run(jid)
    resp = client.get(f"/api/jobs/{jid}/graph")
    assert resp.status_code == 200 and resp.get_json()["meta"]["root"] == "LLNL/zfp"
    assert "attachment" not in resp.headers.get("Content-Disposition", "")
    dl = client.get(f"/api/jobs/{jid}/graph?download=1")
    assert "attachment" in dl.headers["Content-Disposition"]
    assert "LLNL_zfp_dependency_graph.json" in dl.headers["Content-Disposition"]
    spdx = client.get(f"/api/jobs/{jid}/spdx")
    assert spdx.status_code == 200 and spdx.mimetype == "application/zip"
    graph = resp.get_json()
    snippet = next(
        n["data"]["snippetPath"] for n in graph["nodes"] if n["data"].get("snippetPath")
    )
    one = client.get(f"/api/jobs/{jid}/spdx/{os.path.basename(snippet)}")
    assert one.status_code == 200 and one.get_json()["spdxVersion"] == "SPDX-2.3"
    assert client.get(f"/api/jobs/{jid}/spdx/..%2Fmeta.json").status_code in (400, 404)
    assert client.get(f"/api/jobs/{jid}/spdx/meta.json").status_code == 400
    assert client.get(f"/api/jobs/{jid}/spdx/missing.spdx.json").status_code == 404
    log = client.get(f"/api/jobs/{jid}/log?tail=5")
    assert log.status_code == 200 and log.mimetype == "text/plain"
    print("PASS test_graph_download_and_spdx")


def test_cancel_and_delete_rules():
    if _skip():
        return
    jid = _submit()
    resp = client.post(f"/api/jobs/{jid}/cancel")
    assert resp.status_code == 202 and resp.get_json()["status"] == "cancelled"
    assert client.get(f"/api/jobs/{jid}").get_json()["status"] == "cancelled"
    assert client.post(f"/api/jobs/{jid}/cancel").status_code == 409
    # Running jobs can't be deleted; they get a cancel request instead.
    jid2 = _submit()
    appmod.store.try_claim(jid2)
    assert client.delete(f"/api/jobs/{jid2}").status_code == 409
    r = client.post(f"/api/jobs/{jid2}/cancel")
    assert r.get_json()["status"] == "cancelling" and appmod.store.cancel_requested(
        jid2
    )
    assert client.delete(f"/api/jobs/{jid}").status_code == 204
    assert client.get(f"/api/jobs/{jid}").status_code == 404
    print("PASS test_cancel_and_delete_rules")


def test_legacy_aliases_are_deprecated():
    if _skip():
        return
    resp = client.post("/audit", json={"repo": "a/b", "name": "b"})
    assert resp.status_code == 202 and resp.headers["Deprecation"] == "true"
    jid = resp.get_json()["id"]
    got = client.get(f"/jobs/{jid}")
    assert got.status_code == 200
    assert got.headers["Link"] == f'</api/jobs/{jid}>; rel="successor-version"'
    assert "Deprecation" not in client.get(f"/api/jobs/{jid}").headers
    assert client.get("/health").status_code == 200
    print("PASS test_legacy_aliases_are_deprecated")


def test_options_and_health():
    if _skip():
        return
    body = client.get("/api/options").get_json()
    keys = {o["key"] for o in body["options"]}
    assert {"repo", "name", "depth", "no_citations"} <= keys
    assert not keys & (set(auditlib.TOKEN_ENV) | auditlib.SERVER_ONLY)
    health = client.get("/api/health").get_json()
    assert health["worker"]["alive"] is False  # no worker heartbeat in tests
    appmod.store.write_worker_state(
        {"lastSeen": __import__("time").time(), "sgToken": True, "ghToken": False}
    )
    worker_h = client.get("/api/health").get_json()["worker"]
    assert worker_h["alive"] and worker_h["sgToken"] and not worker_h["ghToken"]
    print("PASS test_options_and_health")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nALL APP TESTS PASSED" if flask is not None else "\nAPP TESTS SKIPPED")
