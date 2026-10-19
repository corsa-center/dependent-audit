"""Tests for the progress-event log and the streaming worker path.

Covers ``auditlib.append_event`` / ``tail_events`` (resume, partial lines,
heartbeats, corrupt lines, deletion) and the worker's Popen lifecycle: event
ordering, live log, cancel, timeout, and the stale-job sweep.

Plain-assert style, no external test deps (does not import flask). Run directly:
    python deploy/service/tests/test_events.py
(also importable by pytest as test_* functions.)
"""

import json
import os
import sys
import tempfile
import textwrap
import threading
import time

_SVC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.dirname(os.path.dirname(_SVC))
sys.path.insert(0, _SVC)

os.environ.setdefault("WAIT_TICK", "0.05")
os.environ.setdefault("KILL_GRACE", "2")

import auditlib
import worker

FAKE_AUDIT = os.path.join(_ROOT, "deploy", "ci", "fake_audit.py")


def _tmp():
    return tempfile.mkdtemp()


def _events(path):
    with open(path) as f:
        return [json.loads(line) for line in f]


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def test_append_event_seq_is_line_index():
    path = os.path.join(_tmp(), "events.jsonl")
    for i in range(3):
        auditlib.append_event(path, "job", "web", status=f"s{i}")
    evs = _events(path)
    assert [e["seq"] for e in evs] == [0, 1, 2]
    assert evs[1]["data"] == {"status": "s1"} and evs[1]["src"] == "web"
    assert auditlib.count_lines(path) == 3
    assert auditlib.read_last_event(path)["data"]["status"] == "s2"
    # Unwritable path: swallowed.
    auditlib.append_event("/nonexistent/dir/x.jsonl", "job", "web")
    print("PASS test_append_event_seq_is_line_index")


def test_tail_resume_and_corrupt_lines():
    path = os.path.join(_tmp(), "events.jsonl")
    with open(path, "w") as f:
        f.write('{"type":"a"}\nNOT JSON\n{"type":"c"}\n')
    clock = FakeClock()
    got = list(
        auditlib.tail_events(
            path, 0, max_seconds=1, clock=clock, sleep=clock.sleep, heartbeat=100
        )
    )
    assert [(i, (e or {}).get("type")) for i, _raw, e in got] == [
        (0, "a"),
        (1, None),
        (2, "c"),
    ], got
    resumed = list(
        auditlib.tail_events(
            path, 2, max_seconds=1, clock=clock, sleep=clock.sleep, heartbeat=100
        )
    )
    assert [i for i, _r, _e in resumed] == [2]
    print("PASS test_tail_resume_and_corrupt_lines")


def test_tail_buffers_partial_line_and_heartbeats():
    path = os.path.join(_tmp(), "events.jsonl")
    with open(path, "w") as f:
        f.write('{"type":"a"}\n{"type":')  # second line incomplete
    clock = FakeClock()
    completed = []

    def sleep(s):
        clock.sleep(s)
        if clock.t >= 3 and not completed:
            with open(path, "a") as f:
                f.write('"b"}\n')
            completed.append(True)

    out = []
    for item in auditlib.tail_events(
        path, 0, poll=1, heartbeat=2, max_seconds=6, clock=clock, sleep=sleep
    ):
        out.append("HB" if item is auditlib.HEARTBEAT else item[2]["type"])
    assert out[0] == "a" and "b" in out, out
    assert out.index("HB") < out.index("b"), out  # idle heartbeat came first
    print("PASS test_tail_buffers_partial_line_and_heartbeats")


def test_tail_stops_when_file_deleted_or_missing():
    assert list(auditlib.tail_events("/nonexistent/events.jsonl")) == []
    path = os.path.join(_tmp(), "events.jsonl")
    with open(path, "w") as f:
        f.write('{"type":"a"}\n')
    clock = FakeClock()

    def sleep(s):
        clock.sleep(s)
        if os.path.exists(path):
            os.remove(path)

    got = list(
        auditlib.tail_events(
            path, 0, clock=clock, sleep=sleep, heartbeat=100, max_seconds=100
        )
    )
    assert len(got) == 1 and clock.t < 100
    print("PASS test_tail_stops_when_file_deleted_or_missing")


def _store():
    return auditlib.JobStore(os.path.join(_tmp(), "jobs"))


def _submit(store, **extra):
    payload = auditlib.normalize(
        {"repo": "LLNL/zfp", "name": "zfp", "depth": 1, **extra}
    )
    auditlib.validate(payload)
    meta = store.create(payload)
    assert store.try_claim(meta["id"])
    return meta["id"]


def test_worker_streams_events_in_order():
    os.environ["FAKE_AUDIT_DELAY"] = "0"
    auditlib.AUDIT_SCRIPT = FAKE_AUDIT
    store = _store()
    jid = _submit(store)
    worker._run_job(store, jid)
    evs = _events(store.events_path(jid))
    assert [e["seq"] for e in evs] == list(range(len(evs))), "seq must be line index"
    srcs = [e["src"] for e in evs]
    assert srcs[0] == "web" and srcs[1] == "worker" and srcs[-1] == "worker"
    assert set(srcs[2:-1]) == {"crawler"}
    statuses = [e["data"]["status"] for e in evs if e["type"] == "job"]
    assert statuses == ["queued", "running", "succeeded"], statuses
    types = [e["type"] for e in evs]
    for t in ("run_started", "search_progress", "candidates", "node", "edge", "result"):
        assert t in types, t
    assert store.get_meta(jid)["status"] == "succeeded"
    assert os.path.getsize(store.log_path(jid)) > 0  # crawler log captured
    print("PASS test_worker_streams_events_in_order")


def test_worker_meta_updated_before_terminal_event():
    """A client reacting to the terminal event must find the graph ready."""
    os.environ["FAKE_AUDIT_DELAY"] = "0"
    auditlib.AUDIT_SCRIPT = FAKE_AUDIT
    store = _store()
    jid = _submit(store)
    seen = {}
    real_append = store.append_event

    def spy(job_id, type_, src, **data):
        if type_ == "job" and data.get("status") in auditlib.TERMINAL_STATUSES:
            seen["meta_status"] = store.get_meta(job_id)["status"]
        real_append(job_id, type_, src, **data)

    store.append_event = spy
    worker._run_job(store, jid)
    assert seen["meta_status"] == "succeeded", seen
    print("PASS test_worker_meta_updated_before_terminal_event")


def test_worker_failure_keeps_log():
    os.environ["FAKE_AUDIT_DELAY"] = "0"
    os.environ["FAKE_AUDIT_FAIL"] = "1"
    auditlib.AUDIT_SCRIPT = FAKE_AUDIT
    try:
        store = _store()
        jid = _submit(store)
        worker._run_job(store, jid)
    finally:
        del os.environ["FAKE_AUDIT_FAIL"]
    meta = store.get_meta(jid)
    assert meta["status"] == "failed" and meta["returncode"] == 3, meta
    assert "failing on request" in store.read_log_tail(jid)
    types = [e["type"] for e in _events(store.events_path(jid))]
    assert "error" in types and types[-1] == "job"
    print("PASS test_worker_failure_keeps_log")


def _sleeper(tmp):
    path = os.path.join(tmp, "sleeper.py")
    with open(path, "w") as f:
        f.write(
            textwrap.dedent("""
            import sys, time
            print("sleeper started", file=sys.stderr, flush=True)
            time.sleep(60)
        """)
        )
    return path


def test_worker_cancel_kills_crawler():
    tmp = _tmp()
    auditlib.AUDIT_SCRIPT = _sleeper(tmp)
    store = _store()
    jid = _submit(store)
    t = threading.Thread(target=worker._run_job, args=(store, jid))
    t0 = time.time()
    t.start()
    time.sleep(0.5)
    assert "sleeper started" in (store.read_log_tail(jid) or ""), "log must stream live"
    store.request_cancel(jid)
    t.join(timeout=10)
    assert not t.is_alive() and time.time() - t0 < 10
    assert store.get_meta(jid)["status"] == "cancelled"
    assert _events(store.events_path(jid))[-1]["data"]["status"] == "cancelled"
    print("PASS test_worker_cancel_kills_crawler")


def test_worker_timeout():
    tmp = _tmp()
    auditlib.AUDIT_SCRIPT = _sleeper(tmp)
    store = _store()
    jid = _submit(store)
    old = worker.AUDIT_TIMEOUT
    worker.AUDIT_TIMEOUT = 0
    try:
        worker._run_job(store, jid)
    finally:
        worker.AUDIT_TIMEOUT = old
    assert store.get_meta(jid)["status"] == "timeout"
    assert _events(store.events_path(jid))[-1]["data"]["status"] == "timeout"
    print("PASS test_worker_timeout")


def test_stale_sweep_fails_orphaned_running_job():
    store = _store()
    jid = _submit(store)  # claimed -> running, but no worker is running it
    old = time.time() - 3600
    os.utime(os.path.join(store.job_dir(jid), auditlib.CLAIMED_SENTINEL), (old, old))
    worker._sweep_stale(store, inflight=set())
    meta = store.get_meta(jid)
    assert meta["status"] == "failed" and meta["error"] == "worker lost", meta
    # A job this worker is actively running is never swept.
    jid2 = _submit(store)
    os.utime(os.path.join(store.job_dir(jid2), auditlib.CLAIMED_SENTINEL), (old, old))
    worker._sweep_stale(store, inflight={jid2})
    assert store.get_meta(jid2)["status"] == "running"
    print("PASS test_stale_sweep_fails_orphaned_running_job")


def test_pinned_flags_and_server_only_keys():
    payload = auditlib.normalize(
        {
            "repo": "a/b",
            "name": "b",
            "idf_cache": "/etc/passwd",
            "config": "/etc/shadow",
            "relevance_llm_url": "http://evil",
        }
    )
    argv = auditlib.build_argv(payload, "/out.json", events_file="/e.jsonl")
    joined = " ".join(argv)
    assert "/etc/passwd" not in joined and "/etc/shadow" not in joined
    assert "http://evil" not in joined
    # Always explicitly claimed, so a target repo's config can't set them.
    for flag in ("--idf-cache", "--paper-cache", "--relevance-llm-url"):
        assert flag in argv, flag
    assert argv[argv.index("--events-file") + 1] == "/e.jsonl"
    assert "--config" not in argv
    print("PASS test_pinned_flags_and_server_only_keys")


def test_payload_tokens_gate():
    os.environ["ALLOW_PAYLOAD_TOKENS"] = "0"
    try:
        try:
            auditlib.validate({"repo": "a/b", "name": "b", "sg_token": "x"})
            raise AssertionError("expected rejection")
        except ValueError as e:
            assert "disabled" in str(e)
        env = auditlib.build_env({"sg_token": "x"}, base_env={"SG_TOKEN": "server"})
        assert env["SG_TOKEN"] == "server"
    finally:
        del os.environ["ALLOW_PAYLOAD_TOKENS"]
    assert auditlib.redact({"sg_token": "x", "repo": "a", "idf_cache": "p"}) == {
        "sg_token": "***",
        "repo": "a",
    }
    print("PASS test_payload_tokens_gate")


def test_option_validation():
    for bad, needle in [
        ({"sg_count": "lots"}, "sg_count"),
        ({"paper_relevance_floor": "extreme"}, "one of"),
        ({"depth": -1}, ">= 0"),
        ({"ecosystem": "rust"}, "one of"),
    ]:
        try:
            auditlib.validate({"repo": "a/b", "name": "b", **bad})
            raise AssertionError(f"expected failure for {bad}")
        except ValueError as e:
            assert needle in str(e), (bad, str(e))
    auditlib.validate(
        {
            "repo": "a/b",
            "name": "b",
            "sg_count": "all",
            "no_citations": True,
            "citation_depth": 2,
        }
    )
    print("PASS test_option_validation")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nALL EVENT/WORKER TESTS PASSED")
