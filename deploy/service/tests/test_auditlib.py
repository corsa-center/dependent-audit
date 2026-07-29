"""Unit tests for the service's payload mapping and job store.

Plain-assert style, no external test deps (does not import flask). Run directly:
    python deploy/service/tests/test_auditlib.py
(also importable by pytest as test_* functions.)
"""

import os
import sys
import tempfile
import textwrap
import threading

# Make the service modules importable regardless of cwd.
_SVC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _SVC)

import auditlib  # noqa: E402


def test_normalize_and_truthy():
    assert auditlib.normalize({"academic-keyword": "x"}) == {"academic_keyword": "x"}
    assert auditlib.truthy(True) and auditlib.truthy("yes") and auditlib.truthy("1")
    assert not auditlib.truthy("no") and not auditlib.truthy(False) and not auditlib.truthy("")
    print("PASS test_normalize_and_truthy")


def test_build_argv_maps_every_kind():
    payload = auditlib.normalize({
        "repo": "LLNL/zfp", "name": "zfp", "depth": 2, "ecosystem": "cpp",
        "declared-sources": "spack", "sg_delay": 0.5, "idf_cap": 300,
        "verbose": True, "no_idf": False, "include_vendored": True,
        "sg_count": "5000", "out": "/ignored",
    })
    argv = auditlib.build_argv(payload, "/work/graph.json")
    # service owns --out; client value dropped
    assert argv[argv.index("--out") + 1] == "/work/graph.json"
    assert "/ignored" not in argv
    # true flag present, false flag absent
    assert "--verbose" in argv and "--no-idf" not in argv
    assert "--include-vendored" in argv
    assert argv[argv.index("--depth") + 1] == "2"
    assert argv[argv.index("--sg-delay") + 1] == "0.5"
    assert argv[argv.index("--declared-sources") + 1] == "spack"
    print("PASS test_build_argv_maps_every_kind")


def test_validation_errors():
    for bad, needle in [
        ({}, "required"),
        ({"repo": "a", "name": "b", "bogus": 1}, "unknown"),
        ({"repo": "a", "name": "b", "depth": "x"}, "integer"),
        ({"repo": "a", "name": "b", "sg_delay": "nope"}, "number"),
    ]:
        try:
            auditlib.validate(auditlib.normalize(bad))
            raise AssertionError(f"expected failure for {bad}")
        except ValueError as e:
            assert needle in str(e), (bad, str(e))
    print("PASS test_validation_errors")


def test_tokens_go_to_env_not_argv():
    payload = auditlib.normalize({"repo": "a/b", "name": "b",
                                  "sg_token": "SG", "gh_token": "GH"})
    argv = auditlib.build_argv(payload, "/x")
    assert "SG" not in argv and "GH" not in argv
    env = auditlib.build_env(payload, base_env={})
    assert env["SG_TOKEN"] == "SG" and env["GH_TOKEN"] == "GH"
    print("PASS test_tokens_go_to_env_not_argv")


def _fake_crawler(tmp):
    path = os.path.join(tmp, "fake.py")
    with open(path, "w") as f:
        f.write(textwrap.dedent('''
            import sys, os, json
            out = sys.argv[sys.argv.index("--out")+1]
            os.makedirs("spdx_snippets", exist_ok=True)
            open(os.path.join("spdx_snippets","x.spdx.json"),"w").write("{}")
            json.dump({"meta":{"root":sys.argv[sys.argv.index("--repo")+1],
                               "sg":os.environ.get("SG_TOKEN")},
                       "nodes":[],"edges":[]}, open(out,"w"))
        '''))
    return path


def test_jobstore_lifecycle_and_atomic_claim():
    import worker  # imports auditlib only, no flask

    tmp = tempfile.mkdtemp()
    store = auditlib.JobStore(os.path.join(tmp, "jobs"))
    auditlib.AUDIT_SCRIPT = _fake_crawler(tmp)

    payload = auditlib.normalize({"repo": "LLNL/zfp", "name": "zfp",
                                  "depth": 1, "sg_token": "SECRET"})
    auditlib.validate(payload)
    meta = store.create(payload)
    jid = meta["id"]
    assert meta["status"] == auditlib.STATUS_QUEUED
    assert list(store.iter_queued_ids()) == [jid]

    # Exactly one of many concurrent claimers wins.
    winners = []
    def race():
        if store.try_claim(jid):
            winners.append(1)
    ts = [threading.Thread(target=race) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(winners) == 1, f"expected one winner, got {sum(winners)}"
    assert store.get_meta(jid)["status"] == auditlib.STATUS_RUNNING
    assert list(store.iter_queued_ids()) == []

    # The worker runs the (fake) crawler to success; token reached it via env.
    worker._run_job(store, jid)
    m = store.get_meta(jid)
    assert m["status"] == auditlib.STATUS_SUCCEEDED, m
    import json
    graph = json.load(open(store.graph_path(jid)))
    assert graph["meta"]["root"] == "LLNL/zfp"
    assert graph["meta"]["sg"] == "SECRET"
    assert os.listdir(store.snippets_dir(jid))

    # Failure path: crawler exits non-zero.
    bad = os.path.join(tmp, "bad.py")
    open(bad, "w").write("import sys; sys.exit(3)")
    auditlib.AUDIT_SCRIPT = bad
    m2 = store.create(auditlib.normalize({"repo": "a/b", "name": "b"}))
    store.try_claim(m2["id"])
    worker._run_job(store, m2["id"])
    fm = store.get_meta(m2["id"])
    assert fm["status"] == auditlib.STATUS_FAILED and fm["returncode"] == 3, fm

    assert len(store.list_metas()) == 2
    assert store.delete(jid) and store.get_meta(jid) is None
    print("PASS test_jobstore_lifecycle_and_atomic_claim")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nALL SERVICE UNIT TESTS PASSED")
