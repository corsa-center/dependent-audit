"""Progress-event tests (``--events-file`` / ProgressEmitter).

Covers:
- The emitter is a no-op without a path, continues `seq` after lines the
  service already wrote, serializes sets, and never raises into the crawl.
- EventLogHandler mirrors WARNING+ records into the stream.
- Discovery emits phase events and a throttled `search_progress` counter.
- A stubbed orchestrator run emits the catalogue in the documented order.
- The service's OPTION_SPEC stays in sync with the crawler's argparse parser.

Plain-assert style, no external test deps. Run directly:
    python tests/test_progress_events.py
(also importable by pytest as test_* functions.)
"""

import json
import logging
import os
import sys
import tempfile
import types

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))  # works without `uv sync` too
sys.path.insert(0, os.path.join(_ROOT, "deploy", "service"))

from dependent_audit import audit_dependents as A

LOG = logging.getLogger("test")
LOG.addHandler(logging.NullHandler())


def _read(path):
    with open(path) as f:
        return [json.loads(line) for line in f]


def _tmpfile():
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    return path


def test_emitter_noop_without_path():
    ev = A.ProgressEmitter()
    assert not ev.enabled
    ev.emit("phase", phase="x")  # must not raise
    ev.close()
    print("PASS test_emitter_noop_without_path")


def test_emitter_continues_seq_and_serializes_sets():
    path = _tmpfile()
    with open(path, "w") as f:  # two service-written lifecycle lines
        f.write('{"seq":0,"type":"job"}\n{"seq":1,"type":"job"}\n')
    ev = A.ProgressEmitter(path)
    ev.emit("edge", identifiers={"b", "a"})
    ev.emit("result", complete=True)
    ev.close()
    lines = _read(path)
    assert [line["seq"] for line in lines] == [0, 1, 2, 3], lines
    assert lines[2]["src"] == "crawler" and lines[2]["type"] == "edge"
    assert lines[2]["data"]["identifiers"] == ["a", "b"]
    print("PASS test_emitter_continues_seq_and_serializes_sets")


def test_emitter_never_raises():
    # Unwritable path: disabled, not an exception.
    ev = A.ProgressEmitter("/nonexistent-dir/for/sure/events.jsonl")
    assert not ev.enabled
    ev.emit("phase")
    # A write failure mid-run disables it.
    path = _tmpfile()
    ev = A.ProgressEmitter(path)
    os.close(ev._fd)  # simulate the descriptor going bad
    ev.emit("phase")
    assert not ev.enabled
    print("PASS test_emitter_never_raises")


def test_log_handler_mirrors_warnings():
    path = _tmpfile()
    ev = A.ProgressEmitter(path)
    base = logging.getLogger("test-events-handler")
    base.setLevel(logging.INFO)
    base.addHandler(A.EventLogHandler(ev))
    log = A.ContextAdapter(base, {"depth": 1, "chain": ["a/root", "b/child"]})
    log.info("quiet")
    log.warning("loud", extra={"k": 1})
    log.warning("huge", extra={"blob": "x" * 5000})
    ev.close()
    lines = _read(path)
    assert [line["data"]["message"] for line in lines] == ["loud", "huge"], lines
    first = lines[0]["data"]
    assert first["repo"] == "b/child" and first["depth"] == 1
    assert first["extra"] == {"k": 1}
    assert lines[1]["data"]["extra"] is None  # oversized context dropped
    print("PASS test_log_handler_mirrors_warnings")


def _discovery_plugin(events, matches, clock=None):
    args = types.SimpleNamespace(
        sg_token="x",
        no_defaults=False,
        custom_string=None,
        custom_file=None,
        forks=False,
        include_archived=False,
        include_vendored=False,
        sg_delay=0.0,
        sg_count="5000",
        no_idf=True,
        idf_cache=None,
        idf_cap=300,
        declared_sources="",
    )
    p = A.CppSourcegraphPlugin(args)
    p.events = events
    idf = A.Identifier("zfp/zfp.h", A.IdentifierKind.HEADER_PATH, "header_scan", 3)
    p._compile_identifier_set = lambda *a, **k: A.IdentifierSet([idf])
    p._patterns_from = lambda idset, log=None, protected=frozenset(): [
        A.ConsumptionPattern(idf, r"zfp/zfp\.h", "header", 3.0)
    ]

    def stream(query, log):
        for i in range(matches):
            if clock is not None:
                clock[0] += 0.25
            yield {
                "type": "content",
                "repository": f"github.com/org/repo{i % 7}",
                "path": "src/a.c",
                "commit": "abc",
                "lineMatches": [{"line": '#include "zfp/zfp.h"'}],
                "chunkMatches": [{"content": '#include "zfp/zfp.h"'}],
            }

    p._stream_search = stream
    return p


def test_search_progress_is_throttled():
    path = _tmpfile()
    ev = A.ProgressEmitter(path)
    p = _discovery_plugin(ev, matches=5000)
    consumers = p.discover_dependents("github.com/LLNL/zfp", "zfp", "HEAD", LOG)
    ev.close()
    assert len(consumers) == 7
    lines = _read(path)
    progress = [line for line in lines if line["type"] == "search_progress"]
    finals = [line for line in progress if line["data"]["final"]]
    assert len(progress) < 10, len(progress)
    assert len(finals) == 1 and finals[0]["data"]["matches"] == 5000
    assert finals[0]["data"]["consumers"] == 7
    phases = [
        (line["data"]["phase"], line["data"]["state"])
        for line in lines
        if line["type"] == "phase"
    ]
    assert phases == [
        ("identifiers", "start"),
        ("identifiers", "end"),
        ("specificity", "start"),
        ("specificity", "end"),
        ("search", "start"),
        ("search", "end"),
        ("scoring", "start"),
        ("scoring", "end"),
    ], phases
    print("PASS test_search_progress_is_throttled")


def test_search_progress_ticks_with_time():
    path = _tmpfile()
    ev = A.ProgressEmitter(path)
    clock = [0.0]
    real = A.time.monotonic
    A.time.monotonic = lambda: clock[0]
    try:
        p = _discovery_plugin(ev, matches=20, clock=clock)  # 5 simulated seconds
        p.discover_dependents("github.com/LLNL/zfp", "zfp", "HEAD", LOG)
    finally:
        A.time.monotonic = real
    ev.close()
    ticks = [
        line
        for line in _read(path)
        if line["type"] == "search_progress" and not line["data"]["final"]
    ]
    assert 4 <= len(ticks) <= 5, len(ticks)
    counts = [t["data"]["matches"] for t in ticks]
    assert counts == sorted(counts) and counts[-1] <= 20, counts
    print("PASS test_search_progress_ticks_with_time")


def _stub_orchestrator(events):
    args = types.SimpleNamespace(
        repo="LLNL/zfp",
        name="zfp",
        depth=1,
        ecosystem="cpp",
        sg_count="5000",
        email="t@example.com",
        gh_token=None,
        no_citations=True,
        academic_keyword=None,
        citation_depth=1,
        paper_cache="",
        out=_tmpfile(),
    )
    real_init = A.JOSSPublicationPlugin.initialize
    A.JOSSPublicationPlugin.initialize = lambda self: None  # no network
    try:
        plugin = types.SimpleNamespace(
            search_incomplete=False,
            search_warnings=[],
            discover_dependents=lambda *a: [
                {"name": "github.com/LLNL/zfp", "oid": "s", "url": "u"},  # self
                {
                    "name": "github.com/a/one",
                    "oid": "s1",
                    "url": "https://github.com/a/one",
                    "confidence": "high",
                    "confidenceScore": 9.0,
                    "relationship": "DEPENDS_ON",
                    "evidenceLayer": 3,
                    "identifiers": ["zfp.h"],
                    "matchCount": 4,
                },
                {
                    "name": "github.com/b/two",
                    "oid": "s2",
                    "url": "https://github.com/b/two",
                    "confidence": "low",
                    "confidenceScore": 1.0,
                    "matchCount": 1,
                },
            ],
        )
        orch = A.AuditOrchestrator(args, plugin, LOG, events=events)
    finally:
        A.JOSSPublicationPlugin.initialize = real_init

    def build(
        repo_name, label, owner, type, depth, url, sha, log, rel_path="", discovery=None
    ):
        return {
            "id": repo_name,
            "label": label,
            "type": type,
            "data": {
                "depth": depth,
                "commitSha": sha,
                "stars": 3,
                "papers": [{"relation": "seminal", "relevanceTier": "high"}],
                "paperDiagnostics": {"complete": True},
                "confidence": (discovery or {}).get("confidence"),
                "isFork": False,
            },
        }

    orch._build_node_data = build
    orch.spdx.generate_snippet = lambda *a, **k: "spdx_snippets/x.spdx.json"
    orch.citations.save = lambda: None
    return orch, args


def test_orchestrator_event_order():
    path = _tmpfile()
    ev = A.ProgressEmitter(path)
    orch, args = _stub_orchestrator(ev)
    orch.run()
    ev.close()
    lines = _read(path)
    types_ = [line["type"] for line in lines if line["type"] != "phase"]
    assert types_ == [
        "run_started",
        "node",
        "node_start",
        "candidates",
        "enrich_progress",
        "node",
        "edge",
        "enrich_progress",
        "node",
        "edge",
        "result",
    ], types_
    started = lines[0]["data"]
    assert started["eventsVersion"] == 1 and started["citations"] is False
    assert "sg_token" not in json.dumps(started) and "gh_token" not in json.dumps(
        started
    )
    cands = next(line for line in lines if line["type"] == "candidates")["data"]
    assert cands["total"] == 2  # self-edge removed
    assert [c["id"] for c in cands["batch"]] == ["a/one", "b/two"]  # strongest first
    root = next(line for line in lines if line["type"] == "node")["data"]
    assert root["papers"] == {"total": 1, "seminal": 1, "high": 1}
    result = lines[-1]["data"]
    graph = json.load(open(args.out))
    assert result["nodes"] == len(graph["nodes"]) == 3
    assert result["edges"] == len(graph["edges"]) == 2
    assert result["complete"] == graph["meta"]["completeness"]["complete"]
    print("PASS test_orchestrator_event_order")


def test_option_spec_matches_parser():
    """Every crawler flag is either exposed by the service form, a secret, a
    server-only setting, or owned by the service. Catches drift both ways."""
    import auditlib

    dests = {a.dest for a in A.build_parser()._actions if a.dest != "help"}
    owned = {"out", "events_file"}
    accounted = (
        set(auditlib.OPTIONS_BY_KEY)
        | set(auditlib.TOKEN_ENV)
        | auditlib.SERVER_ONLY
        | owned
    )
    assert dests - accounted == set(), f"unmapped crawler flags: {dests - accounted}"
    assert accounted - dests == set(), f"stale service keys: {accounted - dests}"
    flags = {
        a.dest: a.option_strings[0]
        for a in A.build_parser()._actions
        if a.option_strings
    }
    for key, opt in auditlib.OPTIONS_BY_KEY.items():
        assert flags[key] == opt["flag"], (key, flags[key], opt["flag"])
    print("PASS test_option_spec_matches_parser")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nALL PROGRESS-EVENT TESTS PASSED")
