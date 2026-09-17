"""Identifier-set tests.

Covers:
- Stable signal kinds (find_package / pkg_config / pragma_lib) unchanged.
- Phase 1a: IDF specificity gating + repo-slug VCS references.
- Phase 1b: repo-wide header discovery, include-path normalization, namespace +
  basename identifiers (the protobuf/absl/gtest recall fix), invariant basename
  patterns, structural/owned gating exemptions.
- Phase 2: real CMake package/target/artifact, pkg-config module, and Bazel
  module identifiers extracted from the provider's build files.

Plain-assert style, no external test deps. Run directly:
    python tests/test_identifier_set.py
(also importable by pytest as test_* functions.)
"""

import json
import logging
import os
import re
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_dependents as A  # noqa: E402

LOG = logging.getLogger("test")
LOG.addHandler(logging.NullHandler())
K = A.IdentifierKind
HP, HB = K.HEADER_PATH, K.HEADER_BASENAME
CT, CP, PC, BM, LA = (
    K.CMAKE_TARGET,
    K.CMAKE_PACKAGE,
    K.PKGCONFIG,
    K.BAZEL_MODULE,
    K.LIB_ARTIFACT,
)


def _plugin(no_defaults=False, custom_string=None, no_idf=True):
    args = types.SimpleNamespace(
        sg_token="x",
        no_defaults=no_defaults,
        custom_string=custom_string,
        custom_file=None,
        forks=False,
        include_archived=False,
        include_vendored=False,
        sg_delay=0.0,
        sg_count="5000",
        no_idf=no_idf,
        idf_cache=None,
        idf_cap=300,
        declared_sources="",
    )
    return A.CppSourcegraphPlugin(args)


def _prep(plugin, headers=None, build_paths=None, cmake="", bazel="", modules=None):
    """Stub all provider-file discovery so compilation touches no network."""
    plugin._discover_header_paths = lambda *a, **k: list(headers or [])
    plugin._discover_build_paths = lambda *a, **k: list(build_paths or [])
    plugin._fetch_build_blobs = lambda *a, **k: {"cmake": cmake, "bazel": bazel}
    plugin._extract_module_identifiers = lambda *a, **k: [
        A.Identifier(m, K.MODULE_NAME, "module_unit", A.KIND_WEIGHTS[K.MODULE_NAME])
        for m in (modules or [])
    ]
    return plugin


def _by_kind(ids):
    out = {}
    for i in ids:
        out.setdefault(i.kind, set()).add(i.value)
    return out


def _include_patterns(plugin, idset, protected=frozenset()):
    return [
        re.compile(p.regex, re.I)
        for p in plugin._patterns_from(idset, LOG, protected)
        if p.evidence == "include"
    ]


# --- normalization / header recall -----------------------------------------


def test_include_path_normalization():
    f = A.CppSourcegraphPlugin._include_path
    assert f("src/google/protobuf/message.h") == "google/protobuf/message.h"
    assert f("googletest/include/gtest/gtest.h") == "gtest/gtest.h"
    assert f("absl/strings/str_cat.h") == "absl/strings/str_cat.h"
    assert f("include/zfp.h") == "zfp.h"
    assert f("zfp.h") == "zfp.h"
    assert f("inc/foo/bar.hpp") == "foo/bar.hpp"
    print("PASS test_include_path_normalization")


def test_header_identifiers_fix_recall():
    plugin = _prep(
        _plugin(no_idf=True),
        headers=[
            "src/google/protobuf/message.h",
            "absl/strings/str_cat.h",
            "googletest/include/gtest/gtest.h",
            "include/zfp.h",
            "include/zfp/array.hpp",
        ],
    )
    idset = plugin._compile_identifier_set("owner/repo", "proj", LOG)
    ns = {i.value for i in idset if i.kind == HP}
    for expect in ("google/protobuf", "absl/strings", "gtest", "zfp"):
        assert expect in ns, f"missing namespace {expect}: {ns}"

    pats = _include_patterns(plugin, idset)

    def hit(line):
        return any(rx.search(line) for rx in pats)

    assert hit("#include <google/protobuf/message.h>")
    assert hit("#include <absl/strings/str_cat.h>")
    assert hit("#include <gtest/gtest.h>")
    assert hit('#include "zfp/array.hpp"')
    assert hit("#include <zfp.h>")
    print("PASS test_header_identifiers_fix_recall")


def test_invariant_basename_pattern():
    plugin = _plugin(no_idf=True)
    idf = A.Identifier("zfp.h", HB, "x", 2)
    rx = re.compile(plugin._patterns_for_identifier(idf)[0][0], re.I)
    assert rx.search("#include <zfp.h>")
    assert rx.search("#include <foo/bar/zfp.h>")
    assert not rx.search("#include <libzfp.h>")
    assert not rx.search("#include <zfpx.h>")
    print("PASS test_invariant_basename_pattern")


# --- IDF gating ------------------------------------------------------------


def test_gating_structural_and_owned():
    plugin = _prep(
        _plugin(no_idf=False),
        headers=[
            "src/google/protobuf/message.h",  # multi-component ns -> exempt
            "include/utils/helper.h",  # single-component ns 'utils' -> gated
            "include/config.h",  # basename 'config.h' -> gated
            "include/gtest/gtest.h",  # ns 'gtest' + basename, owned
        ],
    )
    plugin.specificity.enabled = True
    plugin.specificity._probe = lambda regex, log: 10_000
    plugin.specificity.cache = {}

    idset = plugin._compile_identifier_set("owner/repo", "gtest", LOG)
    vals = {
        (p.identifier.kind, p.identifier.value)
        for p in plugin._patterns_from(idset, LOG, {"gtest"})
    }
    assert (HP, "google/protobuf") in vals, "multi-component ns must be exempt"
    assert (HP, "gtest") in vals, "provider-owned single ns must be kept"
    assert (HB, "gtest.h") in vals, "provider-owned basename must be kept"
    assert (HP, "utils") not in vals, "generic single ns must be dropped"
    assert (HB, "config.h") not in vals, "generic basename must be dropped"
    print("PASS test_gating_structural_and_owned")


def test_idf_scales_kept_weight():
    plugin = _prep(_plugin(no_idf=False), headers=["include/zfp.h"])
    plugin.specificity.enabled = True
    plugin.specificity._probe = lambda regex, log: 30
    plugin.specificity.cache = {}
    idset = plugin._compile_identifier_set("owner/repo", "other", LOG)
    zfp = next(
        p
        for p in plugin._patterns_from(idset, LOG, {"other"})
        if p.identifier.value == "zfp.h"
    )
    assert abs(zfp.weight - 2 * (1 - 30 / 300)) < 1e-9, zfp.weight
    print("PASS test_idf_scales_kept_weight")


def test_stable_signals_unchanged():
    plugin = _prep(_plugin(no_idf=True), headers=["include/zfp.h"])
    idset = plugin._compile_identifier_set("owner/repo", "zfp", LOG)
    pats = {p.evidence: p.regex for p in plugin._patterns_from(idset, LOG)}
    assert pats["find_package"] == "find_package\\s*\\(\\s*[zZ][fF][pP][\\s)]"
    assert pats["pkg_config"] == "pkg_check_modules\\s*\\([^)]*\\b[zZ][fF][pP]\\b"
    assert (
        pats["pragma_lib"]
        == "pragma\\s+comment\\s*\\(\\s*lib\\s*,\\s*\\x22.*zfp.*\\x22\\s*\\)"
    )
    print("PASS test_stable_signals_unchanged")


# --- VCS -------------------------------------------------------------------


def test_vcs_ref_never_gated_and_matches():
    plugin = _prep(_plugin(no_idf=False))
    plugin.specificity.enabled = True
    plugin.specificity._probe = lambda regex, log: 10_000
    plugin.specificity.cache = {}

    idset = plugin._compile_identifier_set("github.com/LLNL/zfp", "zfp", LOG)
    vcs = [
        (p.regex, p.weight)
        for p in plugin._patterns_from(idset, LOG)
        if p.evidence == "vcs_ref"
    ]
    assert vcs
    for _, w in vcs:
        assert w == A.KIND_WEIGHTS[K.REPO_SLUG]
    compiled = [re.compile(rx, re.IGNORECASE) for rx, _ in vcs]

    def matches(line):
        return any(rx.search(line) for rx in compiled)

    assert matches("url = https://github.com/LLNL/zfp.git")
    assert matches('  GIT_REPOSITORY "https://github.com/LLNL/zfp"')
    assert matches('CPMAddPackage("gh:LLNL/zfp@1.0.0")')
    assert not matches("https://github.com/someone/other")
    print("PASS test_vcs_ref_never_gated_and_matches")


# --- Phase 2: build-system identifiers -------------------------------------


def test_cmake_package_and_pkgconfig_from_filenames():
    plugin = _prep(
        _plugin(no_idf=True),
        build_paths=["cmake/zfpConfig.cmake.in", "libzfp.pc.in", "Foo-config.cmake"],
    )
    byk = _by_kind(plugin._extract_build_identifiers("owner/repo", LOG))
    assert byk.get(CP) == {"zfp", "Foo"}, byk.get(CP)
    assert byk.get(PC) == {"libzfp"}, byk.get(PC)
    print("PASS test_cmake_package_and_pkgconfig_from_filenames")


def test_cmake_content_parsing():
    plugin = _plugin(no_idf=True)
    cmake = (
        "cmake_minimum_required(VERSION 3.10)\n"
        "project(zfp VERSION 1.0 LANGUAGES C CXX)\n"
        "add_library(zfp SHARED src/zfp.c)\n"
        "add_library(zfp::zfp ALIAS zfp)\n"
        "install(EXPORT zfpTargets NAMESPACE zfp:: DESTINATION lib/cmake/zfp)\n"
    )
    byk = _by_kind(plugin._parse_cmake(cmake))
    assert byk.get(CP) == {"zfp"}, byk.get(CP)
    assert "zfp::zfp" in byk.get(CT, set())
    assert "zfp::" in byk.get(CT, set())
    assert byk.get(LA) == {"zfp"}, byk.get(LA)
    print("PASS test_cmake_content_parsing")


def test_cmake_target_patterns():
    plugin = _plugin(no_idf=True)
    ns = A.Identifier("zfp::", CT, "x", 5)
    full = A.Identifier("zfp::zfp", CT, "x", 5)
    rx_ns = re.compile(plugin._patterns_for_identifier(ns)[0][0])
    rx_full = re.compile(plugin._patterns_for_identifier(full)[0][0])
    assert rx_ns.search("target_link_libraries(app PRIVATE zfp::codec)")
    assert rx_full.search("target_link_libraries(app PRIVATE zfp::zfp)")
    assert not rx_ns.search("some_other_symbol")
    print("PASS test_cmake_target_patterns")


def test_bazel_module_and_patterns():
    plugin = _plugin(no_idf=True)
    ids = plugin._parse_bazel('module(name = "abseil-cpp", version = "20240116")')
    assert len(ids) == 1 and ids[0].kind == BM and ids[0].value == "abseil-cpp"
    pats = [re.compile(rx) for rx, _ in plugin._patterns_for_identifier(ids[0])]

    def hit(line):
        return any(p.search(line) for p in pats)

    assert hit('bazel_dep(name = "abseil-cpp", version = "20240116")')
    assert hit('deps = ["@abseil-cpp//absl/strings"]')
    assert not hit('bazel_dep(name = "something-else")')
    print("PASS test_bazel_module_and_patterns")


def test_build_ids_survive_idf_saturation():
    plugin = _prep(
        _plugin(no_idf=False),
        build_paths=["cmake/FooConfig.cmake.in"],
        bazel='module(name = "foo")',
    )
    plugin.specificity.enabled = True
    plugin.specificity._probe = lambda regex, log: 10_000  # would drop gated tokens
    plugin.specificity.cache = {}
    idset = plugin._compile_identifier_set("owner/repo", "foo", LOG)
    kinds = {
        p.identifier.kind for p in plugin._patterns_from(idset, LOG, {"foo"})
    }
    assert CP in kinds, "cmake package must survive (ungated)"
    assert BM in kinds, "bazel module must survive (ungated)"
    print("PASS test_build_ids_survive_idf_saturation")


# --- Phase 3: corroboration scoring + relationship -------------------------


def test_score_consumer():
    p = _plugin()
    assert p._score_consumer({}, 0) == (0.0, "unknown")
    # exact-identity vcs alone -> high
    assert p._score_consumer({K.REPO_SLUG: 6}, 1)[1] == "high"
    # a single namespaced-header signal -> medium
    assert p._score_consumer({HP: 3}, 1)[1] == "medium"
    # a single weak (IDF-scaled) basename -> low
    assert p._score_consumer({HB: 1.0}, 1)[1] == "low"
    # corroboration across two independent kinds lifts to high
    score, tier = p._score_consumer({HB: 2, CP: 5}, 4)
    assert tier == "high" and score >= 5.5, (score, tier)
    print("PASS test_score_consumer")


# --- Phase A: evidence-layer scoring ---------------------------------------


def test_evidence_layers():
    p = _plugin()
    assert p._evidence_layers({HP: 3}) == [A.LAYER_SOURCE]
    assert p._evidence_layers({CP: 5}) == [A.LAYER_BUILD]
    # two source-layer kinds collapse to a single layer
    assert p._evidence_layers({HP: 3, HB: 2}) == [A.LAYER_SOURCE]
    # cross-layer stays distinct and sorted
    assert p._evidence_layers({HB: 2, CP: 5}) == [A.LAYER_SOURCE, A.LAYER_BUILD]
    # a repo-slug/vcs reference is build-manifest, not source
    assert p._evidence_layers({K.REPO_SLUG: 6}) == [A.LAYER_BUILD]
    # the declared-registry pseudo-kind sits at the registry layer
    assert p._evidence_layers({"declared": 5.0}) == [A.LAYER_REGISTRY]
    # unknown kinds default to source-consumption
    assert p._evidence_layers({"mystery": 1}) == [A.LAYER_SOURCE]
    print("PASS test_evidence_layers")


def test_cross_layer_corroboration():
    p = _plugin()
    lone = p._score_consumer({HP: 3}, 1)[0]
    # Two same-layer signals do NOT corroborate (cross-reach de-dupe): the same
    # #include seen twice is one fact, not two.
    same = p._score_consumer({HP: 3, HB: 3}, 1)[0]
    assert same == lone, (same, lone)
    # Cross-layer (source + build) DOES corroborate: +CORROBORATION_BONUS.
    cross = p._score_consumer({HP: 3, CP: 3}, 1)[0]
    assert cross == round(lone + p.CORROBORATION_BONUS, 2), (cross, lone)
    print("PASS test_cross_layer_corroboration")


def test_narrative_only_capped_low():
    p = _plugin()
    orig = dict(A.EVIDENCE_LAYER)
    A.EVIDENCE_LAYER["prose"] = A.LAYER_NARRATIVE
    try:
        # A strong raw weight stays low when the only evidence is narrative.
        _, tier = p._score_consumer({"prose": 6}, 5)
        assert tier == "low", tier
        # A higher layer corroborating lifts it out of the cap.
        _, tier2 = p._score_consumer({"prose": 6, CP: 5}, 5)
        assert tier2 == "high", tier2
    finally:
        A.EVIDENCE_LAYER.clear()
        A.EVIDENCE_LAYER.update(orig)
    print("PASS test_narrative_only_capped_low")


def test_high_layer_outranks_lone_source():
    p = _plugin()
    orig = dict(A.EVIDENCE_LAYER)
    A.EVIDENCE_LAYER["soname"] = A.LAYER_BINARY
    try:
        # Equal raw weight: a lone binary/link (layer 5) edge outscores a lone
        # source-consumption (layer 2) edge by LAYER_WEIGHT[5], and clears a
        # higher tier — a real link beats an inferred #include.
        src_score, src_tier = p._score_consumer({HP: 4}, 1)
        bin_score, bin_tier = p._score_consumer({"soname": 4}, 1)
        assert bin_score == round(src_score + A.LAYER_WEIGHT[A.LAYER_BINARY], 2)
        assert bin_tier == "high" and src_tier == "medium", (bin_tier, src_tier)
    finally:
        A.EVIDENCE_LAYER.clear()
        A.EVIDENCE_LAYER.update(orig)
    print("PASS test_high_layer_outranks_lone_source")


def test_classify_relationship():
    p = _plugin()
    assert p._classify_relationship(4, 6) == "VENDORED"  # 0.67, enough headers
    assert p._classify_relationship(5, 5) == "VENDORED"  # full reproduction
    assert p._classify_relationship(1, 10) == "DEPENDS_ON"  # a few headers
    assert p._classify_relationship(2, 3) == "DEPENDS_ON"  # below min headers
    print("PASS test_classify_relationship")


# --- Phase 4: declared-dependent registries --------------------------------


def test_declared_alias_and_dependents():
    plugin = _plugin()
    plugin.args.declared_sources = "spack"

    def fake_manifest_paths(cfg, content_re, log, cap):
        if "depends_on" in content_re:
            return {"var/spack/repos/builtin/packages/h5z-zfp/package.py"}
        return {"var/spack/repos/builtin/packages/zfp/package.py"}

    plugin._registry_manifest_paths = fake_manifest_paths
    plugin._fetch_blobs = lambda repo, paths, log, **k: {
        p: 'git = "https://github.com/LLNL/H5Z-ZFP.git"' for p in paths
    }

    aliases = plugin._resolve_declared_aliases("github.com/LLNL/zfp", LOG)
    assert aliases == {"spack": {"zfp"}}, aliases

    deps = plugin._find_declared_dependents(aliases, LOG)
    assert any(d["name"] == "LLNL/H5Z-ZFP" for d in deps), deps
    print("PASS test_declared_alias_and_dependents")


def test_declared_merge_corroborates_and_injects():
    plugin = _plugin()
    plugin._find_declared_dependents = lambda aliases, log: [
        {"name": "a/existing", "url": "https://github.com/a/existing", "source": "spack"},
        {"name": "b/new", "url": "https://github.com/b/new", "source": "spack"},
    ]
    consumers = {
        "github.com/a/existing": {
            "name": "github.com/a/existing",
            "url": "https://github.com/a/existing",
            "oid": "x",
            "evidence": {"find_package": 1},
            "identifiers": {"zfp"},
            "kindWeights": {CP: 5.0},
            "matchedHeaders": set(),
            "provenance": {"convention"},
            "matchCount": 1,
        }
    }
    plugin._merge_declared_dependents(consumers, {"spack": {"zfp"}}, LOG)

    existing = consumers["github.com/a/existing"]
    assert existing["kindWeights"]["declared"] == 5.0
    assert "declared:spack" in existing["provenance"]
    assert "github.com/b/new" in consumers  # injected
    assert consumers["github.com/b/new"]["kindWeights"] == {"declared": 5.0}

    # scoring: corroborated (2 kinds) -> high; declared-only -> medium
    assert plugin._score_consumer({CP: 5.0, "declared": 5.0}, 2)[1] == "high"
    assert plugin._score_consumer({"declared": 5.0}, 0)[1] == "medium"
    print("PASS test_declared_merge_corroborates_and_injects")


# --- Phase 5: path-context weighting ---------------------------------------


def test_doc_path_detection():
    p = _plugin()
    assert p._is_doc_path("README.md")
    assert p._is_doc_path("docs/usage.rst")
    assert p._is_doc_path("doc/guide.adoc")
    assert not p._is_doc_path("CMakeLists.txt")  # .txt is build config
    assert not p._is_doc_path("src/foo.cpp")
    print("PASS test_doc_path_detection")


def _run_single_match(plugin, path, content, name="proj"):
    def sse(event, data):
        return [f"event: {event}", f"data: {json.dumps(data)}", ""]

    m = {
        "type": "content",
        "repository": "github.com/a/b",
        "commit": "x",
        "path": path,
        "chunkMatches": [{"content": content}],
    }
    lines = sse("matches", [m]) + sse("done", {})

    class S:
        status_code = 200
        headers = {}
        text = ""

        def iter_lines(self, decode_unicode=True):
            yield from lines

        def close(self):
            pass

    A.requests.get = lambda *a, **k: S()
    return plugin.discover_dependents("a/b_root", name, "HEAD", LOG)[0]


def test_doc_path_downweights():
    line = "#include <absl/strings/str_cat.h>"
    src = _run_single_match(
        _prep(_plugin(no_idf=True), headers=["absl/strings/str_cat.h"]),
        "src/x.cpp",
        line,
    )
    doc = _run_single_match(
        _prep(_plugin(no_idf=True), headers=["absl/strings/str_cat.h"]),
        "README.md",
        line,
    )
    assert doc["confidenceScore"] < src["confidenceScore"], (doc, src)
    assert src["confidence"] == "medium" and doc["confidence"] == "low"
    print("PASS test_doc_path_downweights")


# --- end to end ------------------------------------------------------------


def test_end_to_end_emits_identifiers():
    plugin = _prep(
        _plugin(no_idf=True), headers=["include/zfp.h", "include/zfp/array.hpp"]
    )

    def sse(event, data):
        return [f"event: {event}", f"data: {json.dumps(data)}", ""]

    def content(repo, commit, line):
        return {
            "type": "content",
            "repository": repo,
            "commit": commit,
            "chunkMatches": [{"content": line}],
        }

    lines = sse(
        "matches",
        [
            content("github.com/a/b", "aaa", "#include <zfp.h>"),
            content("github.com/a/b", "aaa", "find_package(ZFP REQUIRED)"),
        ],
    ) + sse("done", {})

    class Stream:
        status_code = 200
        headers = {}
        text = ""

        def iter_lines(self, decode_unicode=True):
            yield from lines

        def close(self):
            pass

    A.requests.get = lambda *a, **k: Stream()
    out = plugin.discover_dependents("a/b_root", "zfp", "HEAD", LOG)
    assert len(out) == 1
    c = out[0]
    assert c["evidence"] == {"include": 1, "find_package": 1}, c["evidence"]
    assert c["confidence"] == "high"
    assert c["identifiers"] == ["zfp", "zfp.h"], c["identifiers"]
    assert c["relationship"] == "DEPENDS_ON", c["relationship"]
    assert c["provenance"] == ["convention", "header_search"], c["provenance"]
    assert c["confidenceScore"] >= 5.5, c["confidenceScore"]
    # an #include (layer 2) + a find_package (layer 3) span two evidence layers
    assert c["layers"] == [2, 3], c["layers"]
    assert c["evidenceLayer"] == 3, c["evidenceLayer"]
    # internal accumulators are cleaned up before returning
    assert "kindWeights" not in c and "matchedHeaders" not in c
    print("PASS test_end_to_end_emits_identifiers")


def test_regexp_literal_slash_delimits_and_escapes():
    # Regression: a combined alternation dropped into the query bare makes
    # Sourcegraph reject it ("unclear parentheses") and return 0 consumers.
    # Wrapping in a slash-delimited regexp literal disambiguates it; only
    # unescaped '/' is escaped, and existing escape pairs are preserved.
    f = A.CppSourcegraphPlugin._regexp_literal
    assert f("a|b") == "/a|b/"
    assert f(r"find_package\s*\(\s*Foo[\s)]") == r"/find_package\s*\(\s*Foo[\s)]/"
    assert f(r"github\.com[:/]LLNL/zfp") == r"/github\.com[:\/]LLNL\/zfp/"
    assert f(r"x\/y") == r"/x\/y/"  # already-escaped slash passed through
    # The literal is a valid regex whose body round-trips once slashes unescape.
    body = f(r"a(b|c)/d")[1:-1]
    assert re.compile(body.replace(r"\/", "/"))
    print("PASS test_regexp_literal_slash_delimits_and_escapes")


class _CaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


def _capturing_logger(name):
    log = logging.getLogger(name)
    log.setLevel(logging.DEBUG)
    cap = _CaptureHandler()
    log.addHandler(cap)
    return log, cap


def test_search_alert_and_error_are_warnings():
    p = _plugin()
    log, cap = _capturing_logger("test_loud_events")
    try:
        # A query-rejected alert (e.g. the HDF5 bad-regex case) must be WARNING,
        # not INFO — it is the difference between "no dependents" and "the search
        # never ran".
        assert (
            list(p._emit_sse("alert", json.dumps({"title": "x", "description": "bad"}), log))
            == []
        )
        assert any(r.levelno == logging.WARNING for r in cap.records), [
            r.levelno for r in cap.records
        ]
        cap.records.clear()
        list(p._emit_sse("error", json.dumps({"message": "boom"}), log))
        assert any(r.levelno == logging.WARNING for r in cap.records)
    finally:
        log.removeHandler(cap)
    print("PASS test_search_alert_and_error_are_warnings")


def test_stream_search_auth_fast_fail():
    p = _plugin()
    calls = {"n": 0}

    class Resp:
        status_code = 401
        headers = {}
        text = "unauthorized"

        def close(self):
            pass

    def fake_get(*a, **k):
        calls["n"] += 1
        return Resp()

    log, cap = _capturing_logger("test_authfail")
    orig = A.requests.get
    A.requests.get = fake_get
    try:
        # 401 must fail fast (one request, no 6x backoff storm) and loudly.
        assert list(p._stream_search("q", log)) == []
        assert calls["n"] == 1, calls
        assert any(r.levelno == logging.ERROR for r in cap.records), [
            r.levelno for r in cap.records
        ]
    finally:
        A.requests.get = orig
        log.removeHandler(cap)
    print("PASS test_stream_search_auth_fast_fail")
# --- paper-relevance scoring (citation discovery) --------------------------


def test_deinvert_abstract():
    f = A.OpenAlexPublicationPlugin._deinvert_abstract
    assert f({"fast": [1], "zfp": [0], "compression": [2]}) == "zfp fast compression"
    # a token can appear at several positions
    assert f({"a": [0, 2], "b": [1]}) == "a b a"
    # malformed / empty inputs degrade to ""
    assert f({}) == ""
    assert f(None) == ""
    assert f({"x": "nope"}) == ""
    print("PASS test_deinvert_abstract")


def test_parse_work():
    work = {
        "doi": "https://doi.org/10.1/ABC",
        "title": "Fast Compression",
        "abstract_inverted_index": {"Fast": [0], "lossy": [1]},
        "authorships": [
            {"author": {"display_name": "Jane Doe"}},
            {"author": {"display_name": "John Roe"}},
        ],
        "concepts": [{"display_name": "Data compression"}],
        "topics": [{"display_name": "Floating point"}],
        "publication_year": 2020,
        "primary_location": {"source": {"display_name": "SC Proceedings"}},
        "cited_by_count": 42,
        "id": "https://openalex.org/W1",
    }
    meta = A.OpenAlexPublicationPlugin._parse_work(work, "reverse_citation")
    assert meta["doi"] == "10.1/ABC", meta["doi"]
    assert meta["title"] == "Fast Compression"
    assert meta["abstract"] == "Fast lossy"
    assert meta["authors"] == ["Jane Doe", "John Roe"], meta["authors"]
    assert "Data compression" in meta["concepts"]
    assert "Floating point" in meta["concepts"]
    assert meta["year"] == 2020
    assert meta["venue"] == "SC Proceedings"
    assert meta["openalex_citations"] == 42
    assert meta["openalex_id"] == "https://openalex.org/W1"
    assert meta["provenance"] == {"reverse_citation"}
    print("PASS test_parse_work")


def test_provenance_merge():
    # Regression guard: the old `seminal ∪ general` set-union collapsed every
    # channel into one bucket, destroying the per-DOI provenance that is the
    # strongest relevance signal. _merge_meta must UNION provenance and keep
    # both channels' content (fill blanks, dedupe authors/concepts).
    merge = A.CitationEngine._merge_meta
    doi_meta = {}
    merge(
        doi_meta,
        "10.1/x",
        {
            "title": "T",
            "abstract": "",
            "authors": ["A"],
            "concepts": ["c1"],
            "provenance": {"reverse_citation"},
        },
    )
    merge(
        doi_meta,
        "10.1/x",
        {
            "title": "",
            "abstract": "abs",
            "authors": ["B"],
            "concepts": ["c2"],
            "provenance": {"keyword_search"},
        },
    )
    m = doi_meta["10.1/x"]
    assert m["provenance"] == {"reverse_citation", "keyword_search"}, m["provenance"]
    assert m["title"] == "T"  # non-empty original kept
    assert m["abstract"] == "abs"  # blank backfilled from second channel
    assert m["authors"] == ["A", "B"], m["authors"]
    assert m["concepts"] == ["c1", "c2"], m["concepts"]
    # empty DOI is a no-op
    merge(doi_meta, "", {"provenance": {"seminal"}})
    assert "" not in doi_meta
    print("PASS test_provenance_merge")


def test_paper_relevance_scores():
    scorer = A.PaperRelevanceScorer()
    profile = {
        "name": "zfp",
        "owner": "LLNL",
        "topics": {"data compression", "floating point"},
        "terms": {"lossy", "array", "rate", "tolerance"},
        "seminal_authors": {"Peter Lindstrom"},
        "seminal_venues": {"IEEE Transactions on Visualization"},
    }

    # Seminal paper -> always high on provenance alone.
    s, tier, _ = scorer.score({}, {"seminal"}, profile)
    assert tier == "high", (s, tier)

    # A reverse-citation hit clears medium on provenance weight alone.
    s, tier, _ = scorer.score({}, {"reverse_citation"}, profile)
    assert tier == "medium", (s, tier)

    # The "zfp" false positive: a bare keyword-search hit on an unrelated
    # protein paper, no content overlap -> low, dropped by default.
    protein = {
        "title": "Structural basis of the ZFP protein domain",
        "abstract": "We study a zinc finger protein in cells.",
        "authors": ["Unrelated Author"],
        "concepts": ["Molecular biology"],
        "venue": "Cell",
    }
    s, tier, ev = scorer.score(protein, {"keyword_search"}, profile)
    assert tier == "low", (s, tier)
    assert ev["provenance"] == ["keyword_search"]

    # A real keyword-search hit that corroborates (shared author + concept +
    # terms) is lifted out of low.
    real = {
        "title": "Lossy array compression with fixed rate and tolerance",
        "abstract": "A lossy compression scheme for floating point arrays.",
        "authors": ["Peter Lindstrom"],
        "concepts": ["Data compression"],
        "venue": "IEEE Transactions on Visualization",
    }
    s, tier, ev = scorer.score(real, {"keyword_search"}, profile)
    assert tier == "high", (s, tier, ev)
    assert "peter lindstrom" in ev["sharedAuthors"]
    assert "data compression" in ev["matchedConcepts"]
    assert ev["matchedTerms"]
    print("PASS test_paper_relevance_scores")


def test_profile_terms_exclude_bare_name():
    # The bare project-name token must never enter the profile term set, or a
    # colliding-name paper would corroborate itself.
    terms = A._significant_terms(
        "zfp zfp zfp lossy lossy compression array", exclude={"zfp"}
    )
    assert "zfp" not in terms
    assert "lossy" in terms and "compression" in terms
    print("PASS test_profile_terms_exclude_bare_name")


def test_citation_diagnostics():
    d = A.CitationDiagnostics()
    assert d.complete is True
    assert d.summary()["complete"] is True and d.summary()["warnings"] == []

    d.record_http("openalex", A.CitationDiagnostics.RATE_LIMITED)
    d.record_http("openalex", A.CitationDiagnostics.RATE_LIMITED)
    d.record_http("crossref", A.CitationDiagnostics.SERVER_ERROR)
    d.record_cap("citation_total")
    d.dois_unresolved = 3
    assert d.complete is False
    s = d.summary()
    assert s["complete"] is False
    assert s["httpFailures"]["openalex"]["rate_limited"] == 2
    assert s["capsHit"] == ["citation_total"]
    # warnings are deterministic + human-readable
    w = d.warnings()
    assert any("openalex: 2 dropped request(s)" in x for x in w), w
    assert any("citation_total" in x for x in w)
    assert any("3 DOI(s) could not be resolved" in x for x in w)
    # summary is stably ordered (sorted channels/kinds)
    assert list(s["httpFailures"].keys()) == sorted(s["httpFailures"].keys())
    print("PASS test_citation_diagnostics")


def test_frontier_rank_deterministic():
    rank = A.CitationEngine._frontier_rank
    meta = {
        "10.1/a": {"openalex_citations": 5},
        "10.1/b": {"openalex_citations": 50},
        "10.1/c": {},  # unknown count -> 0
        "10.1/d": {"openalex_citations": 5},
    }
    dois = ["10.1/d", "10.1/a", "10.1/c", "10.1/b"]
    # Most-cited first; ties broken by DOI ascending -> fully deterministic.
    assert sorted(dois, key=lambda x: rank(meta, x)) == [
        "10.1/b", "10.1/a", "10.1/d", "10.1/c"
    ]
    # Same result regardless of input order (the determinism property).
    import random as _r
    shuffled = dois[:]
    _r.Random(0).shuffle(shuffled)
    assert sorted(shuffled, key=lambda x: rank(meta, x)) == sorted(
        dois, key=lambda x: rank(meta, x)
    )
    print("PASS test_frontier_rank_deterministic")


def test_paper_sort_key_deterministic():
    key = A.CitationEngine._paper_sort_key
    papers = [
        {"doi": "z", "relevanceTier": "low", "relevanceScore": 1.0, "citationDepth": 1},
        {"doi": "a", "relevanceTier": "high", "relevanceScore": 9.0, "citationDepth": 1},
        {"doi": "b", "relevanceTier": "high", "relevanceScore": 9.0, "citationDepth": 1},
        {"doi": "m", "relevanceTier": "medium", "relevanceScore": 5.0, "citationDepth": 0},
    ]
    ordered = [p["doi"] for p in sorted(papers, key=key)]
    # high before medium before low; ties (a,b both 9.0 high) broken by DOI.
    assert ordered == ["a", "b", "m", "z"], ordered
    print("PASS test_paper_sort_key_deterministic")


def test_expand_citations_caps_and_determinism():
    # Build an engine without __init__ (which would hit the JOSS network).
    eng = object.__new__(A.CitationEngine)
    eng.openalex_plugin = types.SimpleNamespace(
        discover_citing=lambda batch, log: {}
    )
    eng.opencitations_plugin = types.SimpleNamespace(
        citing_dois=lambda batch, log: set()
    )
    saved_cap = A.CITATION_MAX_PER_LEVEL
    try:
        A.CITATION_MAX_PER_LEVEL = 2
        diag = A.CitationDiagnostics()
        doi_meta = {
            "s1": {"openalex_citations": 5},
            "s2": {"openalex_citations": 10},
            "s3": {"openalex_citations": 1},
        }
        depth_of = eng._expand_citations(
            {"s1", "s2", "s3"}, 1, doi_meta, A.defaultdict(set), LOG, diag
        )
        # Frontier (3) exceeded per-level cap (2) -> recorded, not swallowed.
        assert "citation_per_level" in diag.caps_hit
        assert diag.complete is False
        # seminal DOIs are all at depth 0 regardless of truncation.
        assert all(depth_of[d] == 0 for d in ("s1", "s2", "s3"))
    finally:
        A.CITATION_MAX_PER_LEVEL = saved_cap
    print("PASS test_expand_citations_caps_and_determinism")


def test_http_get_json_records_channel_failure():
    plugin = A.PublicationPlugin("e@x.com")
    plugin.diag = A.CitationDiagnostics()

    class Resp:
        def __init__(self, status):
            self.status_code = status
            self.headers = {}

        def json(self):
            return {}

    saved_get, saved_sleep = A.requests.get, A.time.sleep
    try:
        A.time.sleep = lambda s: None
        # Exhausted 429 -> recorded against the named channel as rate_limited.
        A.requests.get = lambda *a, **k: Resp(429)
        assert plugin._http_get_json("http://x", max_attempts=2, channel="openalex") is None
        assert plugin.diag.http_failures["openalex"]["rate_limited"] == 1
        # A definitive 404 is a complete answer -> NOT recorded as a failure.
        A.requests.get = lambda *a, **k: Resp(404)
        assert plugin._http_get_json("http://x", max_attempts=2, channel="crossref") is None
        assert "crossref" not in plugin.diag.http_failures
    finally:
        A.requests.get, A.time.sleep = saved_get, saved_sleep
    print("PASS test_http_get_json_records_channel_failure")


def test_http_get_json_retry_after_cap():
    # Regression: a quota-limited service (OpenAlex was observed sending
    # Retry-After: 30474) must not stall the crawl. A Retry-After beyond the
    # cap abandons the single optional call instead of sleeping for hours.
    plugin = A.PublicationPlugin("e@x.com")

    class Resp:
        def __init__(self, status, retry_after=None, body=None):
            self.status_code = status
            self.headers = {}
            if retry_after is not None:
                self.headers["Retry-After"] = retry_after
            self._body = body

        def json(self):
            return self._body

    slept = []
    saved_get, saved_sleep = A.requests.get, A.time.sleep
    try:
        A.time.sleep = lambda s: slept.append(s)

        # Huge Retry-After -> give up immediately, no sleep, return None.
        A.requests.get = lambda *a, **k: Resp(429, retry_after="30474")
        assert plugin._http_get_json("http://x", max_attempts=4) is None
        assert slept == [], slept  # never slept the multi-hour cool-off

        # A sane Retry-After within the cap IS honored (bounded), then success.
        seq = [Resp(429, retry_after="3"), Resp(200, body={"ok": True})]
        A.requests.get = lambda *a, **k: seq.pop(0)
        assert plugin._http_get_json("http://x", max_attempts=4) == {"ok": True}
        assert slept and max(slept) <= A.HTTP_RETRY_AFTER_CAP
    finally:
        A.requests.get, A.time.sleep = saved_get, saved_sleep
    print("PASS test_http_get_json_retry_after_cap")


def test_llm_judge_offline():
    # No URL -> disabled, never calls out.
    off = A.LLMRelevanceJudge(None, "m")
    assert off.enabled is False
    assert off.judge({"name": "zfp"}, {"title": "t"}, LOG) is None

    judge = A.LLMRelevanceJudge("http://localhost:9", "local-model", token="secret")
    assert judge.enabled is True

    captured = {}

    class Resp:
        status_code = 200

        def __init__(self, content):
            self._content = content

        def json(self):
            return {"choices": [{"message": {"content": self._content}}]}

    saved = A.requests.post
    try:
        # A well-formed verdict embedded in prose is extracted; auth header set.
        def post_ok(url, headers=None, json=None, timeout=None):
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return Resp(
                'Sure! {"relevant": true, "confidence": 0.9, "reason": "cites zfp"}'
            )

        A.requests.post = post_ok
        v = judge.judge(
            {"name": "zfp", "owner": "LLNL", "topics": set(), "terms": set()},
            {"title": "Lossy compression", "abstract": "uses zfp", "venue": "SC"},
            LOG,
        )
        assert v == {"relevant": True, "confidence": 0.9, "reason": "cites zfp"}, v
        assert captured["url"] == "http://localhost:9/v1/chat/completions"
        assert captured["headers"]["Authorization"] == "Bearer secret"
        assert captured["json"]["model"] == "local-model"

        # Non-200 -> None (graceful).
        def post_500(*a, **k):
            r = Resp("")
            r.status_code = 500
            return r

        A.requests.post = post_500
        assert judge.judge({}, {}, LOG) is None

        # Malformed body (no JSON object) -> None.
        A.requests.post = lambda *a, **k: Resp("no json here")
        assert judge.judge({}, {}, LOG) is None

        # A raised exception (server down) -> None, degrades to heuristic.
        def boom(*a, **k):
            raise A.requests.exceptions.RequestException("refused")

        A.requests.post = boom
        assert judge.judge({}, {}, LOG) is None
    finally:
        A.requests.post = saved
    print("PASS test_llm_judge_offline")


def test_llm_apply_and_borderline():
    E = A.CitationEngine
    # Borderline == within the margin just under a cutoff.
    assert E._is_borderline(A.PAPER_TIER_MEDIUM - 0.5) is True
    assert E._is_borderline(A.PAPER_TIER_HIGH - 0.5) is True
    assert E._is_borderline(0.5) is False  # comfortably low
    assert E._is_borderline(A.PAPER_TIER_MEDIUM) is False  # already clears

    below = A.PAPER_TIER_MEDIUM - 0.5
    # Confident "relevant" promotes across the nearest cutoff -> medium.
    score, tier = E._apply_llm(below, "low", {"relevant": True, "confidence": 0.9})
    assert tier == "medium" and score >= A.PAPER_TIER_MEDIUM, (score, tier)
    # Confident "not relevant" demotes.
    score, tier = E._apply_llm(
        A.PAPER_TIER_MEDIUM + 0.2, "medium", {"relevant": False, "confidence": 0.9}
    )
    assert tier == "low", (score, tier)
    # Low confidence changes nothing.
    score, tier = E._apply_llm(below, "low", {"relevant": True, "confidence": 0.1})
    assert tier == "low" and score == round(below, 2), (score, tier)
    print("PASS test_llm_apply_and_borderline")


# --- Phase B: C++20 modules ------------------------------------------------


def _content(*lines):
    return {"type": "content", "chunkMatches": [{"content": ln} for ln in lines]}


def test_extract_module_identifiers():
    p = _plugin()
    p._stream_search = lambda q, log: [
        _content("export module fmt;"),
        _content("  export module boost.json;"),
        _content("export module fmt:core;"),  # partition -> primary fmt (dup)
        _content("export module std;"),  # stoplisted
        _content("module fmt;"),  # not an interface decl (no `export`)
    ]
    ids = p._extract_module_identifiers("github.com/o/r", LOG)
    vals = sorted(i.value for i in ids)
    assert vals == ["boost.json", "fmt"], vals
    assert all(i.kind == K.MODULE_NAME for i in ids)
    assert all(i.provenance == "module_unit" for i in ids)
    print("PASS test_extract_module_identifiers")


def test_module_consumer_pattern():
    p = _plugin()
    (regex, ev), = p._patterns_for_identifier(
        A.Identifier("boost.json", K.MODULE_NAME, "t", 4)
    )
    assert ev == "import"
    assert re.search(regex, "import boost.json;")
    assert re.search(regex, "export import boost.json;")
    assert re.search(regex, "  import boost.json ;")
    # dotted name is escaped: `boost.json` must not match `boostxjson`
    assert not re.search(regex, "import boostxjson;")
    # a Python-style import without a semicolon is not a C++ module import
    assert not re.search(regex, "import boost.json")
    print("PASS test_module_consumer_pattern")


def test_header_unit_import_patterns():
    p = _plugin()
    pats = p._patterns_for_identifier(A.Identifier("zfp.h", K.HEADER_BASENAME, "t", 2))
    evs = {ev for _, ev in pats}
    assert evs == {"include", "header_unit"}, evs
    inc = next(r for r, ev in pats if ev == "include")
    imp = next(r for r, ev in pats if ev == "header_unit")
    assert re.search(inc, "#include <zfp.h>")
    assert re.search(imp, "import <zfp.h>;")
    assert re.search(imp, 'import "subdir/zfp.h";')
    assert not re.search(imp, "#include <zfp.h>")  # include is not a header-unit import
    print("PASS test_header_unit_import_patterns")


def test_module_kind_weight_layer_and_ungated():
    p = _plugin()
    idf = A.Identifier("fmt", K.MODULE_NAME, "module_unit", A.KIND_WEIGHTS[K.MODULE_NAME])
    assert A.KIND_WEIGHTS[K.MODULE_NAME] == 4
    assert A.EVIDENCE_LAYER[K.MODULE_NAME] == A.LAYER_SOURCE
    # module names are distinctive by context -> never IDF-gated
    assert p._is_gated(idf, frozenset()) is False
    print("PASS test_module_kind_weight_layer_and_ungated")


def _has_nested_repeat(regex):
    # RE2 rejects a repetition modified by `+`/`*` (possessive/nested: `c++`,
    # `a*+`); non-greedy `*?`/`+?` are fine. Python 3.11+ silently accepts the
    # possessive forms, so re.compile won't catch them. Detect an unescaped
    # quantifier immediately followed by `+` or `*`.
    return bool(re.search(r"(?<!\\)[+*?][+*]", regex))


def test_identifier_values_are_regex_escaped():
    p = _plugin()

    # HDF5 ships its C++ bindings under `c++/`; that header path carries a `+`.
    # Unescaped it becomes `c++` — a valid possessive quantifier in Python 3.11+
    # but an "invalid nested repetition operator" to Sourcegraph's RE2, which
    # fails the ENTIRE combined query (this is the HDF5 "returns nothing" bug).
    hp = A.Identifier("c++/src", K.HEADER_PATH, "t", 3)
    (regex, _), = p._patterns_for_identifier(hp)
    assert "c\\+\\+" in regex, regex
    assert not _has_nested_repeat(regex), regex

    # Normal identifiers still produce patterns that match real includes.
    hb = A.Identifier("H5Cpp.h", K.HEADER_BASENAME, "t", 2)
    (regex_b, _), = p._patterns_for_identifier(hb)
    assert re.search(regex_b, "#include <H5Cpp.h>")
    assert re.search(regex_b, '#include "subdir/H5Cpp.h"')
    assert not _has_nested_repeat(regex_b), regex_b

    # pkg-config / CMake names with `++` are real (libsigc++, libxml++).
    ci = p._ci_regex("libsigc++")
    assert "\\+\\+" in ci, ci
    fp = f"find_package\\s*\\(\\s*{ci}[\\s)]"
    assert not _has_nested_repeat(fp), fp
    # still case-insensitive on the letters
    assert re.search(f"find_package\\s*\\(\\s*{p._ci_regex('hdf5')}[\\s)]", "find_package(HDF5)")

    print("PASS test_identifier_values_are_regex_escaped")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nALL IDENTIFIER-SET TESTS PASSED")
