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


def _prep(plugin, headers=None, build_paths=None, cmake="", bazel=""):
    """Stub all provider-file discovery so compilation touches no network."""
    plugin._discover_header_paths = lambda *a, **k: list(headers or [])
    plugin._discover_build_paths = lambda *a, **k: list(build_paths or [])
    plugin._fetch_build_blobs = lambda *a, **k: {"cmake": cmake, "bazel": bazel}
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


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nALL IDENTIFIER-SET TESTS PASSED")
