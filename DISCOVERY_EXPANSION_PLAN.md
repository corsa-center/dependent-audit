# Discovery Expansion — Formal Plan

Phased, self-contained implementation plan derived from `DISCOVERY_EXPANSION_NOTES.md`
(research) and the Part 6 evidence matrix. Each phase is independently shippable and
ordered by value (matrix leverage + correctness), not by dependency — the only shared
substrate is Phase A. Check off tasks as they land; move completed phases to a "Shipped"
note.

**Read first:** `DISCOVERY_EXPANSION_NOTES.md` (Parts 1–7 + the Part 6 matrix) for the
full rationale; `IDENTIFIER_SET_PLAN.md` for the identifier-set architecture this extends;
`CLAUDE.md` for conventions (requests-only, label-then-filter, schema sync).

---

## Locked decisions (carried from the notes)

- **Requests-only.** No new heavyweight deps; everything is HTTP + regex over hosted
  indexes/APIs. **AST extraction is ruled out** (tree-sitter/libclang would mean cloning
  sources + a parser service — out of scope, not deferred).
- **Per-symbol C-lib matching is rejected** (bare `open`/`init`/`Buffer` flood on
  generics). Only the **conditional prefix family** survives at the symbol layer; C libs
  without a clean prefix get recall from higher layers instead.
- **URL reconciliation** is the one join key; every new source folds in as
  corroboration / recall / alias, **never ground truth**.
- **Label-then-filter, never hard-drop recall.** New evidence raises/lowers confidence
  and tier; only non-dependents (provider self, forks, vendored copies) are relabeled.
- **Prefer hosted indexes over origin crawls.** Do not crawl self-hosted GitLab; reach
  gitlab.com via its API, the long tail via searchcode. Politeness: API-only, robots.txt,
  concurrency ≤1–2, backoff on 429/`Retry-After`, identifiable UA, cache.

---

## Cross-cutting architecture additions

Three pieces are introduced once and reused across phases.

### 1. Evidence-layer model (Phase A)

Every identifier kind and every declared/registry/SBOM source is tagged with its **Axis-A
evidence layer** (1 Narrative → 2 Source-consumption → 3 Build-manifest → 4
Package-registry → 5 Binary/link → 6 Attestation/SBOM → 7 Bibliometric). Scoring gains a
per-layer `LAYER_WEIGHT` and rewards **cross-layer** corroboration while de-duping
**cross-reach** agreement (three code-search backends seeing one `#include` = one fact).
This is the spine that makes every later phase's contribution legible.

### 2. `HeaderApiExtractor` (Phase C)

Generalizes the existing provider-blob fetch (`_fetch_build_blobs`) from build files to
the already-discovered **public header** blobs, then regex-mines the API surface:
`#define` macros, `namespace X {`, and the dominant function-decl **prefix** (histogram,
no AST). One extractor unlocks the Part 7 language facets. Cached per node.

### 3. `SearchBackend` seam (Phase H)

Abstracts discovery off the Sourcegraph SSE (`_stream_search` / `discover_dependents`)
behind a `query → normalized hits` interface, so backends (Sourcegraph, grep.app, Debian
Code Search, searchcode) can fan-out + fail over, each carrying its own politeness/rate
config and its Axis-D reach. Mirrors the `EcosystemPlugin` / `DECLARED_REGISTRIES`
extension-point style.

---

## Phase A — Evidence-layer scoring foundation ✅ DONE

**Layer:** cross-cutting · **Matrix role:** makes layer diversity rewardable · **Deps:** none

The substrate. Cheap (no new data source), improves current output immediately, and every
later phase plugs into it.

- [x] Added `EVIDENCE_LAYER: dict[kind -> int]` mapping each existing kind to its Axis-A
      layer (headers → 2; cmake/pkgconfig/bazel/**repo-slug** → 3; `declared` → 4; unknown
      defaults to 2). New soname/SBOM kinds add their entry in Phases F/G.
- [x] Added `LAYER_WEIGHT: dict[int -> float]` as an **additive** nudge on the top layer,
      on top of the IDF-scaled `KIND_WEIGHTS` sum. Source/build/registry = 0 (existing
      calibration untouched — `KIND_WEIGHTS` already orders them); narrative = −2.0;
      binary/link = SBOM = +1.5; bibliometric = 0.
- [x] Reworked corroboration: `(len(distinct layers) − 1) * CORROBORATION_BONUS`, not per
      kind — cross-reach agreement on one fact no longer inflates confidence; cross-layer
      does. Added `_evidence_layers(kind_weights)` helper.
- [x] Carry `evidenceLayer` (top layer) + `layers[]` (sorted distinct) onto each entry,
      node `data`, and edge. Colliding-name guard: `top_layer <= LAYER_NARRATIVE` hard-caps
      tier at `low`.
- [x] Schema: added `evidenceLayer`/`layers` to node+edge; bumped `meta.schemaVersion`
      `2.2` → `2.3`; updated `udg_schema.json`.
- [x] Tests (offline, plain-assert): `test_evidence_layers`, `test_cross_layer_corroboration`
      (within-layer de-dupe + cross-layer stack), `test_narrative_only_capped_low`,
      `test_high_layer_outranks_lone_source`; extended `test_end_to_end_emits_identifiers`
      (`layers == [2, 3]`, `evidenceLayer == 3`). All 38 pass; no regression.

**Key symbols:** `_score_consumer` / `_evidence_layers`, `EVIDENCE_LAYER` / `LAYER_WEIGHT`
(module-level near `KIND_WEIGHTS`), `CORROBORATION_BONUS`/`TIER_HIGH`/`TIER_MEDIUM`,
`IdentifierKind`.

**Deviation from draft:** `LAYER_WEIGHT` is purely **additive** (not a multiplier) and
source/build/registry are pinned to 0 so no existing scorer test shifted — the layer model
lands as a zero-behavior-change substrate on today's layer-2/3 kinds, and only activates as
Phases F/G introduce layer-4/5/6 kinds. `repo_url`/`repo_slug` classified as build-manifest
(layer 3), not source, since the reference lives in `.gitmodules`/FetchContent config.

---

## Phase B — C++20 modules (biggest correctness win) ✅ DONE

**Layer:** 2 · **Matrix role:** deepens layer-2 (correctness, not diversity) · **Deps:** none

Consumers using `import zfp;` emit no `#include` and are 100% invisible today.

- [x] New `IdentifierKind.MODULE_NAME` (`KIND_WEIGHTS` 4, `EVIDENCE_LAYER` = source,
      ungated — not in `GATED_KINDS`).
- [x] Provider extractor `_extract_module_identifiers` — scoped content search for
      `^\s*export\s+module\s+[A-Za-z_]` over the provider repo; `_MODULE_DECL_RE`
      captures the name (`[A-Za-z_]\w*(?:\.\w+)*`, stops at `:` so a partition reduces
      to its primary); `MODULE_STOPLIST` = {std, std.compat}; deduped; `MODULE_CAP` 40.
      `MODULE_EXT_RE` recorded for later path-scoping. Wired into `_compile_identifier_set`.
- [x] Consumer pattern: `^\s*(?:export\s+)?import\s+NAME\s*;` (evidence `import`);
      handles `export import` re-exports; name `re.escape`d so `boost.json` ≠ `boostxjson`;
      requires `;` so Python `import x` doesn't match.
- [x] Header-unit alt-patterns on both header kinds: added a second pattern
      `import\s+<…/x.h>;` / `import\s+"…/x.h";` (evidence `header_unit`) beside the
      existing `include` one.
- [x] Tests: `test_extract_module_identifiers` (partition→primary, stoplist, dedup,
      `export`-required), `test_module_consumer_pattern`, `test_header_unit_import_patterns`,
      `test_module_kind_weight_layer_and_ungated`. Updated `_prep` to stub the module
      search (else `_compile_identifier_set` made a real network call → retry-storm hang).
- [ ] Verify live on a modules-adopting provider (adoption reality-check — note if corpus thin).

**Deviations from draft:** (1) the header branches now use `re.escape(idf.value)` instead
of the dots-only escape — this *converges with* the standalone `fix/escape-identifier-regex`
branch (same correctness), since Phase B rewrote these branches to add the header-unit
pattern and writing new code on the known-buggy escape was not acceptable. (2) evidence
label for header-unit imports is `header_unit` (distinct from `include`) so the two are
attributable separately.

**Key symbols:** `_patterns_for_identifier`, `_extract_module_identifiers`,
`_MODULE_DECL_RE`/`MODULE_STOPLIST`/`MODULE_CAP`, `_compile_identifier_set`.

---

## Phase C — `HeaderApiExtractor`: provider macros + conditional prefix family

**Layer:** 2 · **Matrix role:** closes the C-lib layer-2 gap as far as it can go · **Deps:** none

- [ ] `HeaderApiExtractor` — fetch discovered public-header blobs (generalize
      `_fetch_build_blobs`), cache per node.
- [ ] **`IdentifierKind.PROV_MACRO`** (top real facet): mine `#define NAME(` / `#define NAME`
      from headers; consumer `\bNAME\b`; distinctive/prefixed → ungated, high precision.
      Include version/config macros (`#if defined(PROV_VERSION)`).
- [ ] **`IdentifierKind.API_SYMBOL` (prefix family only)**: derive the dominant function
      prefix from a header func-decl histogram; accept only if it clears a min
      length/frequency bar (reject `os_`, `gl`, short/ambiguous stems). Consumer
      `\bPREFIX\w+\(`. **Conditional** — no clean prefix ⇒ no symbol-layer recall (fall back
      to Phase F/G layers for that lib).
- [ ] **No `API_TYPE`** (rejected — bare type names flood).
- [ ] Tests: macro extraction + match; prefix histogram picks `sqlite3_` and rejects `gl`;
      conditional skip when no prefix qualifies; caching.

**Open sub-question:** min prefix length/frequency threshold — tune on real C libs.

---

## Phase D — Structural-search corroboration (specialization + base-class)

**Layer:** 2 · **Matrix role:** precision lift (corroboration) · **Deps:** C (extractor)

- [ ] `IdentifierKind.CPO_SPECIALIZE` — provider CPO templates (`formatter`, `hash`,
      `adl_serializer`); consumer `template<>\s*struct\s+prov::cpo<` via **Sourcegraph
      structural search** (`patterntype:structural`), regex fallback.
- [ ] `IdentifierKind.API_BASE` — provider public base classes; consumer `:\s*public\s+prov::Base`.
- [ ] De-dupe overlap with `CPP_NAMESPACE` (both contain `prov::`) — model as higher-weight
      sub-patterns, not double-counted independent kinds/layers.
- [ ] Tests: structural pattern match on samples; overlap de-dupe.

**Open sub-question:** Sourcegraph structural-search throughput/indexed-only limits at our
query volume.

---

## Phase E — Codegen path facets + niche signals

**Layer:** 2 · **Matrix role:** cheap tool-usage recall · **Deps:** none

- [ ] Generated-byproduct + codegen-input **path** facets via `type:path` search:
      `*.pb.h`/`moc_*`/`*_generated.h`/`*.capnp.h` and `*.proto`/`*.fbs`/`*.capnp`/`*.ui`/`*.msg`.
- [ ] `CPP_NAMESPACE` (Part 1c) — top-level `namespace X {`; `\bX::`; IDF-gated (generics).
- [ ] Niche: dynamic-load strings (`dlopen\("libfoo`, `LoadLibrary\("foo`), UDLs
      (`operator"" _suffix`), toolchain tags (`#pragma omp`, `.cu`+`__global__`, `mpi.h`) as
      weak/ecosystem corroboration.
- [ ] Plugin-entry `PLUGIN_SYMBOL` + export-macro `EXPORT_MACRO` (Part 1b) as corroboration.
- [ ] Tests: path-facet matches; namespace gating; dlopen/UDL/toolchain patterns.

---

## Phase F — Declared-source activation (layers 3–4)

**Layer:** 3–4 · **Matrix role:** lights up dormant reverse-manifest cells · **Deps:** none

Mostly config in the existing `DECLARED_REGISTRIES` machinery (Spack is the live template).

- [ ] **vcpkg** — registry ports + consumer `vcpkg.json` `"dependencies"` (reverse manifest).
- [ ] **Conan** — center recipes + consumer `conanfile.py/.txt` `requires`/`self.requires`
      (strongest modern-C++ declared signal).
- [ ] **CI-config grep** — `apt-get install lib<you>-dev` / `vcpkg install <you>` /
      `conan install` in `.github/workflows/*` (strong install-intent, layer 3).
- [ ] **Repology** — alias feeder only (40+ distro renames), not a dependent source.
- [ ] Tests: manifest reverse-dep reconciliation; CI-grep edge; alias fold-in.

**Key symbols:** `DECLARED_REGISTRIES` (1464), declared-merge path.

---

## Phase G — High-authority layers 5–6 (the matrix's top leverage)

**Layer:** 5–6 · **Matrix role:** fills the thin high-authority cells; **primary** recall
path for prefix-less C libs · **Deps:** A (layer scoring)

The scarce, valuable cells. For C-heavy targets this outranks Phase B — **consider
promoting G above B when auditing C libraries** (see sequencing note).

- [ ] **GitHub Dependency-Graph SBOM export** (`GET /repos/{o}/{r}/dependency-graph/sbom`) —
      first-party reverse edges, layer 6. Confirm a candidate lists the provider.
- [ ] **Debian/Ubuntu soname reverse-deps** (UDD / `apt-rdepends`) and **Fedora/RHEL**
      (`repoquery --whatrequires 'libfoo.so.N()'`) — layer 5, authoritative "who links
      libfoo". Package→repo-URL via Homepage/Source field.
- [ ] **conda-forge `run_exports`** — greppable ABI-pin signal (layer 4→5 bridge) without
      scanning any binary.
- [ ] **In-the-wild SBOMs** — grep `*.spdx.json`/`bom.json` naming the provider; reuse
      `sbomgr`/`github-sbom-toolkit` rather than reinventing SBOM parsing.
- [ ] Reconcile all on URL; fold in as corroboration/recall with layer 5/6 weight.
- [ ] Tests: SBOM-export edge; soname reverse-dep → URL reconciliation; run_exports parse.

**Open sub-question:** reliable distro-package → repo-URL mapping (Homepage fields
inconsistent) — shared across §2b/§5.

---

## Phase H — `SearchBackend` seam + additional backends (Axis D)

**Layer:** 2 (reach diversity) · **Matrix role:** de-single-vendors discovery, adds
non-GitHub recall · **Deps:** stable query shape from B/C

Bigger refactor; do after facets stabilize so we abstract a known query shape. Pull earlier
only if Sourcegraph reliability becomes urgent.

- [ ] `SearchBackend` interface (`query → normalized hits`), Sourcegraph as first impl
      (wrap `_stream_search`).
- [ ] **grep.app** backend (GitHub supplement/fallback) — confirm API stability/ToS first.
- [ ] **Debian Code Search** backend (`/api/v1/searchperpackage`, RE2, C/C++ filter) —
      purpose-built C/C++ corpus; strong fit.
- [ ] **searchcode** backend (multi-host: GitLab/Bitbucket/SourceForge) — non-GitHub recall.
- [ ] Fan-out + merge on repo URL (cross-reach de-dupe from Phase A); per-backend politeness/
      rate/cache config; **gitlab.com via API**, no self-hosted crawling.
- [ ] Discovery diagnostics per backend (ties into the Roadmap's per-node discovery
      diagnostics item).
- [ ] Tests: normalized-hit merge/de-dupe; backend failover; per-backend rate config.

---

## Phase I — CPS (Common Package Specification) build-file extraction

**Layer:** 3 (build-manifest) · **Matrix role:** richer, cleaner provider identifiers +
authoritative include roots · **Deps:** none (composes with Provider-Analysis Phase 3)

CPS is an emerging, build-system-agnostic JSON format for describing an installed
package (`<name>.cps`): the package name, its components (target-like units), the
include directories it exposes, and its own requirements. It is effectively a
structured superset of what we already scrape from `*Config.cmake` + `*.pc`, but as
JSON rather than regex-over-CMake — so extraction is cleaner and lower-noise. Early
adoption today (like C++20 modules), growing, and CMake has experimental support.

Mostly a **provider-side extraction** win; on the consumer side CPS funnels back into
the package name we already search (`find_package(Name)` / a package name in a
Meson/build2 manifest), so no distinctive new consumer token is required yet.

- [ ] Add `.cps` to `BUILD_FILE_RE` discovery (or a dedicated path search).
- [ ] `_parse_cps` — JSON parse (not regex): package `name` → `CMAKE_PACKAGE`;
      component names → `CMAKE_TARGET`; the declared **include directories** → header
      include-root identifiers (`HEADER_PATH`).
- [ ] Feed the CPS include roots into header-path normalization — this is the portable,
      authoritative fix for include-root guessing (the non-standard-layout class, e.g.
      headers under `h/`), parallel to Provider-Analysis Phase 3's CMake install-rule
      parsing. Prefer an explicit CPS/install declaration over directory-name heuristics.
- [ ] Tests: `_parse_cps` on a sample `.cps` → correct package/component/include-root
      identifiers; include roots flow into consumer include patterns.

**Key symbols:** `BUILD_FILE_RE`, `_extract_build_identifiers`, `_parse_cmake`
(sibling parser), `_include_path` / header normalization.

---

## Cross-cutting

- **Schema versioning:** each phase that changes output shape bumps `meta.schemaVersion`
  and updates `udg_schema.json` in the same change (current: `2.3`, after A's
  `evidenceLayer`/`layers`). New fields: `evidenceLayer`/`layers` (A), new `identifiers[]`
  kinds (B, C, I), backend/reach provenance (H).
- **Config surface:** add CLI flags per phase (`--enable-modules`, `--header-api`,
  `--declared-sources` extensions, `--sbom-sources`, `--search-backends`), off-by-default
  for anything network-heavy or unproven; mirror the useful ones into `action.yml`.
- **Testing:** every phase adds offline plain-assert tests to `tests/test_identifier_set.py`
  (canned fixtures, no network), per existing convention. Live verification steps noted
  per phase.
- **Determinism/completeness:** new sources route their data-dropping failures through the
  existing diagnostics choke points (`_http_get_json` channel, `search_incomplete`) so
  partial runs stay *reported*, per `CLAUDE.md`.

## Sequencing tensions (decide before locking order)

1. **B vs G.** B (modules) is the biggest *correctness* win but deepens an already-saturated
   layer-2 cell; G (SBOM/soname) is the biggest *authority/diversity* win and the primary
   recall path for prefix-less C libs. Default order keeps B first; **flip to G-first for
   C-heavy audit targets.**
2. **H placement.** The `SearchBackend` seam is a refactor everything rides on; late by
   default (abstract a known shape), but pull forward if single-vendor Sourcegraph risk
   materializes.
3. **Nixpkgs is layer 4, not 5** — do not treat it as the soname fill; Debian/Fedora
   (Phase G) populate layer 5.

## Explicitly out of scope

- AST / tree-sitter / libclang extraction (would require cloning + a parser service).
- Per-symbol C-lib type/function-name matching (generics flood).
- Crawling arbitrary self-hosted GitLab instances.
- Self-hosted code-search indexing (Zoekt/Hound) — makes us the crawler.
- Producing our own binary scans — we consume others' (distro soname, SBOMs) only.
