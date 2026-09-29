# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A GitHub Action (and standalone Python CLI) that discovers public repositories depending on a target C/C++ project. It searches Sourcegraph's global code index for `#include`/`#pragma comment(lib)`/`find_package` references, enriches each hit with GitHub metadata, mines academic citations, and emits a **Universal Dependency Graph** (`dependency_graph.json`) plus version-pinned **SPDX 2.3** SBOM snippets (`spdx_snippets/`). Those artifacts feed a separate frontend dashboard (not in this repo).

Read `OVERVIEW.md` for the full methodology and `usage.md` for the operator-facing workflow. The near-entirety of the logic lives in one file: `audit_dependents.py`.

## Commands

There is no build step or CI lint gate. A **plain-assert unit suite** covers the
identifier-set / discovery layer (no external test deps):

```bash
python tests/test_identifier_set.py          # or: pytest tests/
```

Development beyond that is running the crawler directly.

```bash
# Local run (Python 3.11+ required — uses stdlib tomllib; only dependency is `requests`)
pip install requests
python audit_dependents.py \
  --repo "LLNL/zfp" --name "zfp" --depth 1 \
  --out dependency_graph.json \
  --sg-token "$SG_TOKEN" --gh-token "$GH_TOKEN"

# Tokens can come from env vars instead of flags: SG_TOKEN, GH_TOKEN, AUDIT_EMAIL
# --verbose switches logging from terse to structured JSON
# --depth 0 audits only the root node's metadata/citations (no Sourcegraph token needed)
```

Linting uses **ruff** (a `.ruff_cache/` is present); run `ruff check .` / `ruff format .`. The Action itself (`action.yml`) installs only `requests`/`argparse` and invokes the same script.

## Running an audit (agent-facing operational recipe)

Read this before running the crawler on a new target; it captures the setup and the identifier-tuning judgment that a raw `--help` does not.

**Environment.** Requires **Python 3.11+** (stdlib `tomllib` for `--config`); the only third-party
dependency is `requests`. The system Python on this machine is PEP 668 externally-managed, so
`pip install requests` fails — create a venv instead (do **not** use `--break-system-packages`):

```bash
python3 -m venv .venv && .venv/bin/pip install requests
.venv/bin/python audit_dependents.py ...
```

**Config file (preferred for anything non-trivial).** `--config PATH` loads a TOML file, and a
checked-in `.dependent-audit.toml` at the target repo's HEAD is auto-loaded too. **Every CLI option
is settable** by its long name (hyphens or underscores), at the top level or under an
`[options]`/`[audit]` table. Precedence (highest first): explicit CLI flag → `--config` file →
auto-fetched repo config → env/argparse default. Secrets (`sg_token`/`gh_token`) are **never** taken
from an auto-fetched repo config — only CLI / env / an explicit `--config`. The `[interface]` table
declares the project's public API and applies **only at the root node**:
- `include_prefix` + `headers` (repo-relative globs) → the tool resolves the globs (locally when
  `--repo-checkout` is set, else via Sourcegraph), strips any `include/`/`src/` marker, prepends the
  prefix, and emits real `HEADER_PATH`/`HEADER_BASENAME` identifiers. This fixes the include-prefix
  problem deterministically. Declared headers replace auto header extraction at the root unless
  `replace_auto_headers = false` (build/VCS auto-discovery still runs).
- `[[interface.consume]]` entries — the exact strings consumers write — each with a `kind` (any
  `IdentifierKind`, e.g. `header_path`, `cmake_package`, `bazel_module`, `repo_slug`, the new
  `executable`) and either `literal` (regex-escaped) or `regex` (verbatim). Crucially each becomes a
  **real identifier of that kind**, so `_score_consumer` corroboration and confidence tiers work —
  unlike `--custom-string`, which collapses everything into one low-weight `ALIAS`.

Declared headers replace *auto header* extraction, but auto *build/VCS* extraction still runs (so
find_package/@repo are picked up for free) **unless you also set `no_defaults = true`**. For a
project that vendors a third-party build config (Drake bundles a `pybind11Config.cmake`), that
auto-build step is exactly the contamination source, so pair the interface with `no_defaults = true`
to search *only* the declared surface — declared identifiers survive `no_defaults` by design.

**Tokens.** Local files `sg_pat` (Sourcegraph) and `gh_pat` (GitHub PAT) hold the tokens — pass `--sg-token "$(cat sg_pat)" --gh-token "$(cat gh_pat)"` (or export `SG_TOKEN`/`GH_TOKEN`). A Sourcegraph token is required unless `--depth 0`. Set `--email` for the OpenAlex/Crossref polite pool (only matters when citations are on).

**Common intents.**
- *Dependents only, no academic mining:* add `--no-citations` (this is what "without publications/papers" means). It emits empty `papers[]` and skips all OpenAlex/OpenCitations/Crossref traffic — much faster.
- *Untruncated results:* the default `--sg-count 5000` is a per-node **match** cap (not a repo cap); when the run warns `sourcegraph: result limit hit` (see `meta.completeness`), re-run with `--sg-count all`. A single popular provider can blow the cap purely on generic-token matches, silently crowding out the real, specific dependents.
- *Depth:* `--depth 1` = direct dependents of the root (the usual ask); `--depth 0` = root metadata only.

**Identifier tuning — the step that actually decides result quality.** Discovery keys off an auto-compiled identifier set (headers, build files, repo URL). The default extraction is a good fit for a library whose repo has an `include/` root and a distinctive project name. It is a **poor fit**, and produces mostly false positives, when either of these holds — check the target's layout first (clone it, look at the header tree and `MODULE.bazel`/CMake):
  - The repo has **no `include/` or `src/` marker**, so `_include_path` leaves header paths unchanged and the consumer-facing include prefix is never derived. (Consumers of such projects usually still include under a project prefix the repo layout doesn't contain — e.g. Drake ships headers at `common/…`, `systems/…` but consumers write `#include <drake/common/…>`.)
  - The top-level header dirs are **generic English words** (`common`, `math`, `geometry`, `systems`) or the repo **vendors another library's build config** (e.g. a bundled `pybind11Config.cmake`), which `_extract_build_identifiers` then attributes to the target as its own package name.

  In those cases the auto-set matches half of GitHub — and because `find_package(pybind11)` etc. is a build kind that is **never IDF-gated**, the false positives even reach *high* confidence. **The fix is to declare the interface in a config file** (above): list the real consumer strings as `[[interface.consume]]` entries with their kinds. Because each becomes a real identifier of the right kind, discovery is precise *and* corroboration still tiers edges properly.

  (The legacy escape hatch — `--no-defaults` plus one `--custom-string` regex that ORs the signals — still works but collapses everything into a single low-weight `ALIAS`, so confidence flattens to `low`/`medium`. Prefer the config file.)

**Worked example — `RobotLocomotion/drake` (no-`include/` layout, generic dirs, vendors pybind11).** Auto-extraction yielded ~148 edges dominated by `common`/`math`/`pybind11` with `torvalds/linux` and `pytorch/pytorch` as false *high*-confidence hits. Declare the interface instead — `drake.toml`:

```toml
repo = "RobotLocomotion/drake"
name = "drake"
depth = 1
no_citations = true
sg_count = "all"
no_defaults = true   # Drake vendors pybind11Config.cmake — suppress noisy auto-ID

[interface]
include_prefix = "drake"
[[interface.consume]]
literal = '#include <drake/'
kind = "header_path"
[[interface.consume]]
literal = "find_package(drake"
kind = "cmake_package"
[[interface.consume]]
regex = '@drake//'
kind = "bazel_module"
[[interface.consume]]
regex = 'github\.com[:/]RobotLocomotion/drake'
kind = "repo_slug"
```

```bash
.venv/bin/python audit_dependents.py --config drake.toml \
  --out drake_dependency_graph.json \
  --sg-token "$(cat sg_pat)" --gh-token "$(cat gh_pat)"
```

This returns a `complete` (untruncated) graph — ~190 dependents, ~130 `high` — with the real consumers (Apollo, IsaacLab, gtsam, fcl, EasyMocap, TNN) tiered `high` and mere URL-mentions in awesome-lists/docs correctly demoted to `low`, and none of the auto-extraction false positives (`pybind11`, `common`, `torvalds/linux`).

## Architecture

`audit_dependents.py` is organized as a set of composable classes driven by `AuditOrchestrator`:

- **`AuditOrchestrator.run()`** — the heart. Runs a **breadth-first crawl**: seeds a queue with the root repo, and for each node calls the ecosystem plugin to find consumers, builds a node record, writes an SPDX snippet per edge, and enqueues newly-seen children until `--depth` is exhausted. `visited`/`nodes_map` dedupe nodes; `edges_list` records `source→target` (consumer→provider) relationships. Emits the final `{meta, nodes, edges}` JSON.

- **`EcosystemPlugin` → `CppSourcegraphPlugin`** — the extension point (only C++ implemented; `rust`/`python`/`node` raise `NotImplementedError`). Discovery is built around a compiled **identifier set** rather than a single guessed token — see `IDENTIFIER_SET_PLAN.md` for the full design and rationale. Per node:
  - **`_compile_identifier_set`** gathers `Identifier`s (kind + value + provenance + weight): repo-wide **header** paths (`_extract_header_identifiers`, normalized to consumer-facing include paths via `_include_path` — no `include/` assumption), real **build-system** names (`_extract_build_identifiers`: CMake package/target/artifact, pkg-config, Bazel module), **repo-URL** identity (`_extract_vcs_identifiers`), and optional **registry aliases**.
  - **`SpecificityService`** (IDF) frequency-gates only *low-context* tokens (bare basenames, generic single namespaces) via bounded Sourcegraph probes, cached in `.idf_cache.json`; build/target/URL kinds are never gated. `--no-idf` disables.
  - Each identifier → consumer-side `ConsumptionPattern`s; one combined regex drives a **streaming** search (`_stream_search`, SSE over `/.api/search/stream` — replaced the old GraphQL `-repo:` pagination). Matches are classified back to identifier kinds.
  - **`_score_consumer`** (corroboration) + **`_classify_relationship`** (copy/fork detection) produce per-edge `confidence`/`confidenceScore`/`relationship`/`evidence`/`identifiers`/`provenance`. See "Scoring" below.
  - **Declared registries** (opt-in `--declared-sources`, e.g. `spack`, config in `DECLARED_REGISTRIES`): mined via Sourcegraph searches of the registry repo, reconciled on repo URL, folded in as corroboration/recall/alias signals — never ground truth.

- **`CitationEngine`** — aggregates a pipeline of publication plugins to attach academic `papers[]` to each node. Two DOI classes: **seminal** (the repo's own paper, from JOSS / `CITATION.cff` / Zenodo/codemeta) and **citing** (found via OpenAlex + OpenCitations reverse-citation lookup, plus README/description text scraping and OpenAlex full-text keyword search). The reverse-citation lookup is a **bounded breadth-first crawl** (`_expand_citations`) seeded by the seminal DOIs: depth 1 = direct citers (the historical behavior), higher = citers-of-citers, cycle-guarded by a `visited`/`depth_of` map and capped by `CITATION_MAX_PER_LEVEL`/`CITATION_MAX_TOTAL`. Each paper carries `citationDepth` (0 = seminal or a one-shot text/full-text seed hit, ≥1 = crawl hop) and `relation`. All DOIs are resolved through Crossref (or the JOSS map). `--academic-keyword` injects extra full-text search terms and `--citation-depth` sets the crawl depth, both **only at the root node (depth 0)** — non-root nodes always use depth 1.

  Every discovered DOI is then **relevance-scored** (`PaperRelevanceScorer`, mirroring `_score_consumer`) rather than blindly attached. `get_publications` preserves per-DOI *provenance* — a `doi_provenance: dict[str,set]` + `doi_meta: dict[str,dict]` instead of the old `seminal ∪ general` union — because *how* a DOI was found (`seminal` > `reverse_citation`/`_oc` > `text_scrape` > `web_scrape` > `keyword_search`, weighted in `PROVENANCE_WEIGHT`) is the strongest relevance signal. Scoring corroborates provenance with lexical overlap against a repo **profile** (built in `_build_node_data`: `name`/`owner`/repo `topics`/significant `terms`/`seminal_authors`/`seminal_venues`) — author/term/concept/venue matches. Seminal DOIs resolve **first** so their authors/venue seed the profile before citing papers are scored. Papers carry `relevanceScore`/`relevanceTier`/`relevanceEvidence`/`provenance` + `authors`/`year`/`concepts` (raw `abstract` scored then dropped). **The bare project name is excluded from `terms`** and a `keyword_search`-only hit needs corroboration to clear `low` — this is the colliding-name ("zfp" ≈ a protein) false-positive fix. **Default policy: drop `low`-tier citing papers** (`--paper-relevance-floor`, default `medium`; `--no-paper-filter` keeps them scored-but-present; `--no-paper-relevance` restores unscored historical behavior). An optional `LLMRelevanceJudge` (`--relevance-llm-url`/`--relevance-llm-model`, off by default, any OpenAI-compatible local endpoint) breaks ties on borderline papers only, recorded in `evidence.llm`. OpenAlex/OpenCitations/Crossref/backfill/LLM calls route through `PublicationPlugin._http_get_json` (backoff on 429/5xx); DOI backfill caches in `.paper_cache.json` (`--paper-cache`).

- **`GitHubEnricher`** — one GraphQL call per repo pulling stars/commits/license/release/README *and* citation source files (`CITATION.cff`, `codemeta.json`, `.zenodo.json`). Skips GitLab/Bitbucket.

- **`SPDXManager`** — writes one `<consumer>.spdx.json` per dependency edge into `spdx_snippets/`, pinned to exact commit SHAs.

Logging goes through `ContextAdapter`, carrying `run_id`/`root_repo`/`depth`/`chain` on every record; `--verbose` selects `JSONFormatter`, otherwise `TerseFormatter`.

## Determinism & completeness (why two runs agree, or say why they don't)

Two users running the same audit should get the same graph *except* as the live data changes. The threats to that are (a) **set-iteration order** feeding bounded caps/slices, and (b) **silently swallowed failures** (a rate-limited 429 that shrinks one user's graph with no signal). Both are handled so a partial run is *reported*, never disguised as a complete one:

- **Deterministic ordering** — the citation frontier is ranked (most-cited first, DOI tiebreak) *before* the per-level cap slices it (`_frontier_rank`), so truncation is reproducible and keeps the most-influential citers; `target_urls`/`seed_search` terms iterate sorted; emitted `papers` are sorted by `_paper_sort_key` (tier↓, score↓, depth↑, DOI). No result depends on hash/set order.
- **`CitationDiagnostics`** (per node, in `data.paperDiagnostics`) records every dropped request by channel (`openalex`/`opencitations`/`crossref` → `rate_limited`/`server_error`/`request_error`/`bad_response`), caps hit (`citation_per_level`/`citation_total`), and unresolved DOIs. `PublicationPlugin._http_get_json(..., channel=)` is the choke point; a definitive `404` is a *complete* answer and is **not** counted, only data-dropping failures are. An over-cap `Retry-After` (`HTTP_RETRY_AFTER_CAP`, 60s) abandons that one optional call instead of stalling the crawl for hours.
- **Run-level `meta.completeness`** (`_build_completeness`) aggregates discovery (Sourcegraph truncation/abandonment/interruption, tracked on `CppSourcegraphPlugin.search_incomplete`), citations (`incompleteNodes`), and the JOSS seminal index (`jossPagesFailed`) into one `complete` boolean + sorted `warnings`. The final log line is INFO "(COMPLETE)" or WARN "INCOMPLETE" accordingly. `schemaVersion` is `2.2`.

## Scoring (why an edge has the confidence it does)

The wide net is deliberately noisy; precision comes from scoring, not from dropping recall. Two guards keep false positives out of the *high-confidence* band without discarding anything:

- **IDF specificity** (`SpecificityService`) — applied **only to low-context kinds** (bare `header_basename`, single-word `header_path`, `project_name`). A token that saturates a bounded frequency probe is dropped from the search. Build-system / target / repo-URL kinds are **never gated**, so a *popular* provider's own `find_package(GTest)`/`gtest::` survives (high global frequency there means many real dependents, not noise). A provider-owned stem (namespace == project name) is also exempt.
- **Corroboration scoring** (`_score_consumer`) — confidence = strongest matched kind weight (already IDF-scaled) + `CORROBORATION_BONUS` per *additional independent kind* + bounded log-volume. A lone generic-basename match scores `low`; an exact `vcs_ref` or a header **and** `find_package` **and** a `::` target scores `high`. Doc-path matches (`_is_doc_path`) contribute at 0.3×.

`_classify_relationship` labels an edge `VENDORED` when a candidate reproduces ≥50% of the provider's header surface (bundled copy/rehost) and the orchestrator upgrades GitHub forks to `MIRROR`; everything else is `DEPENDS_ON`. Copies are **labeled, never dropped**.

Weights live in `KIND_WEIGHTS` (per identifier kind); gating exemptions in `_is_gated`; tiers/bonuses are `TIER_*` / `CORROBORATION_BONUS` constants on the plugin.

## Gotchas

- **`create.sh` is a stale bootstrap generator**, not part of the runtime. It embeds an *old, diverged* copy of `audit_dependents.py` and `action.yml` via heredocs. Do not treat it as source of truth and do not edit it to change behavior — edit `audit_dependents.py` directly. It will drift from the real files.
- **`sbom_to_udg.py` is an unfinished stub** (its `convert()` parses but does nothing).
- `udg_schema.json` is kept in sync with the emitted `{meta, nodes, edges}` (schemaVersion `2.0`: per-node/edge `evidence`/`identifiers`/`provenance`/`relationship`/`confidence*`). Update it when the output shape changes.
- Secrets: `gh_pat`, `sg_pat`, `sg_pat_header` are local token files ignored via `.gitignore` (`sg_*`, `gh_*`). `example_data/` and `spdx_*/` are also git-ignored; the ~550 checked-in `spdx_snippets/` are generated output from prior runs.
- Network calls have broad `try/except` and fixed retry/backoff; failures degrade to empty metadata rather than aborting the crawl.
