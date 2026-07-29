# A Wide-Net Dependent-Discovery Tool for the C/C++ Ecosystem

**One-page summary.** For full methodology see `OVERVIEW.md`; for the discovery
design rationale see `IDENTIFIER_SET_PLAN.md`.

## Motivation

Package registries (Cargo, npm, PyPI, Go modules) give language ecosystems a
queryable graph of who depends on what. C and C++ have no such canonical
registry: Spack, Conan, and vcpkg are opt-in and capture only the subset of
users who publish through them, giving a truncated view of a project's real
footprint. This tool estimates the *actual* downstream consumption of a C/C++
project by analyzing a global index of public source code, rather than trusting
package manifests.

## Approach

A C/C++ project has no single canonical name; it exposes a *bag* of loosely
coupled identifiers — repository slug and git URL, CMake package name and
exported target namespaces, pkg-config modules, installed header paths, library
artifact names, Bazel module, and project name — any of which a consumer may
reference. The tool proceeds in four stages:

1. **Identifier-set compilation.** Rather than guessing one token, it compiles
   the observed identifier set from the *provider's own files*: header paths
   (normalized to the include path a consumer would write, yielding namespace
   and namespace-invariant basename identifiers), real build-system names parsed
   from CMake / pkg-config / Bazel files, and the repository slug (the one
   unambiguous identifier). Optional package-registry aliases and user regexes
   extend it. Each identifier carries a kind, provenance, and a base weight.

2. **Specificity gating.** To suppress non-discriminating tokens (a generic
   `config.h`, a project named `core`), an inverse-frequency (IDF) guard probes
   each candidate's global frequency in the code index and drops/down-weights
   tokens too common to attribute. It is applied *only to low-context tokens*;
   build-system declarations, exported targets, and repository-URL references
   are specific by context and are never frequency-gated — so a popular
   provider's own `find_package(GTest)` is not penalized for being popular.

3. **Search execution.** Identifiers are expanded into consumer-side consumption
   patterns (`#include`, `find_package`, `Foo::Bar`, `pkg_check_modules`,
   submodule/`FetchContent` URLs, …), combined, and run against Sourcegraph's
   streaming search API. Searching indexed code — not manifests — captures usage
   regardless of integration method (build system, submodule, or manual
   vendoring), and truncation is reported explicitly rather than failing
   silently.

4. **Scoring and classification.** Because the net is deliberately wide,
   precision comes from scoring, not from discarding recall. Each discovered
   edge gets a confidence from the strongest matched identifier's
   (specificity-adjusted) weight, a corroboration bonus for each *additional
   independent kind* of evidence, and a bounded volume term; documentation
   matches count less than source/build matches. Copies are labeled, not
   dropped: a repository reproducing most of the provider's header surface is
   `VENDORED`, a GitHub fork is `MIRROR`, otherwise `DEPENDS_ON`. A breadth-first
   crawl repeats the process on each discovered dependent up to a user-set depth.
   Optionally, declared package registries (e.g. Spack) are reconciled on
   repository URL to corroborate, recover, and alias — as evidence, never ground
   truth.

Academic impact is attached per node: **seminal** DOIs (the project's own paper,
from JOSS / `CITATION.cff` / Zenodo-codemeta) and **citing** works (OpenAlex and
OpenCitations reverse-citation lookups on those DOIs, plus README DOI scraping
and full-text keyword search), all normalized through Crossref.

## Outputs

- A **Universal Dependency Graph** (JSON, `schemaVersion` 2.0): nodes
  (repositories, with metadata, citations, depth) and edges (consumer→provider),
  each carrying the discovery **evidence**, matched **identifiers** and their
  **provenance**, a **confidence** tier/score, and a **relationship** label — so
  results are sortable and filterable, and uncertain matches are visibly
  low-confidence rather than silently mixed in.
- **SPDX 2.3** SBOM snippets pinned to exact commit hashes, one per edge,
  ingestible by standard compliance/security tooling.

## Illustrative result

Run on `dyninst/dyninst` (`depth 1`), the tool discovered 21 downstream
repositories — including EasyBuild, Fedora's `dyninst` RPM, ROCm/omnitrace,
HexHive/retrowrite, and the E4S stack — tiered by corroborating evidence (e.g.
an exact repo-URL reference *and* a `find_package` scoring `high`; a lone generic
header match scoring `low`), and attached 20 citing publications to the root.

## Scope and limitations

The tool sees only public code indexed by Sourcegraph/GitHub (no private or
non-GitHub usage without appropriate access); performs syntax-level static
analysis, so a match indicates *intent to use*, not proven runtime linkage;
is bounded by index completeness and API result limits (reported, not hidden);
and yields *confidence, not ground truth* — a high-confidence, multiply
corroborated edge is very likely real, while a low-confidence edge is a lead for
human review. It is distributed as a GitHub Action and a standalone Python CLI.
