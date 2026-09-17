# A Wide-Net Dependent-Discovery Tool for the C/C++ Ecosystem

**One-page summary.** For the full, self-contained methodology and workflow see
`OVERVIEW.md`.

## What it does

Given a C or C++ library (for example `LLNL/zfp`), this tool discovers the public
projects that depend on it, with supporting evidence and a confidence rating for
each. It ships as a command-line program, a GitHub Action, and a small
containerized web service.

## Why it is needed

Rust (Cargo), Node (npm), Python (pip), and Go all have central registries that
answer "who depends on this?" directly. C and C++ have none. The C/C++ package
managers — Spack, Conan, vcpkg — are opt-in, mutually inconsistent, and cover only
the small fraction of projects someone chose to package. This tool instead reads
the world's public source code directly to estimate a project's *actual*
downstream usage.

## How it works

1. **Compile an identifier set.** A C/C++ project has no single canonical name; it
   exposes a bag of loosely related identifiers, any of which a consumer might use.
   The tool observes them from the provider's own files rather than guessing one:
   header paths and filenames; C++20 module names (`export module`); CMake package
   and exported-target names, pkg-config modules, Bazel modules, and library
   artifact names; and the repository slug/URL (the one unambiguous identifier).
   Optional package-registry aliases and a user regex extend it. Each identifier
   carries a kind, a provenance, and a base weight.

2. **Gate for specificity.** A frequency guard measures how common each low-context
   token is across the global code index and drops or down-weights ones too common
   to attribute (a generic `config.h`, a project named `core`). Build-system,
   target, and repository-URL identifiers are specific by context and are never
   gated, so a popular library's own `find_package(GTest)` is not penalized for
   being popular.

3. **Search indexed code.** Each identifier becomes the consumer-side pattern that
   references it (`#include`, `import`, `find_package`, `Namespace::`,
   `pkg_check_modules`, submodule/`FetchContent` URLs, …). These run as one
   combined query against Sourcegraph's streaming code-search API. Searching code,
   not manifests, catches usage regardless of how the consumer integrated the
   library, and truncation is reported rather than hidden.

4. **Score, layer, and classify.** Precision comes from scoring, not from
   discarding recall. Each edge's confidence combines the strongest matched
   signal, a bonus for each *additional independent kind and layer* of corroborating
   evidence, and a bounded volume term; documentation matches count less. Evidence
   is grouped into ordered **layers** (narrative < source < build-manifest <
   registry < binary/link < bill-of-materials), and agreement across different
   layers counts more than repetition within one. Copies are labeled, not dropped:
   a repository reproducing most of the provider's headers is `VENDORED`, a GitHub
   fork is `MIRROR`, everything else `DEPENDS_ON`. A breadth-first crawl repeats
   the process on each discovered dependent up to a user-set depth. Optionally,
   declared registries (e.g. Spack) are reconciled on repository URL to
   corroborate, recover, and alias — as evidence, never ground truth.

Academic impact is attached per node: **seminal** DOIs (the project's own paper,
from JOSS / `CITATION.cff` / Zenodo-codemeta) and **citing** works (reverse-citation
lookups through OpenAlex and OpenCitations, README DOI scraping, and full-text
search), all resolved through Crossref and relevance-scored so colliding names do
not flood the results.

## Outputs

- A **dependency graph** (JSON, schema `udg_schema.json`): nodes (repositories with
  metadata, citations, depth) and edges (consumer→provider), each carrying the
  discovery **evidence**, matched **identifiers** and their **provenance**, the
  **evidence layers** involved, a **confidence** tier and score, and a
  **relationship** label — sortable and filterable, with uncertain matches visibly
  low-confidence.
- **SPDX 2.3** bill-of-materials files, one per edge, pinned to exact commit
  hashes, ingestible by standard compliance and security tooling.

## Scope and limitations

Public, largely GitHub-hosted code only; syntax-level analysis, so a match shows
*intent to use*, not proven runtime linkage; bounded by index completeness and API
limits (reported, not hidden); and **confidence, not ground truth** — a
high-confidence, multiply-corroborated edge is very likely real, a low-confidence
edge is a lead for human review. The only runtime dependency of the core engine is
the `requests` HTTP library; it analyzes code by searching a public index, never by
downloading or compiling it.
