# Dependency Audit Toolchain: Architecture and Methodology

## Problem Statement

Measuring the impact, usage, and ecosystem relevance of open source software is a complex requirement for program management and technical auditing. In modern ecosystems like Rust, Node, Python, and Go, centralized package managers (Cargo, NPM, Pip, and Go modules) maintain public registries. These registries provide an immediate, queryable graph of downstream dependents.

The C and C++ ecosystems lack this centralized standardization. While package managers like Spack, Conan, and vcpkg exist, they are strictly opt-in. They only track usage by developers who have explicitly packaged and published their software within those specific systems. Relying on these tools provides a severely truncated view of a project's actual footprint, although they do provide a great "at a glance" overview and an invaluable starting point for usage tracking.

## Objective

This effort is an attempt to provide a more wholistic view of the downstream consumption of a target software project. It surveys the C++ ecosystem at a wider scope by performing code analysis on a large index of Github to find where and a project is referenced in the wild.

## Methodology

### Compiling the Identifier Set

A C/C++ project has no single canonical name. It exposes a *bag* of loosely-coupled identifiers — repository slug, git URL, CMake package name, exported target namespace(s), pkg-config module(s), installed header paths, library artifact names, Bazel module, project name — any of which can diverge from the others and each of which a downstream consumer might reference. Rather than guessing one token, the tool **compiles the observed identifier set** from the provider's own files. Each identifier carries its kind, the provenance of how it was learned, and a base weight reflecting how strongly a match implies real usage.

1. **Header discovery.** The tool enumerates header files anywhere in the repository (not only a root `include/` directory — many major projects ship headers under `src/`, a top-level namespace directory, or a nested `<sub>/include/`). Each header path is normalized to the path a consumer would actually `#include` (the portion after the last `include/`/`inc/` segment, else with a leading `src/` stripped). From these it derives **namespace** identifiers (e.g. `absl/strings`, `google/protobuf`) and **basename** identifiers (e.g. `str_cat.h`). Basenames are namespace-invariant: a consumer may write `#include <foo/bar.h>` or `#include <bar.h>` depending on its own include flags, but `bar.h` is stable.
2. **Build-system names.** The tool parses the provider's build files for the *real* names consumers reference: CMake package names (from `*Config.cmake` file names and `project()`), exported targets (`install(EXPORT … NAMESPACE X::)`, `add_library(X::Y ALIAS)`), library artifacts, pkg-config module names (`*.pc` files), and the Bazel module name (`MODULE.bazel`).
3. **Repository identity.** The repo slug is the one unambiguous identifier, searched for directly in git submodules, CMake `FetchContent`/`ExternalProject`, and CPM (`gh:owner/repo`) — references that require no name-mapping guess at all.
4. **Registry aliases (opt-in).** Package registries (e.g. Spack) are mined for the name they give the provider, folded in as additional search identifiers. This turns registry renaming (such as Spack's `py-` prefix) into extra coverage rather than a mismatch.
5. **Custom override.** A user-supplied regular expression can be added to target usage patterns outside these conventions (e.g. language bindings).

Each identifier is expanded into consumer-side **consumption patterns** — the regexes a consumer would produce (`#include`, `find_package`, `Foo::Bar`, `#pragma comment(lib)`, `pkg_check_modules`, `bazel_dep`, submodule URLs, …).

### Specificity Gating

A wide net risks false positives from non-discriminating tokens: a project that ships a `config.h` header, or is named `core`, matches half of the open-source world. The tool applies an **inverse-frequency (IDF) guard**: it probes the global frequency of a candidate token in the code index and drops or down-weights tokens that are too common to attribute. Crucially this is applied **only to low-context tokens** (bare header basenames, generic single-word namespaces, bare project names). Build-system declarations, exported targets, and repository-URL references are specific *by context* and are never frequency-gated — otherwise a *popular* provider's own `find_package(GTest)` would be penalized precisely because it is popular. Frequency probes are cached across runs.

### Search Execution Engine

The consumption patterns are combined and executed against Sourcegraph's **streaming search API** (Server-Sent Events), which returns every match in one long-lived request and reports explicitly when and why results were truncated (shard or display limits). Searching indexed code rather than package manifests captures usage regardless of how a consumer integrated the library — build systems, git submodules, and manual vendoring alike. Rate limiting and transient errors are absorbed with exponential backoff so a large crawl degrades gracefully rather than silently truncating.

### Scoring, Corroboration, and Relationship Classification

Because the net is deliberately wide, precision comes from **scoring rather than from discarding recall**. Every discovered edge is assigned a confidence driven by the strongest matched identifier's (specificity-adjusted) weight, plus a bonus for each *additional independent kind* of evidence that corroborates it — a header inclusion together with a `find_package` and a namespaced target is far stronger than three header matches — plus a bounded volume term. Matches inside documentation contribute less than matches in source or build files. Each edge records the evidence types, the specific identifiers matched, and their provenance, so a reader can see *why* a repository was flagged and filter by confidence.

The tool also distinguishes genuine dependents from copies. A repository that reproduces most of the provider's header surface is labeled **VENDORED** (a bundled copy or rehost) and a GitHub fork is labeled **MIRROR**, rather than **DEPENDS_ON**. Such nodes are labeled, never dropped.

### Corroboration from Declared Registries

Optionally, the tool cross-checks its source-derived findings against package registries (Spack, with others as configuration). It reconciles on repository URL — the one unambiguous identifier — and uses declared dependents to *corroborate* repositories already found in source (raising their confidence), to *recover* dependents that source search missed, and to feed registry aliases back into the identifier set. Registries are treated as additional evidence, never as ground truth.

### Traversal and Graph Expansion

When a repository is identified as a dependent, the tool queries the GitHub API for its metadata (owner, activity metrics, license). A Breadth First Search then maps the wider ecosystem: each newly discovered dependent has its own identifier set compiled and searched, up to a user-defined depth limit, mapping the multi-tier chain from the root project down to end-user applications.

### Citation and Academic Impact Tracking

To measure academic impact, the tool attaches formal publications to each node. It identifies **seminal** DOIs (the repository's own paper, from JOSS, `CITATION.cff`, or Zenodo/codemeta metadata) and **citing** works (via OpenAlex and OpenCitations reverse-citation lookups on those seminal DOIs, plus DOI scraping from READMEs and OpenAlex full-text keyword search). All DOIs are normalized through Crossref (or the JOSS map) into a uniform record of title, journal, citation count, and link.

## Outputs and Data Artifacts

The crawler compiles the discovered data into two primary artifacts, which are bundled into a single archive for the visualizer dashboard.

### Universal Dependency Graph

The core output is a JSON formatted Universal Dependency Graph. This file maps every discovered node (repository) and edge (dependency relationship). Each node carries its extracted metadata, citation records, and computed graph depth; each node and edge additionally carries the discovery **evidence** (which kinds of signal matched and how many times), the specific provider **identifiers** the consumer referenced, the **provenance** of those identifiers, a **confidence** tier and score, and a **relationship** label (`DEPENDS_ON`, `VENDORED`, or `MIRROR`). This lets the frontend render sortable, filterable tables and topological network maps in which uncertain matches are visibly low-confidence rather than silently mixed in. The schema (`udg_schema.json`, `schemaVersion` 2.0) accompanies the crawler.

### SPDX Manifest Generation

For every dependency relationship identified during the traversal, the tool generates a Software Package Data Exchange (SPDX) 2.3 compliant Software Bill of Materials snippet. This provides a formalized, machine readable record of the exact linkage between the consuming repository and the provider repository at their respective commit hashes. These manifests ensure the audit output can be ingested by standard compliance and security tooling.

These snippets can then be introduced to Github to populate the dependent project tab, and allows Github to render your dependents.

## System Limitations

While this methodology provides a significantly broader view than opt-in package managers, it operates within several technical boundaries:

1. **Visibility of Private Codebases:** The toolchain relies on the public indices of Sourcegraph and GitHub. It cannot map internal, proprietary, or classified enterprise usage unless the execution environment is provided with authentication tokens explicitly granting access to those private environments.
2. **Github Only** The toolchain is currently limited to scraping Github only, as that is what has been indexed by SourceGraph. Efforts are underway to expand this capacity.
3. **Static Analysis Constraints:** The search engine performs syntax-level static analysis, not build-time dynamic analysis. A matched `#include` or `find_package` indicates intent to use the library, but it does not guarantee the code is actively compiled into a final binary (e.g., dead code or deprecated modules). The confidence score reflects strength of evidence, not proof of runtime linkage.
4. **Index Completeness and API Limits:** The accuracy of the dependency graph is bounded by the completeness of the third-party search indices at the time of execution. Very high-volume providers may still exceed the index's internal result limits; when this happens the streaming API reports the truncation rather than failing silently, and rate limits are absorbed with backoff.
5. **Residual Heuristic Fragility:** The identifier set is compiled from the provider's own files, but header layout, build-system conventions, and macro-generated includes are not standardized. A provider whose files are unindexed or unconventional may yield a thinner identifier set. The design goal is graceful degradation: no single weak or missing signal is decisive, and low-confidence matches are surfaced as such rather than presented as certain.
6. **Confidence, Not Ground Truth:** Both the source heuristics and the optional package-registry corroboration are best-effort evidence. A high-confidence, multiply-corroborated edge is very likely a real dependency; a low-confidence edge is a lead for a human to review, not an assertion.
7. **Citation Context Ambiguity:** Attaching a DOI captures the presence of an academic reference, but not its semantic context. A README may cite a paper that inspired an algorithm rather than citing the repository itself.
