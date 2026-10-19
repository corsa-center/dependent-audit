# Dependency Audit Toolchain Usage Guide

This document outlines operational procedures for the Dependency Audit Crawler and the web service that runs it and renders its results.

## Architecture Overview

The toolchain consists of two components:
1. **The Crawler (Backend):** A Python-based script that identifies downstream dependencies via Sourcegraph and extracts metadata using the GitHub GraphQL API. It runs from the command line, as a GitHub Action, or inside the web service.
2. **The Web Service (`deploy/`, `frontend/`):** A browser interface and API that submits audits, shows their progress live, and renders crawler output as tables, network graphs, and citation lists. It can also open graphs produced elsewhere. See `deploy/README.md`.

## The Crawler

The crawler searches global open-source indices to find projects utilizing a target repository. It outputs a Universal Dependency Graph (`.json`) and a set of SPDX 2.3 manifests.

For each project it compiles an **identifier set** (header, CMake/Bazel/pkg-config, and repository-URL identifiers) from the project's own files and searches for the ways consumers reference them. Every dependency edge in the graph carries a **confidence** tier and score, the **evidence** and **identifiers** behind it, its **provenance**, and a **relationship** label (`DEPENDS_ON`, or `VENDORED`/`MIRROR` for bundled copies and forks) — so the dashboard can sort and filter dependents by how strongly the evidence supports them. See `OVERVIEW.md` for the methodology.

Each node can also carry the **academic papers** related to that project (its seminal work plus the works that cite it), discovered via OpenAlex/Crossref. This citation analysis is the most rate-limited stage, so by default it runs only for the root project and its direct consumers (`citation_graph_depth` = 1); raise it to analyze papers further out in the graph. Set an OpenAlex API key (`openalex_api_key` input / `OPENALEX_API_KEY`) to use the authenticated lane and greatly reduce throttling on large crawls.

### Configuration file

Automatic identifier detection is heuristic and misfits many real layouts (no `include/` root, source roots nested under tool/namespace directories, generic top-level directory names, or a bundled third-party build config). For reliable results a project should **declare its public interface** in a TOML config, which you can check into the repository as `.dependent-audit.toml` (auto-loaded from the target repo's HEAD) or pass explicitly with `--config PATH`.

The file can set **any** command-line option (by its long name, hyphens or underscores; at the top level or under an `[options]`/`[audit]` table) plus an `[interface]` table describing the API:

```toml
repo = "myorg/mylib"
name = "mylib"
depth = 1

[interface]
# What consumers write after < or " when including your headers.
include_prefix = "mylib"
# The files that make up your public interface (repo-relative globs).
headers = ["include/**/*.h", "mylib/**/*.hpp"]

# The exact strings other people use to consume your project. Each is tagged
# with a kind so it is weighted and corroborated correctly.
[[interface.consume]]
literal = "#include <mylib/"          # matched literally
kind = "header_path"
[[interface.consume]]
literal = "find_package(mylib"
kind = "cmake_package"
[[interface.consume]]
literal = "execute_process(mylib-tool" # a tool/binary invocation
kind = "executable"
[[interface.consume]]
regex = "@mylib//"                     # a raw regex, used verbatim
kind = "bazel_module"
```

Precedence, highest first: an explicit command-line flag, then `--config`, then an auto-loaded repo config, then defaults/environment. Tokens are never read from an auto-loaded repo config — supply them via the command line, environment, or an explicit `--config`. Header globs resolve against a local checkout when `--repo-checkout` is given, otherwise remotely against the target repo. The `[interface]` block applies only to the audited (root) project.

Declared headers replace automatic header detection, but automatic build/repository detection still runs so common build references are found for free. If your repository bundles a third-party build config (e.g. a vendored `pybind11Config.cmake`) or uses very generic directory names, that automatic step is a source of false positives — set `no_defaults = true` alongside the `[interface]` block to search **only** your declared interface.

### Live progress events

`--events-file PATH` makes the crawler append structured progress events (one JSON object per line: phases, live Sourcegraph match counts, each dependent as it is found and enriched, warnings, and the final completeness verdict) to `PATH`. The web service uses this to stream progress to the browser; it is off by default and does not change the graph output. The event catalogue is in `deploy/README.md`.

### Data Generation
The crawler can run as a GitHub Action. Upon execution, the action outputs an archive containing all graph data and SPDX manifests, which the viewer can open directly.

1. Navigate to the target repository's GitHub Actions panel.
2. Select the **Dependency Audit Crawler** workflow.
3. Trigger the workflow manually, supplying the required `project_name` parameter.
4. Download the resulting artifact archive once the workflow completes.

The archive contains a flat file structure: the `dependency_graph.json` mapping file, and an `spdx_snippets` directory containing strictly version-pinned SBOMs.

## The Web Interface

Start the service with `docker compose up --build` and open `http://localhost:8080` (see `deploy/README.md` for configuration).

### Running an audit

1. **New audit:** enter the repository (`owner/name` or a GitHub URL). The project name is filled in from it. Choose a depth and, optionally, skip papers or open the advanced sections, such as the `no_defaults` + `custom_string` override for projects the automatic identifiers misfit.
2. **Audit page:** progress streams live. It shows the phase timeline, the Sourcegraph match counter, and a dependents table that fills in as consumers are found and enriched. Warnings and a cancel button are also on this page. Reloading or losing the connection resumes where it left off.
3. When the audit finishes, the same page shows the results.

### Viewing results

The results view is used both for audits and for graphs opened via **Open graph** (`/view`). The viewer accepts a URL, a `dependency_graph.json`, or the GitHub Action's `.zip` artifact, and reads files in the browser.

* **Dependents:** a sortable, paginated table of every consumer, with confidence, relationship, evidence layer, stars, matches, papers, license, and last update. You can filter by confidence, relationship, evidence layer, depth, and free text. The filtered rows export to CSV.
* **Graph:** an interactive network with the root at the centre. Rings go outward by depth, with the strongest dependents innermost. Colour shows confidence, shape shows relationship, and size shows stars. It shares the table's filters, and large graphs are capped at the top 3000 by score.
* **Papers:** every paper across the graph, de-duplicated by DOI, with relevance tier, provenance, and the repositories it attaches to.
* **Detail drawer:** click any row or node to see repository statistics, the evidence behind the edge (signals, identifiers, layers), its connections, its papers with relevance evidence, and the edge's SPDX manifest (viewable and downloadable).
* **Downloads:** the graph JSON, the SPDX snippet archive (for audits), and CSV.