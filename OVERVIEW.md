# Dependency Audit Toolchain: Architecture and Methodology

## Problem Statement

Measuring the impact, usage, and ecosystem relevance of open source software is a complex requirement for program management and technical auditing. In modern ecosystems like Rust, Node, Python, and Go, centralized package managers (Cargo, NPM, Pip, and Go modules) maintain public registries. These registries provide an immediate, queryable graph of downstream dependents.

The C and C++ ecosystems lack this centralized standardization. While package managers like Spack, Conan, and vcpkg exist, they are strictly opt-in. They only track usage by developers who have explicitly packaged and published their software within those specific systems. Relying on these tools provides a severely truncated view of a project's actual footprint, although they do provide a great "at a glance" overview and an invaluable starting point for usage tracking.

## Objective

This effort is an attempt to provide a more wholistic view of the downstream consumption of a target software project. It surveys the C++ ecosystem at a wider scope by performing code analysis on a large index of Github to find where and a project is referenced in the wild.

## Methodology

### Determining the Public Interface and Search Heuristics

To find potential consumers of a project, the system must first know what to search for. Rather than relying on a static name, the tool constructs a potential view of the project's public interface by inspecting the associated repository for common patterns and conventions used to expose projects to downstream consumers. The engine employs the following search heuristics to build its query parameters:

1. **Public Header Discovery:** The system queries the target repository's file tree at the default branch, specifically looking for an `include` directory. It then parses this directory for files and subfolders that match the project's short name. In C and C++ ecosystems, the `include` directory is the standard convention for exposing a library's public API. Isolating the contents of this directory ensures the tool only generates search queries for the intended public interface, reducing false positives from internal utility scripts.
2. **#include Matching:** Using the tokens identified during the header discovery phase, the tool constructs strict regular expressions to find `#include` statements across global open source repositories. If the token is a file, it builds a regex to capture direct inclusions (e.g., `#include <zfp.h>` or `#include "zfp.h"`). If the token is a directory, it builds a regex to capture the inclusion of any file within that namespace. Searching for these specific directives ensures the tool captures actual code level integration, regardless of the build system used.
3. **MSVC Linker Directive Matching:** The system automatically generates an additional regular expression to search for `#pragma comment(lib, "library_name")`. In Windows environments utilizing the Microsoft Visual C++ compiler, developers frequently use pragma directives to link libraries directly within the source code. Capturing this directive ensures the audit captures downstream consumers operating in Windows environments.
4. **Convention Fallbacks:** If the target repository does not contain a standard `include` directory, or if the file tree query fails, the system falls back to a generalized assumption. It generates search tokens for `project_name.h` (as a file) and `project_name` (as a directory). This fallback ensures the crawler can execute a high probability search based on standard C naming conventions rather than failing silently on older projects.
5. **Custom Override Directives:** The toolchain accepts user defined regular expressions and explicit target filenames, which can bypass the default C/C++ header heuristics entirely. Providing a custom override allows the auditor to target precise usage patterns that fall outside standard preprocessor directives, such as Python bindings or custom CMake configurations.

### Search Execution Engine

The tool executes these interface queries against the Sourcegraph GraphQL API. Sourcegraph is utilized because it provides globally indexed code search across millions of open source repositories, while providing a rich and robust code query API that allows for regex and symbols.

Searching indexed code rather than package manifests allows the tool to identify usage regardless of how the downstream developer integrated the code. It captures standard build systems, git submodules, and manual vendor copying in addition to standard in source references.

### Traversal and Graph Expansion

When the search engine identifies a repository containing the target string, that repository is registered as a dependent. The tool queries the GitHub API to extract relevant metadata about this consumer, including its organizational owner, activity metrics, and license data.

The system then uses a Breadth First Search algorithm to map the wider ecosystem. It takes the newly discovered dependent, determines its public interface, and queries Sourcegraph for its consumers. This recursion continues up to a user defined depth limit, mapping the multi tier dependency chain from the root project down to end user applications.

### Citation and Academic Impact Tracking

Software impact is not limited to other software products, with potential implications for use in academic and research environments. To measure academic impact, the tool tracks formal citations and publications associated with discovered repositories.

1. **JOSS Integration:** The crawler indexes the Journal of Open Source Software (JOSS) database. It cross references the URLs of discovered dependents against JOSS records to associate formal publication data to the dependents or even the primary software of interest.
2. **README Extraction and Crossref:** The tool parses the README files of discovered repositories using regular expressions designed to identify Digital Object Identifiers (DOIs).
3. **Resolution:** Discovered DOIs are resolved against the Crossref API. This standardizes the citation data into a uniform format containing the paper title, journal, and link, which is then attached to the respective repository node.

## Outputs and Data Artifacts

The crawler compiles the discovered data into two primary artifacts, which are bundled into a single archive for the visualizer dashboard.

### Universal Dependency Graph

The core output is a JSON formatted Universal Dependency Graph.  This file maps every discovered node (repository) and edge (dependency relationship). It contains all extracted metadata, citation records, and computed graph depth. This structure allows the frontend visualizer to render the data as both sortable tables and topological network maps. The schema for the UDG can be found in the dependent audit repository.

### SPDX Manifest Generation

For every dependency relationship identified during the traversal, the tool generates a Software Package Data Exchange (SPDX) 2.3 compliant Software Bill of Materials snippet. This provides a formalized, machine readable record of the exact linkage between the consuming repository and the provider repository at their respective commit hashes. These manifests ensure the audit output can be ingested by standard compliance and security tooling.

These snippets can then be introduced to Github to populate the dependent project tab, and allows Github to render your dependents.

## System Limitations

While this methodology provides a significantly broader view than opt-in package managers, it operates within several technical boundaries:

1. **Visibility of Private Codebases:** The toolchain relies on the public indices of Sourcegraph and GitHub. It cannot map internal, proprietary, or classified enterprise usage unless the execution environment is provided with authentication tokens explicitly granting access to those private environments.
2. **Github Only** The toolchain is currently limited to scraping Github only, as that is what has been indexed by SourceGraph. Efforts are underway to expand this capacity.
3. **Static Analysis Constraints:** The search engine performs syntax-level static analysis, not build-time dynamic analysis. Finding an `#include` directive indicates intent to use the library, but it does not guarantee the code is actively compiled into a final binary (e.g., dead code or deprecated modules left in the repository).
4. **Index Completeness and API Limits:** The accuracy of the dependency graph is bounded by the completeness of the third-party search indices at the time of execution. Furthermore, high-volume downstream consumers may trigger internal search limits (truncation) or API rate limits, which cap the total discoverable universe for a single traversal.
5. **Heuristic Evasion:** Projects utilizing different directory structures, heavy C-macro generation for dynamic includes, or non-standard build automation may evade the default search heuristics. These edge cases require manual intervention via the custom override directives.
6. **Citation Context Ambiguity:** Scraping DOIs from README files captures the presence of an academic reference, but it cannot ascertain semantic context. A README may cite a paper that inspired an algorithm, rather than citing the repository itself.
