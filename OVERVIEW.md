# Finding Who Depends on a C/C++ Project — Design and Methodology

This document explains, from scratch and in full, what this tool is, the problem
it solves, the strategy it uses, and how it works under the hood. It assumes no
prior knowledge of the project. Terms that a reader outside the C/C++ build world
might not know are explained where they first appear.

---

## Part 1 — What this tool is and who it is for

This tool discovers, as completely as it can, the public software projects that
**depend on** a given C or C++ library. You point it at a target project (for
example the compression library `zfp`, published on GitHub as `LLNL/zfp`) and it
produces a ranked, evidence-backed list of other projects that use it, together
with *why* it believes each one is a real user and *how strongly*.

It is meant for:

- **Maintainers** who want to know who actually uses their library — to gauge
  impact, plan releases, understand who a breaking change would affect, or make
  the case for continued funding.
- **Program managers and auditors** measuring the reach and importance of a piece
  of open-source software.
- **Security and supply-chain work**, where knowing the downstream consumers of a
  library matters (for example, when that library has a vulnerability).

It is delivered three ways: a command-line program, a GitHub Action (a job that
runs inside GitHub's automation system), and a small containerized web service.
All three run the same underlying engine.

The output is a machine-readable **dependency graph** (which projects use which,
with supporting evidence) plus standardized **bill-of-materials** files (a formal,
tool-ingestible record of each dependency link). A separate dashboard, not part of
this repository, renders the graph for browsing.

---

## Part 2 — The problem: C and C++ have no dependency registry

In many modern language ecosystems there is a single, central place that records
who depends on what:

- Rust has **Cargo** and crates.io.
- JavaScript/Node has **npm**.
- Python has **pip** and PyPI.
- Go has the module system and its index.

In those ecosystems every project declares its dependencies in a standard manifest
file, and the central registry can therefore answer the reverse question directly:
"which published packages depend on this one?" The dependency graph is essentially
handed to you.

**C and C++ have no such central registry.** There are package managers for C/C++
— **Spack**, **Conan**, and **vcpkg** are the common ones — but they are all
*opt-in*. A project only appears in them if some person deliberately wrote and
published a packaging recipe for it. Most C/C++ software in the world is never
packaged in any of them. The three package managers also disagree with each other,
rename projects (for example, adding a `py-` prefix), and split a single project
into multiple package names. So if you rely only on package managers, you see a
small and distorted slice of a project's real usage.

The reason C/C++ is different is historical and technical: C and C++ predate the
idea of a central package index, and they have many independent, coexisting ways
to consume a library — copying source files in directly, using a system package,
using any of several build systems, referencing a git repository, and so on. There
is no single declaration that says "I depend on library X."

This tool takes a different approach. Instead of trusting package manifests, it
**reads the world's public source code directly** and looks for the many concrete
ways a project reveals, in its own files, that it uses a particular library. That
gives a far broader — though necessarily best-effort — picture of real usage.

---

## Part 3 — The core idea: compile an "identifier set," don't guess one name

A C/C++ project does not have one canonical name that consumers use. It exposes a
whole *bag* of loosely related identifiers, any of which a consumer might
reference, and which frequently differ from one another. For a single library, all
of the following can be different strings:

- the repository slug (`LLNL/zfp`) and its git URL;
- the name used in CMake, a common build system (`find_package(ZFP)`);
- the "target" name CMake consumers link against (`zfp::zfp`);
- the pkg-config module name (`libzfp`), from another common build-configuration
  tool;
- the header files it installs (`zfp.h`, `zfp/array.hpp`);
- the compiled library artifact name (`libzfp`);
- the Bazel build-system module name;
- the project's own short name (`zfp`);
- the names package registries give it (`zfp`, `py-zfp`, …).

Because these diverge, guessing a single token to search for is unreliable. The
central design decision of this tool is to **observe the whole set of identifiers
from the provider's own files**, map each identifier to the pattern a *consumer*
would write when using it, search for all of those patterns, and then rank each
discovered project by how much and how strongly it matched.

Each identifier the tool learns is recorded with three things:

1. its **kind** (header, CMake package, exported target, repository slug, module
   name, and so on);
2. its **provenance** — how the tool learned it (read from a header path, parsed
   from a build file, taken from the repository URL, supplied by a registry, …);
3. a **base weight** — how strongly a match on this kind of identifier implies
   real usage. An exact repository-URL reference is near-certain evidence; a bare,
   common header filename is weak evidence.

A guiding principle throughout is **observe, don't guess**, and its companion,
**keep and label, don't discard**. The tool deliberately casts a wide net and
then controls false positives by *scoring and labeling* what it finds, rather than
by throwing away uncertain matches. A weak match is reported as weak, not deleted.

---

## Part 4 — The strategy: which facets of C/C++ structure reveal a dependent

This is the heart of the tool. A project that uses a C/C++ library leaves traces
in several distinct layers of its own source tree — in its code, in its build
configuration, and in its source-control setup. The tool knows how a consumer
writes each of those traces, and searches for all of them. Below is each facet,
what it looks like, and why it is evidence.

### 4.1 Source-code references — how consumer *code* names the library

**Header includes.** In C and C++, to use a library you almost always include one
of its header files with a line like:

```cpp
#include <zfp.h>
#include <zfp/array.hpp>
```

A header is a file (typically ending in `.h`, `.hpp`, `.hh`, `.hxx`, …) that
declares what the library offers. The tool enumerates the header files the target
project actually ships and turns each into two search patterns:

- The **full include path** as a consumer would write it, e.g. `zfp/array.hpp`.
- The **bare filename** (the "basename"), e.g. `array.hpp` or `zfp.h`.

The reason for both is a subtlety of how C/C++ compilers find headers. A compiler
searches a list of directories (its "include path," configured with `-I` flags).
Depending on which directory a consumer added to that list, the *same* header may
be included as `#include <zfp/array.hpp>` or as `#include <array.hpp>`. The
directory prefix varies between consumers, but the **filename is stable**. So the
tool searches for the filename in a way that allows any leading directory, while
being careful about boundaries so that, for example, `zfp.h` does not accidentally
match `libzfp.h`. Full-path matches are treated as stronger evidence than
bare-filename matches, because a filename alone is more likely to be a
coincidence.

To find the headers in the first place, the tool does not assume the project keeps
them in a folder called `include/`. Many well-known projects do not: some ship
headers under `src/`, some under a top-level folder named after the project, some
under a nested path. The tool enumerates header files wherever they live in the
repository and normalizes each to the path a consumer would actually write.

**C++20 modules.** C++20 (the 2020 revision of the C++ standard) introduced
**modules**, a newer alternative to header includes. A library can declare a
module in a special interface file:

```cpp
export module zfp;          // the library declares a module named "zfp"
```

and a consumer uses it with:

```cpp
import zfp;                  // the consumer imports it — note: no #include
```

This matters because a consumer that uses modules emits **no `#include` line at
all**, so a tool that only searched for includes would completely miss it. The
tool therefore also reads the target project's module-interface files (extensions
such as `.ixx`, `.cppm`, `.mpp`), extracts the module names it declares, and
searches consumers for the matching `import name;`. It also handles the related
"header unit" form, where a consumer writes `import <zfp.h>;` instead of
`#include <zfp.h>`. Module names tend to be distinctive, so they are relatively
strong evidence.

### 4.2 Build-system declarations — how a consumer's *build* wires in the library

Before code can use a library, the consumer's build has to locate and link it.
C/C++ has several competing build and configuration systems, and each has a
characteristic way of naming a dependency.

**CMake** is the most widely used C/C++ build system. A consumer that uses a
library through CMake typically writes:

```cmake
find_package(ZFP REQUIRED)              # locate the library by its package name
target_link_libraries(myapp zfp::zfp)   # link against its exported "target"
```

Two identifiers appear here:

- The **package name** given to `find_package` (`ZFP`). The tool learns this from
  the target project's CMake files — from the names of its installed configuration
  files (files ending in `Config.cmake`) and from its `project()` declaration.
- The **exported target**, written as `Namespace::Name` (`zfp::zfp`). The
  double-colon form is a strong, distinctive signal because it is specific to how
  that library publishes itself. The tool learns the namespace from the project's
  install rules (`install(EXPORT ... NAMESPACE zfp::)`) and alias definitions.

**pkg-config** is an older, simpler mechanism: a library installs a small `.pc`
file describing how to compile against it, and a consumer's build asks for it by
module name, often via CMake's `pkg_check_modules(... libzfp)`. The tool learns
the module name from the `.pc` file names the project ships.

**Bazel** is another build system (used heavily at large companies). A consumer
declares a Bazel dependency with `bazel_dep(name = "…")` and references it as
`@name//…`. The tool learns the Bazel module name from the project's
`MODULE.bazel` file.

**Compiled library artifacts.** On Windows/MSVC, code can request a specific
compiled library by name with `#pragma comment(lib, "zfp")`. On Unix-style
builds, a compiled library is requested with a `-lzfp` linker flag. The tool
learns the artifact name (`libzfp`) from the project's build files.

These build-level identifiers are valuable because they are **specific by
context**: the surrounding syntax (`find_package(...)`, `Namespace::`,
`pkg_check_modules(...)`) makes a match hard to confuse with unrelated text.

### 4.3 Source-control identity — how a consumer pulls the library by identity

Many consumers do not go through a build system's package lookup at all. They pull
the library's *source* directly into their own tree, referencing it by its
repository. The repository slug (`owner/name`) and URL are the **one truly
unambiguous identifier** — there is no name-mapping guesswork involved. Consumers
reveal it in several ways:

- **Git submodules**: a `.gitmodules` file records the URL of another repository
  embedded inside this one.
- **CMake `FetchContent` / `ExternalProject`**: build-time instructions that name
  a `GIT_REPOSITORY` URL to download.
- **CPM** (a popular CMake add-on): a shorthand like `gh:owner/repo`.

Because the repository URL is unambiguous, a match on it is the strongest single
piece of evidence the tool can find.

### 4.4 Package-registry names — optional corroboration

The opt-in package managers mentioned earlier (Spack, Conan, vcpkg) are not
ignored — they are folded in as *additional* evidence. When enabled, the tool
looks up the name a registry gives the target project and adds it to the search
identifiers. This turns a registry's renaming (Spack's `py-` prefix, for instance)
from a mismatch into extra coverage. Registries are also used in reverse — see
Part 7 — but always as corroboration, never as the source of truth.

### 4.5 Fallbacks — project name and custom patterns

If the richer facets above yield little (for example, the project's files are not
indexed, or it has an unusual layout), the tool falls back to conventional guesses
built from the project's short name (`name.h`, `find_package(name)`, `libname`). A
user can also supply a custom search pattern to catch usage that does not fit any
convention — for example, a language binding in Python or Rust that wraps the
C/C++ library.

### 4.6 Why this multi-facet approach

No single facet is reliable on its own, and different consumers reveal themselves
in different ways: one vendors the source as a submodule, another calls
`find_package`, another just includes a header. Searching *all* facets at once is
what makes the net wide. And because each facet carries a different strength, the
combination is also what lets the tool judge *confidence*: a project that both
references the repository URL **and** calls `find_package` **and** includes a
header is far more certainly a real dependent than one that merely mentions a
common header filename once.

---

## Part 5 — Controlling false positives without throwing away leads

A wide net catches noise. The tool's precision does **not** come from discarding
uncertain matches; it comes from scoring and labeling them so a reader can trust
the strong ones and review the weak ones. There are four mechanisms.

### 5.1 Frequency gating: drop tokens too common to mean anything

Some identifiers are worthless because they are everywhere. A project that ships a
header called `config.h`, or is named `core`, would "match" a huge fraction of all
open-source code purely by coincidence. To prevent this, the tool measures how
common a candidate token is across the entire global code index (a quick count
query) and drops or down-weights tokens that are too common to attribute to any
one project. Tokens that appear rarely are distinctive and kept at full strength;
tokens that saturate the index are discarded.

Crucially, this gating is applied **only to low-context tokens** — bare header
filenames, generic single-word directory names, and bare project names. It is
never applied to build-system declarations, exported targets, or repository-URL
references, because those are already specific by their surrounding syntax. If it
were applied to them, a *popular* library would be penalized precisely for being
popular: `find_package(GTest)` is common because the GoogleTest library is widely
used, and those matches are real dependents, not noise. These frequency measures
are cached between runs, since a token's global frequency changes slowly.

### 5.2 Corroboration scoring: many independent signals beat one loud one

Every discovered dependency link ("edge") is assigned a numeric confidence and a
tier (**high**, **medium**, or **low**). The score combines:

- the **strongest single signal** matched (its base weight, after any
  frequency adjustment);
- a **corroboration bonus** for each *additional independent kind* of evidence
  that points to the same dependency — an include *plus* a `find_package` *plus* a
  namespaced target is worth far more than three copies of the same include; and
- a small, **bounded volume term** — many matches count for a little more than
  one, but with strongly diminishing returns so that sheer repetition cannot fake
  high confidence.

Matches found inside documentation (README files, `.md`/`.rst` docs) count for
less than matches in real source or build files, because a mention in prose is
weaker evidence of actual use than a line of code.

### 5.3 Evidence layers: weighting *kinds* of evidence by authority

Beyond the per-identifier weights, the tool groups every kind of evidence into an
ordered set of **evidence layers**, reflecting how authoritative that *kind* of
observation is. From weakest to strongest:

1. **Narrative** — prose mentions in documentation.
2. **Source-consumption** — the consumer's code references the library (an
   include, an `import`, a namespace use).
3. **Build-manifest** — the consumer's build declares the library
   (`find_package`, a target, a submodule URL).
4. **Package-registry** — a third-party registry says the consumer uses it.
5. **Binary/link** — evidence that a compiled artifact actually links the library.
6. **Attestation / bill-of-materials** — a formal, machine-generated dependency
   record.
7. **Bibliometric** — an academic citation (a separate, parallel signal; see Part
   8).

This layering feeds the confidence score two ways. First, agreement across
**different layers** is worth more than repetition **within** one layer — a code
reference plus a build declaration plus a registry entry is strong precisely
because those are independent kinds of observation, whereas the same include seen
by three different code-search backends is still just one fact. Second, a lone
piece of high-authority evidence can outrank a lone piece of low-authority
evidence of equal raw weight. As a guard against false positives from the weakest
layer, a link supported *only* by a prose mention is capped at low confidence
until something more authoritative corroborates it.

(Layers 5 and 6 — binary linkage and formal bills of materials — are part of the
scoring model and are the focus of planned data sources; the tool's live discovery
today concentrates in the source-consumption and build-manifest layers, with
package-registry corroboration available as an option.)

### 5.4 Relationship classification: a user is not a copy

Not every repository that contains a library's code is a *user* of it. Some are
**copies**: a bundled/vendored duplicate of the library, or a fork (a
GitHub-hosted clone) of the library itself. Counting those as dependents would be
misleading. The tool labels each edge:

- **`VENDORED`** — the repository reproduces most of the target's header surface,
  i.e. it contains a bundled copy of the library rather than merely using it.
- **`MIRROR`** — the repository is a GitHub-recorded fork of the library.
- **`DEPENDS_ON`** — everything else: a genuine consumer.

Copies are **labeled, not deleted**, so the information is preserved and a reader
can filter as they wish.

---

## Part 6 — How it works under the hood: technology and workflow

### 6.1 Technology stack

- **Language and dependencies.** The core engine is a single Python program
  (`audit_dependents.py`), targeting Python 3.10 or newer. Its only third-party
  dependency is the `requests` HTTP library. Everything the engine does is done
  over ordinary HTTP calls to public services; it does not run a database, and it
  does not download or compile any of the code it analyzes.
- **The code index: Sourcegraph.** The engine's window into the world's public
  source code is **Sourcegraph**, a hosted service that continuously indexes source
  code across millions of public repositories and offers a search API supporting
  regular expressions (a compact language for describing text patterns). The engine
  uses Sourcegraph's **streaming search**: results arrive incrementally over a
  single long-lived connection (a "Server-Sent Events" stream), and the service
  reports explicitly when it has truncated results (for example, because a query
  matched too much) rather than silently returning a partial answer. Access
  requires a Sourcegraph token when crawling for dependents.
- **Repository metadata: GitHub.** For each repository discovered, the engine calls
  the **GitHub GraphQL API** (GitHub's structured query interface) once to pull
  metadata: star count, contributor count, commit count, license, latest release,
  description, the default-branch commit hash, and files used for citation
  discovery (see Part 8). A GitHub token raises rate limits and is required for
  this metadata step.
- **Academic sources.** For citations the engine calls **OpenAlex** and
  **OpenCitations** (open scholarly databases), **Crossref** (the DOI registry
  that resolves a paper identifier to its bibliographic record), and a map derived
  from **JOSS** (the Journal of Open Source Software). An optional, self-hostable
  language model can be pointed at a local endpoint to help judge borderline
  papers; it is off by default.
- **Outputs.** The engine writes a JSON dependency graph and a set of **SPDX 2.3**
  files. SPDX ("Software Package Data Exchange") is a widely supported standard
  format for a Software Bill of Materials (SBOM) — a machine-readable list of the
  components a piece of software is built from.
- **Distribution and service.** The same engine ships as a command-line tool, as a
  GitHub Action (packaged in `action.yml`, which installs `requests` and runs the
  script), and as a small web service. The service (under `deploy/service/`) wraps
  the engine with a **Flask** web application served by **gunicorn** (a production
  Python web server) that accepts audit jobs, plus a separate **worker** process
  that runs the queued jobs; jobs and their outputs live in a shared directory, and
  the whole thing is packaged as a **Docker** container image that can play either
  the web or the worker role.

### 6.2 The overall workflow

The engine performs a **breadth-first crawl**. Breadth-first means it fully
processes everything at one level of the dependency tree before going deeper: it
starts with the target project, finds its direct dependents, then (if configured
to go deeper) finds the dependents of those, and so on, out to a user-specified
depth limit. A depth of 0 processes only the target itself (metadata and citations,
no dependent search); a depth of 1 finds direct dependents; higher depths map
multiple tiers, from the root library down toward end-user applications. A
"visited" set prevents processing the same repository twice.

For each repository it processes, the engine runs this ordered pipeline:

1. **Compile the identifier set.** Read the provider's own files to gather all the
   identifiers described in Part 4 — headers, module names, build-system names,
   repository identity, and (optionally) registry aliases — each with its kind,
   provenance, and weight. Header and module discovery use scoped searches and
   reads of the provider's repository; build names come from parsing the provider's
   build files.
2. **Gate for specificity.** Apply the frequency guard from Part 5.1 to the
   low-context identifiers, dropping or down-weighting tokens too common to
   attribute.
3. **Expand to consumption patterns.** Turn each surviving identifier into the
   regular-expression pattern(s) a *consumer* would produce — an `#include`, an
   `import`, a `find_package`, a `Namespace::`, a submodule URL, and so on. All
   patterns are combined into a single search expression, with the identifier
   values safely escaped so that special characters in a name (for example, the
   `++` in a `c++` directory or in `libsigc++`) cannot corrupt the combined
   pattern.
4. **Search the code index.** Run the combined pattern against Sourcegraph's
   streaming search, filtered to exclude forks, archived repositories, and
   vendored/third-party directories unless the user asks to include them. Transient
   failures (rate limiting, temporary server errors) are retried with increasing
   back-off delays, and if the search is truncated or abandoned that fact is
   recorded rather than hidden.
5. **Classify each match.** For every matching line, determine which identifier and
   which kind of evidence it represents, and accumulate, per consuming repository,
   the set of matched identifiers, the counts of each evidence kind, the provenance,
   and the evidence layers involved.
6. **Score and label.** Compute each edge's confidence score and tier (Part 5.2 and
   5.3) and its relationship label — `DEPENDS_ON`, `VENDORED`, or `MIRROR` (Part
   5.4).
7. **Optionally corroborate against registries.** If enabled, reconcile with
   declared package registries (Part 7).
8. **Enrich with GitHub metadata** for each newly discovered repository (Part 6.1).
9. **Attach academic citations** to the node (Part 8).
10. **Emit outputs.** Add the node and its edges to the graph, and write one SPDX
    bill-of-materials file per dependency edge. Newly discovered dependents that are
    within the depth limit are queued for their own turn through the pipeline.

When the crawl finishes, the engine writes the complete graph and a run-level
**completeness** verdict (Part 9.3).

---

## Part 7 — Corroboration from declared package registries

As an optional step, the engine cross-checks its source-derived findings against
opt-in package registries (Spack is implemented; others are a matter of
configuration). Everything is reconciled on the **repository URL**, the one
unambiguous identifier, so that a registry's renaming cannot cause a mismatch.
Registry data plays three roles, always as evidence and never as ground truth:

- **Corroborate** — a project found in source *and* declared by a registry gets a
  confidence boost.
- **Recover** — a project a registry declares but source search missed can be
  added, marked with registry provenance.
- **Alias-feed** — the name a registry uses is added back into the identifier set
  as an extra search term.

---

## Part 8 — Academic citations: measuring scholarly impact

Many C/C++ libraries, especially in scientific computing, are associated with a
published paper, and their usage shows up in the academic literature as well as in
code. The engine attaches publication records to each node in two categories:

- **Seminal** — the project's *own* paper. This is found from standard metadata a
  project may ship: a `CITATION.cff` file, a JOSS entry, or Zenodo/codemeta
  metadata. A paper is identified by its **DOI** (Digital Object Identifier, a
  permanent identifier for a publication).
- **Citing** — papers that reference the project. Starting from the seminal DOIs,
  the engine performs a reverse-citation lookup through OpenAlex and OpenCitations
  ("who cites this paper?"), and also scrapes DOIs from the project's README and
  runs full-text keyword searches. The reverse-citation lookup is a bounded
  breadth-first crawl of its own, so it can optionally follow citations of
  citations, capped to stay tractable.

Every discovered DOI is resolved through Crossref (or the JOSS map) into a uniform
record — title, authors, year, journal, citation count, link — and then
**relevance-scored** rather than blindly attached. A colliding project name (for
example, `zfp` is also a term in an unrelated scientific field) would otherwise
flood the results with false matches. The relevance score corroborates *how* a
paper was found (a reverse citation of the project's own paper is strong; a bare
keyword hit is weak) with textual overlap between the paper and a profile of the
project (shared authors, shared significant terms, shared research concepts,
shared venue). Low-relevance papers are filtered out by default; flags let a user
keep them for inspection or disable scoring entirely. The optional local language
model, when configured, is consulted only for borderline cases.

---

## Part 9 — Outputs

### 9.1 The dependency graph (JSON)

The primary output is a single JSON file describing a graph of **nodes**
(repositories) and **edges** (a consumer-to-provider dependency). Its shape is
pinned by an accompanying schema file (`udg_schema.json`).

Each **node** carries the repository's metadata (owner, stars, contributors,
commits, license, latest release, description), its computed depth in the crawl,
its attached publication records, and its discovery evidence.

Each **edge**, and the discovery data on each node, carries:

- **evidence** — a map of evidence kind (include, `find_package`, target, module
  import, submodule URL, …) to the number of matching lines seen;
- **identifiers** — the specific provider identifiers the consumer was observed
  referencing;
- **provenance** — how each of those identifiers was originally learned;
- **evidenceLayer / layers** — the strongest evidence layer and the full set of
  layers involved (Part 5.3);
- **confidence** and **confidenceScore** — the tier and numeric score;
- **relationship** — `DEPENDS_ON`, `VENDORED`, or `MIRROR`.

Because every edge records *why* it exists and *how strongly*, a consumer of this
output can sort and filter — showing only high-confidence genuine dependents, or
drilling into the exact evidence behind any one link. Uncertain matches are
visibly low-confidence rather than silently mixed in with certain ones.

### 9.2 SPDX bills of materials

For every dependency edge, the engine writes one **SPDX 2.3** file recording the
exact link between the consuming repository and the provider repository, each
pinned to a specific commit hash. These are standard SBOM files that compliance and
security tooling can ingest directly, and they can be published to GitHub to
populate a repository's "used by / dependents" information.

### 9.3 Completeness reporting

A central honesty principle is that a partial result must never masquerade as a
complete one. Two users running the same audit should get the same graph except
where the live data itself has changed. The engine therefore:

- makes its bounded steps **deterministic** — anything that ranks-then-truncates
  does so in a fixed, reproducible order, and nothing depends on unordered data;
- records every dropped request, truncated search, and hit limit as a structured
  diagnostic; and
- rolls those up into a run-level **completeness** verdict in the output — a single
  "complete" flag plus a sorted list of warnings — and a final log line that states
  plainly whether the run was complete. A rate-limited or truncated crawl is
  reported as incomplete, not disguised as "no more results."

---

## Part 10 — Running the tool

The command-line form takes the target repository and short name, a crawl depth,
an output path, and tokens, for example:

```
python audit_dependents.py \
  --repo "LLNL/zfp" --name "zfp" --depth 1 \
  --out dependency_graph.json \
  --sg-token "<sourcegraph token>" --gh-token "<github token>"
```

Tokens can also come from environment variables (`SG_TOKEN`, `GH_TOKEN`,
`AUDIT_EMAIL`). A depth of 0 needs no Sourcegraph token because it does not search
for dependents. `--verbose` switches logging to structured detail.

Notable options group into families:

- **Crawl scope**: `--depth`; `--forks`, `--include-archived`, `--include-vendored`
  to widen what counts; `--search-count` and `--search-delay` to bound and throttle
  each search.
- **Precision controls**: `--no-idf` to disable frequency gating, `--idf-cap` to
  tune it, `--idf-cache` for its cache; `--declared-sources` to enable registry
  corroboration; `--custom-string` / `--custom-file` / `--no-defaults` to override
  or replace the built-in identifier set.
- **Citations**: `--academic-keyword`, `--citation-depth`, `--no-paper-relevance`,
  `--paper-relevance-floor`, `--no-paper-filter`, `--relevance-llm-url` /
  `--relevance-llm-model`, `--paper-cache`.

The GitHub Action exposes the same controls as declarative inputs. The web service
accepts an audit request over HTTP, runs it in the background worker, and serves
the resulting graph and SPDX files back through simple endpoints.

---

## Part 11 — Limitations

This method sees far more than opt-in package managers, but it has real
boundaries, and the tool is deliberately honest about them:

1. **Public code only.** It relies on the public indexes of Sourcegraph and
   GitHub. It cannot see private, proprietary, or internal usage unless it is given
   credentials for those environments.
2. **GitHub-centric today.** Coverage is currently bounded by what the code index
   holds, which is predominantly GitHub. Broadening to other hosts is planned.
3. **Intent, not proven linkage.** The search reads text, not compiled binaries. A
   matched `#include` or `find_package` shows *intent to use* the library; it does
   not prove the code is compiled into a shipping binary (it could be dead code or a
   disabled option). The confidence score reflects strength of evidence, not proof
   of runtime linkage.
4. **Bounded by index completeness.** Accuracy is limited by how complete the
   third-party indexes are at the moment of the run, and very popular providers can
   exceed an index's internal result limits. When that happens it is reported, not
   hidden.
5. **Unconventional layouts yield thinner results.** The identifier set is only as
   rich as the provider's own files allow. A project with an unusual header layout
   or build setup, or one whose files are not indexed, produces fewer identifiers.
   The design goal is graceful degradation: no single weak or missing signal is
   decisive.
6. **Confidence, not ground truth.** Both the source heuristics and the optional
   registry corroboration are best-effort evidence. A high-confidence,
   multiply-corroborated edge is very likely a real dependency; a low-confidence
   edge is a lead for a human to review, not an assertion.
7. **Citation context is ambiguous.** Attaching a paper captures that an academic
   reference exists, not its exact meaning — a README might cite the paper behind an
   algorithm rather than the project itself. Relevance scoring mitigates this but
   does not eliminate it.

---

## Appendix — Glossary

- **Build system** — software that compiles a project and links its dependencies.
  Common C/C++ ones: CMake, Bazel; pkg-config is a related configuration helper.
- **Header / header include** — a C/C++ file declaring a library's interface,
  pulled in by a consumer with `#include`.
- **C++20 modules** — a newer way (from the 2020 C++ standard) to consume a library
  with `import` instead of `#include`.
- **CMake `find_package` / target** — the CMake calls that locate a library and link
  a consumer against its published "target" (written `Namespace::Name`).
- **pkg-config** — a mechanism where a library ships a `.pc` description and
  consumers ask for it by module name.
- **Git submodule / FetchContent / CPM** — three ways a consumer embeds or downloads
  another repository by its URL.
- **Sourcegraph** — the hosted service that indexes public source code and answers
  regular-expression searches across it.
- **Regular expression (regex)** — a compact notation for describing text patterns
  to search for.
- **GraphQL** — a structured query language for APIs; used here to fetch GitHub
  repository metadata.
- **DOI / Crossref / OpenAlex / OpenCitations / JOSS** — a publication's permanent
  identifier, the registry that resolves it, two open scholarly databases, and the
  Journal of Open Source Software, respectively.
- **SPDX / SBOM** — a standard file format (SPDX) for a Software Bill of Materials
  (SBOM), the machine-readable list of components in a piece of software.
- **Node / edge** — in the output graph, a repository and a dependency link between
  two repositories.
