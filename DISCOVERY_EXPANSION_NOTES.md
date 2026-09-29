# Discovery Expansion — Research Notes

Working scratchpad for expanding C++ dependent detection beyond `#include`-based
header matching, and widening where we scrape association data from. **Not a plan
yet** — these are captured ideas to grow as we research. We'll draft a detailed,
phased plan (ROADMAP-style) once the exploration settles.

Everything here must slot into existing invariants: new *language* signals become
`IdentifierKind`s (+ `_patterns_for_identifier` entry + an extractor); new *scrape*
sources become `DECLARED_REGISTRIES` configs reconciled on **repo URL**, folded in
as corroboration / recall / alias — never ground truth. Label-then-filter, never
hard-drop recall.

Status legend: 🔵 idea · 🟡 researching · 🟢 validated / ready to plan · ⚪ parked

---

## Part 1 — Language-structure signals beyond `#include`

Today language-level detection is one mechanism: header identifiers matched vs
`#include` ([audit_dependents.py:2165](audit_dependents.py:2165)). Everything else
is build-system structure. C++ itself offers more consumption surfaces.

| # | Signal | Provider extraction | Consumer pattern | Weight | Gate | Status | Notes |
|---|---|---|---|---|---|---|---|
| 1a | **C++20 modules** `MODULE_NAME` | `export module X;` in `.ixx/.cppm/.mpp` | `import X;` | 4–5 | no | 🔵 | **Highest value.** Invisible to `#include` today. Exclude `std`/`std.compat` |
| 1a′ | header units (reuse header ids) | existing | `import <x.h>;` / `import "x.h";` | as header | as header | 🔵 | Cheap alt-pattern on existing header kinds |
| 1b | **Export macro** `EXPORT_MACRO` | `*_export.h`, `generate_export_header`, `__declspec(dllexport)` | `\bNAME_API\b` | 2 | no | 🔵 | Co-occurs w/ include → corroboration only, not primary |
| 1b′ | **Plugin entry** `PLUGIN_SYMBOL` | provider's `extern "C"` entry contract | `extern "C" ... SYMBOL` | 5 | no | 🔵 | Narrow, high-precision. Plugin hosts only (LLVM/Qt/OBS/…) |
| 1c | **C++ namespace** `CPP_NAMESPACE` | top-level `namespace X {` in public headers | `\bX::` | 2–3 | yes (IDF) | 🔵 | Independent corroboration of include; gate generics (core/util/io) |

Parked: `using namespace foo;` (subsumed by `X::`), forward-decl coupling (rare),
Obj-C++ `@import` (Apple-only, low priority).

---

## Part 2 — Where else to scrape (all URL-reconciled)

Have today: Sourcegraph (code), GitHub (metadata), Spack (1 live declared-source;
vcpkg/Conan/Repology/GitHub-dependents are configured-but-dormant slots).

| # | Source | What it gives | Join | Effort | Status | Notes |
|---|---|---|---|---|---|---|
| 2a | **vcpkg** ports + consumer `vcpkg.json` | `"dependencies"` edges | URL | low | 🔵 | Dormant `DECLARED_REGISTRIES` slot; GitHub-hosted, Sourcegraph-greppable |
| 2a | **Conan** center + consumer `conanfile.py/.txt` | `requires`/`self.requires` | URL | low | 🔵 | Strongest modern-C++ declared signal |
| 2a | **Repology** | package aliases across 40+ distros | URL | low | 🔵 | Best as **alias** feeder, not dependent source |
| 2b | **Nixpkgs** `buildInputs` | pkg-level reverse-deps | Homepage/src URL | low-med | 🔵 | On GitHub → greppable. Do first among distros |
| 2b | **Debian** `Build-Depends` (UDD) | pkg-level reverse-deps | Homepage URL | med | 🔵 | corroboration + alias |
| 2b | **Fedora** `BuildRequires` (repoquery) | pkg-level reverse-deps | URL | med | 🔵 | corroboration + alias |
| 2c | **GitHub Dependency Graph / Dependents** | first-party reverse edges | native | med | 🔵 | Dormant slot. C++ coverage weaker; reverse view needs scrape/SBOM |
| 2c | **GitHub SBOM export** `/dependency-graph/sbom` | consumer's dep list (SPDX) | native | low-med | 🔵 | Confirms an edge with first-party provenance |
| 2d | **ClearlyDefined** | normalized declared deps | URL | med | 🔵 | Free API |
| 2d | **deps.dev** | reverse-dep graph | URL | — | ⚪ | **C/C++ coverage minimal today** — watch, don't build on |
| 2d | **Software Heritage** | full VCS archive | URL/content | med | 🔵 | Sourcegraph *fallback* for non-GitHub/unindexed providers; vendored-copy confirm |
| 2d | published **SBOMs in the wild** | authoritative declared edge | URL | med | 🔵 | grep `*.spdx.json`/`bom.json` naming the provider |
| 2e | **CI configs** (`apt/vcpkg/conan install <you>`) | strong install-intent edge | native | low | 🔵 | Cheap Sourcegraph content pattern; strong corroboration |
| 2f | **Docs/README prose** ("requires zfp") | low-precision hints | native | low | 🔵 | Reuse citation text-scrape channel; keep at `low` tier only |

---

## Part 3 — Code-search backends (Sourcegraph alternatives) + politeness

Motivation: reduce single-vendor dependence on Sourcegraph, and widen host
coverage (esp. non-GitHub) **without becoming a scraper**. Guiding principle:
**prefer hosted aggregator indexes over crawling origins.** Each index has already
crawled the world politely and collapses our load onto one rate-limited API — the
opposite of pointing a crawler at thousands of self-hosted GitLab instances. If we
ever must touch an origin, use its *search API* (never HTML scrape), respect
robots.txt, conditional requests, concurrency ≤1–2, backoff on 429/`Retry-After`,
an identifiable `User-Agent`, and cache aggressively.

| Backend | Corpus | Regex | API | Hosts | Cost | Status | Fit |
|---|---|---|---|---|---|---|---|
| **Sourcegraph public** (have) | 2M+ OSS repos | yes | streaming SSE (token) | multi | free\* | 🟢 | Current primary. \*Commercial goodwill — changelog shows ongoing removals → single-vendor **risk** |
| **grep.app** (Grep by Vercel) | ~1M+ **GitHub** repos | yes | unofficial (MCP wrapper exists) | GitHub only | free | 🟡 | Best **supplement/fallback** for GitHub code; confirm API stability/terms |
| **searchcode** | GitHub+GitLab+Bitbucket+SourceForge | limited | documented free API | **multi-host** | free | 🟡 | Non-GitHub **recall** — smaller/older index, weaker regex |
| **Debian Code Search** | ~130 GB, ~17k src pkgs | RE2 | `/api/v1/searchperpackage` JSON, API keys | Debian src | free | 🟢 | **Purpose-built C/C++ consumer corpus** + doubles as distro angle (§2b). Polite by design. Strong fit |
| **GitHub Code Search** REST | all GitHub | no (token match) | official | GitHub only | free | 🟡 | First-party, authoritative, but **10 req/min** + no true regex → low-throughput corroboration only |
| **GitLab.com search** | gitlab.com projects | advanced (ES) | official API | gitlab.com | free | 🔵 | Covers gitlab.com via **API** — avoids scraping self-hosted instances |
| Zoekt / Hound | self-indexed | yes | self-host | any | infra | ⚪ | Would make **us** the crawler — avoid unless we control the corpus |
| Software Heritage | full VCS archive | limited content search | API | multi | free | 🔵 | Archival / **vendored-copy confirmation**, non-GitHub fallback |

**Self-hosted GitLab stance (locked-ish):** do **not** crawl arbitrary self-hosted
GitLab. Coverage, effort, and politeness all argue against it amid the current
AI-scraping backlash. Cover gitlab.com via its search API; cover the long tail via
searchcode's index (already crawled politely on our behalf). Revisit only with a
specific high-value instance + its API + explicit rate discipline.

**Backend abstraction idea:** today discovery is welded to Sourcegraph's SSE. A
thin `SearchBackend` seam (query → normalized hits) would let us (a) fail over when
Sourcegraph degrades, (b) fan a query across grep.app + Debian CS + searchcode and
merge on repo URL, (c) keep each backend's politeness/rate config local. Parallels
the existing `EcosystemPlugin` / `DECLARED_REGISTRIES` extension-point style.

---

## Part 4 — Where C++ actually lives (host landscape)

Beyond GitHub. Goal is recall across the whole ecosystem, but reached through
**indexes** (Part 3), not by us crawling each host. Grouped by how we'd reach them.

**General forges (reach via searchcode / their own APIs):** GitLab.com, Bitbucket,
SourceForge, Codeberg + the Gitea/Forgejo fleet, Launchpad, GNU Savannah.

**Big self-hosted GitLab/Gerrit (high-value, API-only, polite):** freedesktop.org,
KDE Invent, GNOME GitLab, Chromium/AOSP `googlesource.com` (Gerrit), LLVM, Qt Gerrit,
Apache GitBox, Eclipse, CERN. Each is a large *curated* C++ corpus — worth targeting
individually via API before any generic crawl.

**Distro / packaging source trees (also feed Part 2 + Part 5):** Debian
(sources.debian.org), Fedora dist-git (src.fedoraproject.org), Arch/AUR, Gentoo ebuild
tree, Nixpkgs, FreeBSD/OpenBSD ports, Homebrew formulae, **conda-forge feedstocks**
(GitHub-hosted `meta.yaml` w/ `run_exports` — strong C/C++ ABI-dep signal, greppable),
vcpkg ports, Conan center, Spack.

**Archive / catch-all:** Software Heritage archives ~all of the above — the backstop
for dead hosts (Google Code, Gitorious) and non-GitHub providers.

**Scientific/HPC deposits:** Zenodo, HAL, OSF, figshare — code+DOI, ties into the
existing citation engine.

Status: 🔵 all. Key insight: most "small volume" hosts are already inside an index or
Software Heritage, so the marginal move is picking indexes/APIs that cover them, not
adding N bespoke crawlers.

---

## Part 5 — Binary-scan & SBOM evidence (new evidence *class*)

New idea class: dependency facts derived from **compiled artifacts** and **published
bills of materials**, not source text. Higher authority (a real link edge), coarser
granularity (package/binary), and — crucially — **someone already did the scan**.

**Distro binary dependency graphs = published binary-scan results at scale.** Distro
build farms run `dpkg-shlibdeps` / RPM auto-dep generators that scan every ELF for
`NEEDED` sonames and publish the resulting dependency graph. This is authoritative
"who links libfoo" data covering the entire archive:
- **Debian/Ubuntu** — `Depends`, `shlibs`/`symbols`, soname graph via UDD / `apt-rdepends`.
- **Fedora/RHEL** — soname `Provides`/`Requires`; `dnf repoquery --whatrequires 'libfoo.so.1()(64bit)'`.
- **conda-forge** — `run_exports` ABI pins (source-side, GitHub-greppable).
- Maps to a repo via the package's upstream/Homepage URL (same join problem as §2b).

**Published SBOM corpora (confirmed to exist, free):**
- **GitHub Dependency-Graph SBOM export** (`/dependency-graph/sbom`) — per-repo SPDX, first-party.
- **Zenodo SBOM datasets** — a 100k+ GitHub-repo SPDX set (2025) and **"Wild SBOMs"** (~78k SBOMs mined from 94M repos). Static but large; grep for docs naming the provider.
- **SBOM search tooling** — `sbomgr` (search repos by name/PURL/CPE/checksum), `github-sbom-toolkit`, `sbomqs`. Reusable rather than reinventing SBOM parsing.
- **In-the-wild SBOMs** — `*.spdx.json` / CycloneDX `bom.json` committed to repos; grep for ones whose `relationships`/`components` name the provider = authoritative declared edge.

**Provenance/attestation (watch):** Sigstore/SLSA attestations, GUAC (ingests SBOMs
into a graph), OSV.dev (vuln ranges, not dependents). ⚪ — emerging, C++ coverage thin.

Caveats: binary/SBOM edges are **package-granular** and need URL reconciliation; they
**corroborate/recall**, and their authority (real link vs. inferred include) is a
genuinely *new, strong* evidence tier worth modeling explicitly (see Part 6).

---

## Part 6 — Organizing framework: from "arbitrary pile" to an evidence taxonomy

The real ask: stop being a semi-arbitrary collection of sources. The fix isn't fewer
sources — it's a **taxonomy** every source slots into deliberately, so the pile becomes
a matrix with visible cells and visible *gaps*. This generalizes the existing
identifier-set thesis (a bag of loosely-coupled *identifiers*) up one level to a bag of
loosely-coupled *evidence sources*, still all reconciled on **repo URL**, still
label-then-filter.

**Axis A — Evidence layer** (what kind of fact; roughly increasing authority):
1. **Narrative** — prose/docs "uses zfp" (weakest).
2. **Source-consumption** — code references (`#include`, `import`, `X::`, macros). *Current core.*
3. **Build-manifest** — declared intent (CMake/`vcpkg.json`/`conanfile`/CI install).
4. **Package-registry** — third-party curated packaging (Spack/Conan/distro recipe).
5. **Binary/link** — compiled artifact actually links it (soname graph). *New (Part 5).*
6. **Attestation/SBOM** — signed/first-party bill of materials. *New (Part 5).*
7. **Bibliometric** — academic citation. *Existing, orthogonal.*

**Axis B — Directionality:** forward (provider declares) · reverse (consumer declares) ·
third-party assertion (registry/distro/SBOM about someone else).

**Axis C — Granularity:** repo · package · binary/artifact · symbol.

**Axis D — Reach:** direct API · hosted index (Part 3) · static corpus · origin crawl (avoid).

**Payoff.** Every current + proposed source becomes one cell `(layer, direction,
granularity, reach)`. Benefits:
- **Principled, not arbitrary** — we add a source to fill a *named gap*, not because it exists.
- **Layer → confidence** — evidence layer feeds the existing scorer as a first-class
  weight (a binary-link or SBOM edge outranks a lone narrative mention), extending
  `KIND_WEIGHTS`/corroboration rather than replacing it.
- **Coverage map** — we can literally chart which cells are filled and prioritize holes.
- **Backend seam falls out** — Axis D is exactly the `SearchBackend`/`DeclaredProvider`
  abstraction; sources plug in without bespoke wiring.

### The matrix

One row per named source / channel / language facet from Parts 1–5 + 7 (plus the
current baseline kinds it must slot beside). Where a source spans two cells it gets
two rows (e.g. vcpkg = registry *and* consumer manifest; GitHub = dep-graph *and*
SBOM). Axis B: **fwd** = provider declares · **rev** = consumer declares · **3p** =
third-party assertion. Axis D: **API** = direct API · **index** = hosted index
(Part 3) · **static** = static corpus · **crawl✗** = origin crawl, avoided. Grouped
Part-4 host clusters share one cell, so they share one row.

| Source / Channel | Axis A layer | B | C granularity | D reach | Primary role | ⚑ |
|---|---|---|---|---|---|---|
| Docs/README prose "requires zfp" §2f | 1 Narrative | rev | repo | index | corroboration (low tier only) | 🔵 |
| Header path ↔ `#include` (baseline) | 2 Source-consumption | rev | symbol | index | discovery | 🟢 |
| C++20 modules `import X;` §1a | 2 Source-consumption | rev | symbol | index | discovery / recall | 🔵 |
| Header units `import <x.h>` §1a′ | 2 Source-consumption | rev | symbol | index | recall | 🔵 |
| Export macro `NAME_API` §1b | 2 Source-consumption | rev | symbol | index | corroboration | 🔵 |
| Plugin entry `PLUGIN_SYMBOL` §1b′ | 2 Source-consumption | rev | symbol | index | recall (narrow) | 🔵 |
| C++ namespace `X::` §1c/§7 | 2 Source-consumption | rev | symbol | index | recall + corrob | 🔵 |
| Provider macros `PROV_MACRO` §7 | 2 Source-consumption | rev | symbol | index | corrob + recall | 🔵 |
| Version/config macros §7 | 2 Source-consumption | rev | symbol | index | corroboration | 🔵 |
| Distinctive type names `API_TYPE` §7 | 2 Source-consumption | rev | symbol | index | recall (C-libs) | 🔵 |
| Function / prefix family `API_SYMBOL` §7 | 2 Source-consumption | rev | symbol | index | recall (C-libs) | 🔵 |
| CPO specialization `CPO_SPECIALIZE` §7 | 2 Source-consumption | rev | symbol | index (structural) | corroboration | 🔵 |
| Base-class inheritance `API_BASE` §7 | 2 Source-consumption | rev | symbol | index (structural) | corroboration | 🔵 |
| User-defined literals §7 | 2 Source-consumption | rev | symbol | index | corroboration | 🔵 |
| Dynamic-load strings `dlopen("libfoo")` §7 | 2 Source-consumption | rev | symbol | index | recall (plugins) | 🔵 |
| Generated byproduct paths (`*.pb.h`,`moc_*`) §7 | 2 Source-consumption | rev | repo | index | recall (tool use) | 🔵 |
| Codegen input paths (`*.proto`,`*.fbs`) §7 | 2 Source-consumption | rev | repo | index | recall (tool use) | 🔵 |
| Toolchain/pragma markers (`#pragma omp`) §7 | 2 Source-consumption | rev | symbol | index | tag (weak edge) | 🔵 |
| Sourcegraph public §3 | 2 Source-consumption | rev | symbol/repo | index | discovery (primary) | 🟢 |
| grep.app §3 | 2 Source-consumption | rev | symbol/repo | index (GitHub) | recall / fallback | 🟡 |
| searchcode §3 | 2 Source-consumption | rev | symbol/repo | index (multi-host) | recall (non-GitHub) | 🟡 |
| Debian Code Search §3 | 2 Source-consumption | rev | symbol/repo | API (Debian src) | discovery / recall | 🟢 |
| GitHub Code Search REST §3 | 2 Source-consumption | rev | symbol/repo | API (GitHub) | corroboration (low throughput) | 🟡 |
| GitLab.com search §3 | 2 Source-consumption | rev | symbol/repo | API (gitlab.com) | recall | 🔵 |
| Zoekt / Hound self-index §3 | 2 Source-consumption | rev | symbol/repo | crawl✗ | (avoid — makes us the crawler) | ⚪ |
| Software Heritage content §2d/§3 | 2 Source-consumption | rev | repo/content | static / API | recall + vendored-copy confirm | 🔵 |
| General forges (GitLab.com, Bitbucket, SourceForge, Codeberg/Gitea/Forgejo, Launchpad, Savannah) §4 | 2 Source-consumption | rev | repo | index / API | recall (non-GitHub) | 🔵 |
| Big self-hosted GitLab/Gerrit (freedesktop, KDE, GNOME, googlesource, LLVM, Qt, Apache GitBox, Eclipse, CERN) §4 | 2 Source-consumption | rev | repo | API (per-instance) | recall (curated C++) | 🔵 |
| CMake `find_package`/target/artifact (baseline) | 3 Build-manifest | rev | package/symbol | index | discovery / corrob | 🟢 |
| pkg-config / Bazel module (baseline) | 3 Build-manifest | rev | package | index | corroboration | 🟢 |
| Consumer `vcpkg.json` dependencies §2a | 3 Build-manifest | rev | package | index | corroboration | 🔵 |
| Consumer `conanfile.py/.txt` requires §2a | 3 Build-manifest | rev | package | index | corroboration (strong modern-C++) | 🔵 |
| CI configs (`apt/vcpkg/conan install`) §2e | 3 Build-manifest | rev | package/repo | index | corroboration (strong) | 🔵 |
| GitHub Dependency Graph / Dependents §2c | 3 Build-manifest | rev | package/repo | API | recall / corrob | 🔵 |
| `-lfoo` link flags in Make/`*.mk` §7 | 3 Build-manifest | rev | binary/artifact | index | recall | 🔵 |
| Spack (live declared-source, baseline) | 4 Package-registry | 3p | package | index | corroboration / alias | 🟢 |
| vcpkg ports registry §2a | 4 Package-registry | 3p | package | index | corroboration / alias | 🔵 |
| Conan center registry §2a | 4 Package-registry | 3p | package | index | corroboration / alias | 🔵 |
| Repology §2a | 4 Package-registry | 3p | package | API | alias (40+ distros) | 🔵 |
| Nixpkgs `buildInputs` §2b | 4 Package-registry | 3p | package | index | corrob / recall | 🔵 |
| Debian `Build-Depends` (UDD) §2b | 4 Package-registry | 3p | package | API | corrob / alias | 🔵 |
| Fedora `BuildRequires` (repoquery) §2b | 4 Package-registry | 3p | package | API | corrob / alias | 🔵 |
| ClearlyDefined §2d | 4 Package-registry | 3p | package | API | corroboration | 🔵 |
| deps.dev §2d | 4 Package-registry | 3p | package | API | recall (C/C++ thin — watch) | ⚪ |
| conda-forge `run_exports` §4/§5 | 4 Package-registry | 3p | package | index | corrob (ABI-oriented, greppable) | 🔵 |
| Other distro trees (Homebrew, Gentoo, Arch/AUR, FreeBSD/OpenBSD ports) §4 | 4 Package-registry | 3p | package | index / API | corrob / alias | 🔵 |
| Debian/Ubuntu soname graph (`Depends`/`shlibs`/`symbols`, apt-rdepends) §5 | 5 Binary/link | 3p | binary/artifact | API (UDD) | recall / corrob (authoritative link) | 🔵 |
| Fedora/RHEL soname `Provides`/`Requires` (`repoquery --whatrequires`) §5 | 5 Binary/link | 3p | binary/artifact | API | recall / corrob (authoritative link) | 🔵 |
| GitHub SBOM export `/dependency-graph/sbom` §2c/§5 | 6 Attestation/SBOM | rev (first-party) | package | API | corroboration (first-party) | 🔵 |
| In-the-wild SBOMs (`*.spdx.json`/CycloneDX `bom.json`) §2d/§5 | 6 Attestation/SBOM | rev / 3p | package | index (grep) | corroboration (declared edge) | 🔵 |
| Zenodo SBOM datasets / "Wild SBOMs" §5 | 6 Attestation/SBOM | 3p | package | static | recall (one-shot seed) | 🔵 |
| Sigstore/SLSA · GUAC · OSV.dev §5 | 6 Attestation/SBOM | 3p | package | API | watch (C++ coverage thin) | ⚪ |
| Citations / OpenAlex / OpenCitations (existing engine) §4/§6 | 7 Bibliometric | 3p | repo | API | orthogonal signal | 🟢 |
| Scientific deposits (Zenodo/HAL/OSF/figshare) code+DOI §4 | 7 Bibliometric | rev | repo | API | seminal-DOI + alias | 🔵 |

Not sources but **layer-6 tooling** (reuse, don't reinvent): `sbomgr` (search by
name/PURL/CPE/checksum), `github-sbom-toolkit`, `sbomqs`. The **`HeaderApiExtractor`**
(§7) is likewise an *enabler* for the layer-2 symbol facets, not a cell of its own.

### Coverage map

Axis A (evidence layer, rows) × Axis C (granularity, columns). Reach/direction are
folded away here on purpose — this grid is only for spotting filled vs. empty cells.

| Layer ↓ / Granularity → | repo | package | binary/artifact | symbol |
|---|---|---|---|---|
| **1 Narrative** | Docs/README prose | — | — | — |
| **2 Source-consumption** | SWH content · codegen/byproduct paths · forge & backend repo-hits | — | — | `#include` · modules · header units · export/plugin/namespace macros · `PROV_MACRO`/version macros · `API_TYPE` · `API_SYMBOL` · CPO · base-class · UDL · dlopen strings · toolchain tags **(saturated)** |
| **3 Build-manifest** | CI configs · GitHub dep-graph | CMake `find_package` · pkg-config/Bazel · `vcpkg.json` · `conanfile` · GitHub dep-graph | `-lfoo` link flags | CMake `::` target · `-lfoo` |
| **4 Package-registry** | *(URL-join only)* | Spack · vcpkg · Conan · Repology · Nixpkgs · Debian BD · Fedora BR · ClearlyDefined · deps.dev⚪ · conda-forge `run_exports` · Homebrew/Gentoo/Arch/FreeBSD | — | — |
| **5 Binary/link** | — | *(rolls up from artifact)* | Debian/Ubuntu soname · Fedora/RHEL soname | — *(empty — needs symbol-table scan; avoid)* |
| **6 Attestation/SBOM** | *(SBOM repo-level)* | GitHub SBOM export · in-the-wild SBOMs · Zenodo/Wild datasets · Sigstore/GUAC/OSV⚪ | — | — |
| **7 Bibliometric** | OpenAlex citations · Zenodo/HAL/OSF/figshare | — | — | — |

**Gaps & observations**
- **Over-concentrated in layer 2 × symbol.** Nearly every §1/§7 facet piles into one
  cell reached almost entirely through code-search indexes. Adding more facets there
  raises *within-layer* correctness but does **not** widen the taxonomy — three
  backends all seeing the same `#include` is one fact, not three.
- **The high-authority layers are the thin ones.** Layer 5 (binary/link) has only two
  distro soname sources and is empty at symbol granularity (real per-symbol link
  evidence would mean scanning binaries ourselves — correctly avoided). Layer 6 is
  present but leans on static corpora + one first-party API. So authority and coverage
  are **inversely** correlated: we are richest exactly where evidence is weakest.
- **The `binary/artifact` column is nearly empty** (only §5 sonames + `-lfoo`), because
  we consume *others'* scans rather than producing our own — consistent with the
  requests-only ethos, but it means layers 5–6 are our leverage points, not layer 2.
- **Layer 2 × package, layer 4 × {binary,symbol}, layer 1 × {package,binary,symbol}
  are empty by nature** (source text isn't package-scoped; a recipe/narrative isn't a
  symbol) — those blanks are *correct*, not gaps to fill.
- **Layer 3 reverse-manifest package cell is filled but dormant** (`vcpkg.json`/
  `conanfile` slots exist, unactivated) — cheap to light up.

**Highest-value fills (2–4):**
1. **GitHub Dependency-Graph SBOM export** (layer 6, package, API, first-party) — turns
   a thin high-authority cell into a *live* one with real reverse provenance. Matches
   working-priority #3.
2. **Distro soname reverse-deps: Debian UDD + Fedora repoquery** (layer 5,
   binary/artifact) — the *only* way to populate layer 5 at all; authoritative "who
   actually links libfoo." **Tension with the provisional priority:** working-priority
   #5 reaches for **Nixpkgs first**, but Nixpkgs `buildInputs` is layer **4** (a recipe),
   so it does *not* touch the empty layer-5 cell. If the goal is filling the emptiest
   valuable cell, Debian/Fedora soname graphs should be lifted above Nixpkgs.
3. **Activate vcpkg + Conan consumer-manifest grep** (layer 3, package, reverse) —
   cheap, mostly config in existing machinery; lights up the dormant reverse-manifest
   cell. Matches working-priority #2.
4. **conda-forge `run_exports`** (layer 4→5 bridge, package) — a greppable ABI-pin
   signal that leans toward binary/link authority *without* us scanning any binary; the
   cheapest step toward the thin layer-5 region.

**Agreement vs. tension with the provisional priority.** Working-priority #1 (C++20
`import`) is genuinely the biggest *correctness* win, but it lands in the already-
saturated layer-2×symbol cell — it deepens a full cell rather than filling an empty
one. The coverage map says the scarce, valuable cells are layers 5–6. Both hold at
once: **modules = biggest within-layer win; SBOM/soname = biggest cross-layer authority
win.** Recommendation: keep modules #1 for precision, but pair it with an SBOM/soname
push (#1–#2 above) so the graph gains *layer diversity*, which the scorer can then
reward (below). Priorities #2 (vcpkg/Conan) and #4 (CI grep) already align with the map;
only the distro item (#5) wants re-pointing from Nixpkgs(L4) to Debian/Fedora(L5).

### How the matrix drives scoring

Axis A becomes a first-class **layer weight** feeding the existing scorer, not a
replacement for it: each matched edge carries the layer of its strongest evidence, and
a per-layer `LAYER_WEIGHT` (Narrative < Source-consumption < Build-manifest <
Package-registry < Binary/link ≈ Attestation/SBOM; Bibliometric orthogonal) sets a
confidence floor/multiplier *on top of* the IDF-scaled `KIND_WEIGHTS` already summed in
`_score_consumer`. So a lone layer-5 soname or layer-6 SBOM edge should clear a higher
tier than a lone layer-1 narrative or even a single layer-2 `#include`, because it is a
real link/declared bill of materials rather than an inferred reference. Crucially, the
`CORROBORATION_BONUS` should reward **distinct layers**, not just distinct kinds or
sources: `#include` + `find_package` + SBOM + soname (four layers) is far stronger than
the same `#include` seen by Sourcegraph *and* grep.app *and* searchcode (three reaches,
one fact) — cross-*reach* agreement de-dupes to one signal, cross-*layer* agreement
stacks. This keeps label-then-filter and URL reconciliation intact (every source still
folds in as corroboration/recall/alias, never ground truth), and preserves the
colliding-name guard: a keyword/narrative-only (layer 1) hit stays capped at `low`
until a higher layer corroborates it.

---

## Part 7 — [OWN TASK] C++ language facets for identifying use — design pass

Its own line of thinking; deepens Part 1. Goal: enumerate the C++ language/structural
surfaces a consumer exposes, and turn the good ones into `IdentifierKind`s. Each facet
judged on: **extractability** (can we auto-derive the identifiers from the provider?),
**distinctiveness** (FP risk), **role** (recall vs corroboration), **consumer surface**,
and **parsing depth** needed.

### The core reframe: read the headers we already find

Today we *discover* provider header **paths** (scoped `type:path` search) but never read
their **contents**. Almost every facet below is mined by one new capability: a
**`HeaderApiExtractor`** that fetches the already-discovered public-header blobs and
regexes out the API surface — `#define`, `namespace`, `class/struct/enum`, `using`/
`typedef`, exported function decls, `operator""`, `template<> struct prov::cpo`. One
extractor unlocks buckets A–D. Provider-blob fetch already exists in spirit
(`_fetch_build_blobs`); generalize it to public headers.

### Two strategic buckets

- **Recall-expanding (fills real gaps).** The real hole is **C-style libraries** (zlib,
  libpng, OpenSSL, sqlite3, curl, ffmpeg): no namespaces, header basenames may be
  generic, and a consumer may not even `#include` the canonical header (transitive, or
  own forward-decls). **DECIDED — per-symbol/type-name matching is out.** Matching bare
  type/function names (`z_stream`, `open`, `init`, `Buffer`) via regex + IDF *will* be
  overwhelmed by generics in the normal C case (confirmed, not worth investigating), and
  accurate API enumeration would need an AST we've ruled out (below). The **only**
  survivor is the **API prefix family** (`sqlite3_`, `SDL_`, `curl_`, `png_`, `av*_`):
  the prefix carries the specificity, so `\bsqlite3_\w+\(` is safe where `\bopen\b` is
  not. But it's **conditional** — it only works when the provider has a distinctive,
  consistent, sufficiently-long prefix; many C libs don't. **When there's no clean
  prefix, we do NOT try symbol-level recall — that C lib's recall comes from the
  higher-authority layers instead** (build-manifest L3, soname L5, SBOM L6 per the Part 6
  matrix). This dovetails with the matrix's core finding: symbol-layer recall is the thin
  spot for C libs; lean on layers 3/5/6 there rather than forcing layer 2.
- **Precision-corroborating (confirms, rarely alone).** Specialization, base-class
  inheritance, provider macros, UDLs — hard to appear by accident, so they strongly lift
  confidence, but usually **co-occur with an include** → corroboration kinds, not primary
  recall. (Exceptions: macros / specialization occasionally the *only* visible signal.)

### Facet catalog

| Bucket | Facet → candidate kind | Provider extraction | Consumer pattern | Distinct. | Role | Gate | Parse |
|---|---|---|---|---|---|---|---|
| A pp | **Provider macros** `PROV_MACRO` | `#define NAME(` / `#define NAME` in public hdrs | `\bNAME\b` (`Q_OBJECT`, `TEST_CASE`, `PYBIND11_MODULE`) | high (prefixed) | corrob + some recall | prefix-safe | regex |
| A pp | **Version/config macros** | `#define PROV_VERSION` | `#if defined(PROV_VERSION)` | high | corrob | no | regex |
| B name | **Namespaces** `CPP_NAMESPACE` (Part 1c) | top-level `namespace X {` | `\bX::` | med (multi-comp high) | recall+corrob | IDF | regex |
| C type | ~~Distinctive type names `API_TYPE`~~ **REJECTED** | — | bare `\bTypeName\b` floods on generics; AST out | low | ✗ dropped | — | — |
| D func | **Function *prefix family*** `API_SYMBOL` (per-symbol dropped) | derive dominant prefix from hdr func-decl histogram (cheap regex, no AST) | `\bsqlite3_\w+\(`, `\bMPI_\w+\(` | high **iff clean prefix** | recall (C-libs, *conditional*) | prefix carries specificity | regex |
| C tmpl | **CPO specialization** `CPO_SPECIALIZE` | provider CPO templates (`formatter`,`hash`,`adl_serializer`) | `template<>\s*struct\s+prov::cpo<` | very high | corrob (strong) | no | structural/regex |
| C base | **Base-class inheritance** `API_BASE` | public base classes (`QObject`,`testing::Test`,`rclcpp::Node`) | `:\s*public\s+prov::Base` | very high | corrob (strong) | no | structural/regex |
| D udl | **User-defined literals** | `operator"" _suffix` in hdrs | `""_json` / `\d+_suffix` | high | corrob | no | regex |
| E link | **Dynamic-load strings** | soname / dll base name | `dlopen\("libfoo`, `LoadLibrary\("foo` | high | recall (plugins) | no | regex |
| E link | **`-lfoo` link flags** | lib artifact (have) | `-lfoo` in Make/`*.mk` | med | recall | IDF | regex |
| F gen | **Generated byproducts** (paths) | codegen output naming (`*.pb.h`,`moc_*`,`*_generated.h`) | `type:path` search | high | recall (tool use) | no | path |
| F gen | **Codegen input files** (paths) | IDL exts (`*.proto`,`*.fbs`,`*.capnp`,`*.ui`,`*.msg`) | `type:path` search | med-high | recall (tool use) | no | path |
| G tool | **Toolchain/pragma markers** | n/a (ecosystem, not one repo) | `#pragma omp`, `.cu`+`__global__`, `mpi.h`+`MPI_` | ecosystem | tag, weak edge | — | regex/path |

Already in Part 1: C++20 modules `import`, header units, export macros, plugin symbols.

### Parsing-depth decision (DECIDED — regex + structural only; AST is out)

The project is **requests-only / regex-over-Sourcegraph**, and that is the hard ceiling.
**DECIDED — no AST extraction.** tree-sitter / libclang would mean cloning provider (and
candidate) sources and running a parser over them — effectively a separate microservice
with its own storage, compute, and ops. Far too heavy for this; explicitly ruled out,
not "deferred." So the two available tiers are:

1. **Regex-extractable now** (no new dep): macros, version macros, namespaces, module
   names, UDLs, file-path facets, dynamic-load strings, `#define`s, and the C-lib
   **prefix family** (dominant prefix derived from a cheap header func-decl histogram).
   → the bulk of Part 7 lives here.
2. **Sourcegraph structural search** (Comby, `patterntype:structural`) — for
   specialization / base-class shapes (`template<> struct fmt::formatter<:[t]>`,
   `: public :[b]`) that regex handles clumsily. **No new dependency.** Ceiling of our
   precision; Comby *rules* still unofficial but base structural is live.

Consequence: accurate per-symbol API enumeration is simply **not on the menu** — the
facets that needed it (`API_TYPE`, per-symbol `API_SYMBOL`) are dropped, and C-lib recall
falls back to the prefix family (when it exists) or to Part 6 layers 3/5/6 (when it
doesn't).

### Priority within Part 7

1. **`HeaderApiExtractor`** (the enabler) — fetch discovered public headers, mine
   macros + namespaces + `#define`s + the dominant func-decl **prefix** (regex only, no
   AST). Unlocks the viable facets.
2. **Provider macros** `PROV_MACRO` — cheap, distinctive, high precision. (Promoted —
   per-symbol C-lib recall is dropped, so this is the top real facet.)
3. **C-library prefix family** `API_SYMBOL` — *conditional* recall, only when a clean
   distinctive prefix exists; otherwise defer that lib's recall to Part 6 layers 3/5/6.
   (Bare type/function-name matching is rejected — generics flood.)
4. **CPO specialization + base-class** corroboration via structural search — precision lift.
5. **Codegen input/byproduct path facets** — cheap `type:path` adds, strong tool-usage recall.
6. **Dynamic-load strings / UDLs / toolchain tags** — niche, add as corroboration.

### Open questions (Part 7)
- ~~C-lib symbol matching precision~~ **RESOLVED:** per-symbol regex+IDF floods on generics;
  only the conditional prefix family survives; AST ruled out. (See buckets + parse decision.)
- ~~Where does tree-sitter/libclang pay off~~ **RESOLVED:** never here — AST is a separate
  microservice, out of scope.
- Prefix derivation: how reliably can a cheap header-func-decl histogram surface the
  dominant prefix, and what's the min length/frequency to accept one (avoid `os_`, `gl`)?
- Provider header-content fetch cost/caching (fetch every public header blob per node).
- Sourcegraph structural search: throughput + indexed-only limits at our query volume.
- De-dup facet overlap: specialization/base already contain `prov::` (namespace kind) —
  model as higher-weight sub-patterns, not double-counted independent kinds.

---

## Working priority (provisional — revisit as research lands)

1. **C++20 modules (`import`)** — real coverage gap, high-precision, reuses Sourcegraph. Biggest correctness win.
2. **Activate vcpkg + Conan declared-sources** — mostly config in existing machinery.
3. **GitHub Dependency-Graph SBOM endpoint** — first-party reverse edges.
4. **CI-config grep** — cheap, strong corroboration.
5. **Distro reverse-deps (Nixpkgs first)** — high recall, alias/corroboration.
6. **`EXPORT_MACRO` / `CPP_NAMESPACE` / `PLUGIN_SYMBOL`** — precision polish once recall is broad.

---

## Open questions / to research further

- Sourcegraph coverage of `.ixx`/`.cppm` files and `import` statements at scale — is module adoption yet high enough to matter? (adoption reality-check)
- Reliable distro-package → repo-URL mapping (Homepage fields are inconsistent).
- GitHub reverse-"Dependents" without HTML scraping — is the SBOM/GraphQL path sufficient?
- Whether `EXPORT_MACRO`/`CPP_NAMESPACE` add real corroboration lift or just noise given they co-occur with `#include`.
- Module *partitions* (`X:part`) and `import std;` handling / stoplist scope.
- grep.app: is there a stable/official/ToS-permitted API, or only the reverse-engineered one behind the MCP wrapper? Rate limits?
- searchcode: current index freshness + regex capability + rate limits; does GitLab/Bitbucket coverage actually add non-GitHub recall we're missing?
- Debian Code Search: `searchperpackage` vs. per-file endpoints; how to map a Debian source package back to its upstream repo URL (reuse §2b mapping problem).
- Do we want a `SearchBackend` seam now (fan-out + failover) or stay Sourcegraph-primary until it actually degrades?
- Binary/SBOM edges: model evidence *layer* (Axis A) as a new first-class scorer weight, or fold each source into existing `KIND_WEIGHTS`? (Part 6 says the former.)
- Distro soname graph (Debian UDD / Fedora repoquery): queryable at scale without hosting a mirror? Package→repo-URL mapping reliability (shared with §2b/§5).
- Published SBOM corpora (Zenodo/Wild SBOMs) are static snapshots — useful as a one-shot recall seed, or too stale? Reuse `sbomgr`/`github-sbom-toolkit` vs. roll our own parse?
- The Part 6 matrix: draw it explicitly and use filled/empty cells to pick what to build first.
- Part 7 is a separate task — schedule a dedicated language-facets research pass; don't fold into the source-side work.
