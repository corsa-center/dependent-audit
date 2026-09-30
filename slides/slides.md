---
theme: default
title: Who Is #include-ing You?
titleTemplate: '%s · CppCon 2026'
info: |
  ## Who Is #include-ing You?
  Measuring the Impact of C++ Libraries - CppCon 2026, John Parent (Kitware).

  A tool that discovers the public projects depending on a C/C++ library by
  reading the world's source code, not trusting package manifests.
author: John Parent
class: text-left
highlighter: shiki
lineNumbers: false
drawings:
  persist: false
transition: slide-left
mdc: true
fonts:
  provider: none
  sans: Barlow
  mono: JetBrains Mono
---

<!-- ============================================================= -->
<!-- 1 · COVER                                                      -->
<!-- ============================================================= -->

<div class="cover-title">
  <span class="ct-lead">Who Is <span class="hash">#include</span>-ing You?</span>
  <span class="ct-sub">Measuring the Impact of C++ Libraries</span>
</div>

<div class="cover-speaker">JOHN PARENT <span class="cs-org">· Kitware</span></div>

<!--
Welcome. This talk is about a question that sounds trivial and turns out to be
one of the harder questions you can ask about the C++ ecosystem:
who actually uses your library?
-->

---
transition: fade
clicks: 2
---

<span class="eyebrow">Before we start: two talks worth your time</span>

# Go see my Kitware colleagues


<div class="talk-cards">

<div class="talk-card" v-click="1">
  <img src="/talk-vito.png" alt="Vito Gamberini, Building C++20 Modules: The Rest of the Story" />
  <div class="tc-cap">This morning, time machine not included</div>
</div>

<div class="talk-card" v-click="2">
  <img src="/talk-bill.png" alt="Bill Hoffman, CMake: Making Hard Things Easy" />
  <div class="tc-cap">Friday 9am</div>
</div>
</div>

<!--
Quick shout-out before I start. Two of my Kitware colleagues are speaking here,
and both topics are load-bearing for this talk. Vito on C++20 modules: a module
import is one of the ways a dependent reaches for you, and it emits no #include
at all. Bill on CMake: exported targets are the single strongest build-system
identifier we key on. Go see both.
-->

---
layout: statement
transition: fade
clicks: 2
---

# How many of you can name **the dependencies** of a codebase you work on?

<AudiencePoll :step="$clicks" :raised="0.82" caption="Hint: your build system does" />

<!--
Ask it for real and wait. Hands go up across the room. Everyone knows what they
pull in: it is in the manifest, the find_package calls, the submodules. This is
the easy direction, and the audience feeling that is the point.
-->

---
layout: statement
transition: fade
clicks: 2
---

# Who can name **every project that depends on you**?

<AudiencePoll :step="$clicks" :raised="0.04" />

<!--
Same question, reversed. Wait through the pause. One or two brave hands, maybe.
Nobody actually knows their dependents, because nothing hands you that graph.
Let the contrast with the previous slide sit before you move on.
-->

---
layout: statement
transition: fade
---

<span class="eyebrow">The question behind the talk</span>

# You (or some tool) can list your **dependencies** easily.

**Nothing tells you what depends on you**.

<!--
That gap, easy one way and near impossible the other, is the whole talk. Let's
motivate why closing it matters before we solve it.
-->

---
layout: section
index: 1
---

<span class="eyebrow">Motivation</span>

# Why should you care?

---

# Everything is a stack of dependencies

<div class="center-col" style="margin-top:0.4rem">

<StackTower :step="$clicks" />

</div>

<div v-click="4" class="text-center lead-in" style="max-width:820px;margin:1.5rem auto 0">
Every one of us is someone's dependent, all the way down the stack. <span class="gold">Measuring who sits above <em>you</em> is the whole point.</span>
</div>

<!--
Click through: the stack builds, the forgotten compression library lights up and
ships a breaking change, and your project up top is suddenly unhappy. The point:
every one of us is a dependent, all the way down the stack until it bottoms out
on physics. That reach, upward, is exactly what this tool measures.
-->

---
clicks: 2
---

# Your code (usually) is a cut-vertex

<div class="cols-2 items-center">
<div class="center-col">

<GraphFlip :step="$clicks" />

</div>
<div>

<div v-click="0">

**As a source**, you point *down* at what you consume.
That graph is handed to you: a manifest, a `find_package`, a submodule, etc.

</div>

<div v-click="1" class="mt-4">

**As a sink**, an unknown number of projects point *at you*.
Nobody hands you that graph. <p></p> <span class="gold">How do we find that information?</span>

</div>

<div v-click="2" class="mt-4">

Fuse both halves and you are the **knot in a bowtie**: fan-in above, fan-out below. <span class="gold">This talk computes the top half.</span>

</div>

</div>
</div>

<!--
Same node, two roles. Flip the card on click, then fuse both halves into the
full bowtie: dependents fanning in, dependencies fanning out, you at the pinch
point. The whole talk is about computing that top half, which no registry will
just give you for C++.
-->

---

# The most information we can get in one place, easily, right now

<div class="cols-2">
<div>

```bash
$ spack dependents zlib
==> Dependents of zlib
  boost   curl   git   hdf5
  libpng  mesa   python  ...
```

<div class="muted text-sm mt-2">Conan, vcpkg, apt, Homebrew, and friends all answer the same reverse query. Spack is just the example.</div>

<div v-click="1" class="mt-3 card card-accent">
Real, precise, and <strong>resolver-aware</strong> - a package manager knows the
exact build graph it resolves.
</div>

</div>
<div>

<div v-click="2">

### But each only sees its own recipes.

<v-clicks at="3">

- Opt-in: a project exists here only if **someone wrote a recipe** for that manager.
- Most C++ software in the world is **never packaged**, in any of them.
- The managers **disagree**, rename (`py-`…), and split packages differently.
- Any one of them is a shallow, distorted slice of real usage.

</v-clicks>

</div>

</div>
</div>

<!--
Package managers give a *true* answer to a *small* question, and this is not a
Spack problem: Conan, vcpkg, apt, and the rest all share it. C and C++ have no
central registry the way Cargo/npm/PyPI/Go do. So the reverse question,
"who depends on this?" has no authoritative source.
-->

---

# Doesn't this already exist?

<div class="muted text-sm" style="margin:-0.2rem 0 0.2rem">Plenty of tools answer "who depends on this?" - for <em>other</em> ecosystems.</div>

| Tool | What it maps | Why it's blind to C++ |
|---|---|---|
| **deps.dev** (Google) | npm · Cargo · PyPI · Go · Maven · NuGet | No C/C++ - there's **no registry to index** |
| GitHub dependency graph / *"Used by"* | manifests & lockfiles (`go.mod`, `Cargo.lock`…) | C++ ships **no manifest it parses**; "Used by" sits empty |
| Libraries.io · Ecosyste.ms | 30+ package registries | C++ = only the opt-in **Spack/Conan/vcpkg** slice, renamed & split |
| `spack/conan/vcpkg dependents` | that manager's recipe graph | opt-in; concretizer-exact but a **tiny fraction** of real use |
| Sourcegraph · `grep` · gh code-search | raw text matches | strings, **not identity**: no scoring, no fork/vendor dedupe, no graph |
| SBOM scanners (Syft, Trivy) | what a built **binary contains** | wrong direction, needs the artifact - your deps, not your dependents |

<div v-click class="mt-1 text-center"><span class="muted">The common wall:</span> <span class="gold font-600">C++ has no registry and no universal manifest: the answer must come from the source.</span></div>

---

# Why I actually built this

<div class="cols-2 gap-8 mt-2">
<div class="card" v-click>
<div class="m-icon">🔬</div>

### The scientists
Researchers I work with kept asking one simple thing: **is anyone actually using
my library?** Nobody could give them an answer.

</div>
<div class="card" v-click>
<div class="m-icon">💥</div>

### The broken builds
I kept making local changes that **broke Spack packages downstream** of the ones I
maintained, with no way to see who I was about to break easily.

</div>
</div>

<div v-click class="mt-6 text-center lead-in">
Interrogating the package manager made the first pass straightforward. <span class="gold font-600">The rest of the problem was hard.</span>
</div>

<!--
Two real reasons, not a grand vision. Scientists I support wanted to know whether
their libraries mattered to anyone, and I kept breaking downstream Spack packages
and wanted to see the blast radius first. Spack answered the easy hop. Everything
past that, the unpackaged world, was the hard part, and that is what this tool is.
-->

---

# Three reasons this is worth the trouble

<div class="motiv">

<div class="card" v-click>
<div class="m-icon">🛡️</div>

### Supply chain
When a small library has a vulnerability, **who is exposed?** You cannot patch,
warn, or triage exposure you can't see.

</div>

<div class="card" v-click>
<div class="m-icon">📈</div>

### Impact & funding
"Who uses this?" is the question behind **every grant, every headcount, every
'is this still worth maintaining?'** Reach in code *and* in the literature that
cites it.

</div>

<div class="card" v-click>
<div class="m-icon">🧨</div>

### Blast radius
**Hyrum's Law**: with enough users, *every* observable behavior gets depended on.
So who actually breaks when you change one? Dependents turn a guess into a
checkable list.

</div>

</div>

<div v-click class="mt-6 lead-in text-center">
All three are the <span class="gold">same</span> question: <em>who depends on me?</em>
</div>

<!--
Security triage, sustainability and reach, and knowing what your own changes will
break: three audiences, but every one reduces to the dependents graph. On the
last one, Hyrum's Law is the punchline: with enough users, someone depends on
every observable behavior you have, so "is this change safe?" is unanswerable
until you can see who your users actually are. One computation answers all three.
-->

---
layout: section
index: 2
---

<span class="eyebrow">Dependencies</span>

# A quick coverage of a solved problem

How do we find *dependencies*?

---
layout: statement
---

<span class="eyebrow">The short answer</span>

# You shouldn't have to
<p></p>

You should **know your dependencies**


<div v-click class="faint mt-6 text-base">
…and yet, handed an unfamiliar project, we still have to go looking. So ... where?
</div>

<!--
Half-joke, half-plea. Statically linking the same big dependency into every
binary in your graph, undeclared, is how you end up here. But in practice we're
often handed a project we know nothing about. So we ask: where do deps live?
-->

---

# Where a project *consumes* its dependencies

<div class="cols-2 gap-6 tight-list">
<div>

<v-clicks>

- <span class="chip">manifests</span> `conanfile` · `vcpkg.json` · Spack env · `requirements`
- <span class="chip">containers</span> Docker images - scrape the layers
- <span class="chip">build system</span> `find_package` · linker lines · FetchContent / ExternalProject · pkg-config · CPS
- <span class="chip">VCS</span> git submodules

</v-clicks>

</div>
<div>

<v-clicks>

- <span class="chip">compile / link lines</span> the ground truth - <span class="faint">but we rarely get to see them</span>
- <span class="chip gold">C++ itself</span> how the code actually reaches for a library:
  - `#include` headers
  - `import` **modules**
  - `#pragma comment(lib, …)`
  - plugin architectures
  - namespaces <span class="faint">(flakey, very hard to extract)</span>

</v-clicks>

</div>
</div>

<div v-click class="mt-2 card card-accent">
The build system <strong>feeds the compiler</strong>; the code <strong>names the library</strong>.
Both leave traces we can read.
</div>

<!--
This is the menu of places dependency intent is recorded. Note the split:
build/manifest layer vs the source layer. We'll exploit both.
-->

---

# "Just interrogate the binary"

<div class="cols-2 items-center gap-8">
<div>

```text
$ ldd ./app
  libssl.so.3  => ...
  libz.so.1    => ...
  libstdc++.so.6 => ...
```

```text
$ nm -D ./app | c++filt
  deflate
  SSL_connect
  ...
```

</div>
<div>

<v-clicks>

- SO names and symbols are **generic**: `libz`, `deflate`, `SSL_*`.
- It needs the **built artifact**, per platform, per config.
- Maps a symbol back to *a* provider, not *your* provider.

</v-clicks>

</div>
</div>

<!--
Binary interrogation is real evidence (it's the strongest layer!), but as a
discovery method at corpus scale it's impractical and ambiguous. We want text we
can search across millions of repos, not binaries we'd have to build.
-->

---
layout: section
index: 3
---

<span class="eyebrow">Dependents</span>

# Now the relfection

Dependencies → **dependents.** This is where it gets weird.

---
clicks: 2
---

# The reflection

<div class="cols-2 items-center">
<div class="center-col">

<GraphFlip :step="Math.min($clicks,1)" />

</div>
<div>

<div v-click="1">

Flip a dependency graph and suddenly there's no way to obtain this information

</div>

<div v-click="2" class="mt-4 card card-accent">
Searching for consumers of <span class="mono gold">foo</span> means
</div>

</div>
</div>

<!--
The satisfying part and the terrifying part in one move. Finding dependencies is
local; finding dependents is global. It's not an engineering problem so much as
a time-and-access problem.
-->

---
layout: statement
---

# <span class="grey">Needle</span> meet <span class="gold">haystack.</span>

<p>Less a complex engineering problem, more <strong> an exercise in thoroughness </strong></p>

<!--
Be honest with the audience: the clever part is NOT the algorithm. The core is
brute force. Because "who depends on me" is inherently a search over all code,
there is no closed-form shortcut. The engineering is all in doing that search
tractably and honestly.
-->

---

# Can we shrink the haystack?

<div class="lead-in" style="max-width:64ch">There's too much hay, we need a smaller haystack... or maybe a magnet
<em></em>
</div>

<div class="mt-8 center-col">
<div class="text-2xl font-700">Five potential approaches, and a wall.</div>
<div class="faint mt-1">Each buys something. None of them buys <span class="gold">completeness</span>.</div>
</div>

<!--
Set up the series: every reasonable instinct for bounding the corpus. Walk them
in order of how "structured" the signal is. The meter on each slide shows the
same truth from a different angle - you can prune a lot and still see very little.
-->

---

# Magnet 1 - Package managers

<span class="eyebrow">Shrink to what's packaged</span>

<div class="cols-2 gap-6 mt-2">
<div>

**The idea**: enumerate consumers straight from the managers' own recipe graphs. A finite, closed set you can just walk.

```bash
spack dependents zfp
conan list --graph …
vcpkg depend-info zfp
```

</div>
<div>

**The catch**
- Opt-in - someone had to *write the recipe*
- Spack · Conan · vcpkg disagree, rename (`py-…`), split
- **Most C++ is never packaged - anywhere**

</div>
</div>

<div class="mt-5"><ScopeMeter :reach="8" reach-label="packaged software" miss-label="everything unpackaged" verdict="finite - but a sliver" /></div>

<!--
The most obvious lever, and the one everyone reaches for. It gives a real,
enumerable set - but it's the smallest slice, and it's the slice least
representative of how C++ is actually consumed in the wild.
-->

---

# Magnet 2 - Build systems

<span class="eyebrow">Shrink to declared builds</span>

<div class="cols-2 gap-6 mt-2">
<div>

**The idea**: only look at repos whose build actually *wires the dependency to the linker*. That's specific, greppable syntax.

```cmake
find_package(ZFP)         # CMake
bazel_dep(name = "zfp")   # Bazel
dependency('zfp')         # Meson
```

</div>
<div>

**The catch**
- You still have to **scan every repo** to find these files
- A dozen build systems, each with its own dialect
- **Vendored** and **header-only** consumers declare nothing

</div>
</div>

<div class="mt-5"><ScopeMeter :reach="42" reach-label="projects with declared builds" miss-label="vendored · header-only · ad-hoc" verdict="specific - but the scan is unbounded" /></div>

<!--
Build files are where dependencies really get wired, so the signal is strong. But
"restrict to repos with build files" doesn't shrink the scan - you must read
everything to discover which repos even qualify. And the messiest consumers skip
the build system entirely.
-->

---

# Magnet 3 - Package config files

<span class="eyebrow">Shrink to the config layer · CPS · pkg-config · CMake config</span>

<div class="cols-2 gap-6 mt-2">
<div>

**The idea**: the installed-package *description* layer: machine-readable, build-tool-agnostic identity, designed to be parsed.

```text
libzfp.pc         # pkg-config / pkgconf
zfpConfig.cmake   # CMake config-mode
zfp.cps           # CPS - the emerging cross-tool standard
```

</div>
<div>

**The catch**
- Describes **providers**, not who consumes them
- **CPS is brand-new**: minimal adoption yet; pkg-config is Unix-centric
- `FetchContent` / submodule users emit **none of it**
- None of them solve needing to read every repo

</div>
</div>

<div class="mt-5"><ScopeMeter :reach="18" reach-label="standard-config consumers" miss-label="new standard · thin adoption" verdict="precise - but sparse" /></div>

<!--
The most structured signal of all, and the direction the ecosystem is slowly
heading (CPS especially). But structure lives on the provider/install side, and
adoption is thin - so today it's precise where present and absent almost
everywhere.
-->

---

# Magnet 4 - Everything else

<span class="eyebrow">The long tail of clever ideas</span>

<div class="two-col-list mt-2">

- **Docker image layers**: only what ships in a runtime
- **Published SBOMs · GitHub dependency graph**: only if someone uploaded one
- **GitHub code-search API**: rate-limited, shallow, GitHub-only
- **Binary / symbol indexes**: need the built artifact; names are generic
- **Downloads · telemetry**: executables only, and only if instrumented

</div>

<div class="mt-4"><ScopeMeter :reach="55" reach-label="union of every lens above" miss-label="private · unindexed · silent" verdict="broader - still never complete" /></div>

<!--
Even the union of every partial source has a hard ceiling: private code, whatever
isn't indexed, and the silent majority. Each also brings its own access tax
(rate limits, needing built artifacts, needing an upload to have happened).
-->

---

# Magnet 5 - O(1) 

<span class="eyebrow"></span>

<div class="cols-2 gap-6 items-center mt-2">
<div>

Push a major breaking change with no warning at 2:58 AM on a random Tuesday.

**Wait.**

</div>
<div>

<ScopeMeter :reach="96" reach-label="angry developers breaking down your door" miss-label="the polite ones, silently migrating away" verdict="100% recall · 0 friends" />

</div>
</div>

<div v-click class="mt-6 lead-in text-center">
Every filter leaks. So we stop magnet fishing the haystack ... and <span class="gold">search all of it, precisely.</span> &rarr;
</div>

<!--
The punchline, then the pivot. The honest conclusion of the whole series: none of
these bounds the problem without gutting completeness, because "who depends on me"
is inherently a search over everything. So we embrace the search - and spend all
our cleverness on aiming it. Straight into Part 4.
-->

---
layout: section
index: 4
---

<span class="eyebrow">Part four</span>

# Searching the haystack

Using the structure of C++ to define the search.

---
clicks: 8
---

# Observe: the identifier *set*

<div v-click="0" class="lead-in text-center" style="max-width: 62ch; margin: 0 auto 0.2rem;">
One library does <strong>not</strong> have one name. It exposes a <em>bag</em> of
loosely-related identifiers - and consumers reach for different ones.
</div>

<IdentifierBag :step="$clicks" />

<div v-click="8" class="card card-accent" style="max-width: 74ch; margin: 0.2rem auto 0; text-align:center;">
So we <strong>read the provider's own files</strong>, learn every identifier,
and record each with a <span class="gold">kind</span>, a
<span class="gold">provenance</span>, and a <span class="gold">weight</span>.
</div>

<!--
Walk the ring: target, package name, header path, header basename, module,
pkg-config/-l, repo URL, registry alias. They diverge constantly. Guessing one
token is unreliable; observing the whole set is the central design decision.
-->

---

# C++ structure *is* our search plan

<div class="muted text-sm" style="margin:-0.3rem 0 0.35rem">Each way the <strong class="gold">provider</strong> publishes itself maps to the exact line a <strong class="gold">consumer</strong> writes to reach for it.</div>

<FacetPairs :step="$clicks" />

<div v-click="6" class="mt-2 lead-in text-center">
One combined regex, one <strong>streaming</strong> search over the global index, then classify every hit back to its kind.
</div>

<!--
This table is the heart of the method. The surrounding syntax - find_package(),
Namespace::, a GIT_REPOSITORY url - is what makes a match specific. Modules
matter because a modules consumer emits NO #include; an include-only tool misses
them entirely.
-->

---

# We don't clone the world, we query it

<div class="muted text-sm" style="margin:-0.3rem 0 0.4rem">The whole approach rests on a <strong class="gold">high-availability index of public source</strong>. Today that backend is <strong>Sourcegraph</strong>.</div>

<div class="cols-2 gap-6 tight-list">
<div>

### What Sourcegraph gives us
<v-clicks>

- A continuously updated index of **millions of public repos**, already cloned and parsed.
- **Regex search** across all of it in a single query.
- A **streaming API** (SSE): hits arrive as they are found, no pagination dance.
- `fork:no`, repo metadata, and file paths: enough to dedupe and attribute a match.

</v-clicks>

</div>
<div>

### Why it carries the method
<v-clicks>

- The "brute force" only works because **someone already crawled the corpus**.
- One combined regex per provider becomes **one bounded query**, not a fleet of clones.
- The same endpoint powers the **IDF probes**: rarity is just a capped match count.
- It is one adapter behind our interface, so an **internal index drops in** the same way.

</v-clicks>

</div>
</div>

<div v-click class="mt-4 lead-in text-center">
No private corpus of our own: <span class="gold">we rent the haystack and bring the magnet.</span>
</div>

<!--
This is the honest core of the "boring" claim. We are not the ones who indexed
the world; Sourcegraph did. We lean on a high-availability code search that has
already cloned and parsed millions of public repositories, hand it one regex per
provider over a streaming API, and let rarity probes ride the same endpoint. It
is also just one backend behind a small interface, so a shop with its own
internal index or forge can swap it in without touching the rest.
-->

---

# Where the structure thins out, heuristics take over

<div class="cols-2 gap-6">
<div>

### High context → strong signal
<v-clicks>

- `find_package(ZFP)`: the call names the intent.
- `zfp::zfp`: the `::` is specific to how *this* library publishes.
- A `GIT_REPOSITORY` URL: **unambiguous.** One true identifier.

</v-clicks>

</div>
<div>

### Low context → we're guessing
<v-clicks>

- A bare `#include <config.h>`: whose config?
- A lone basename that collides with half of GitHub.
- **Namespaces in code**: sometimes a tell, usually noise, very hard to attribute.

</v-clicks>

<div v-click class="mt-3 card card-accent text-sm">
The strata where C++ gives the compiler <em>less</em> context are exactly where
our search devolves into <span class="gold">heuristics</span> - so we treat them
as weak, not wrong.
</div>

</div>
</div>

<!--
The honest symmetry: the more surrounding syntax C++ requires, the more specific
our match. Where C++ is permissive (bare includes, namespaces), we lose
attribution power and must lean on scoring instead of certainty.
-->

---

# A wide net catches noise, so we score, we don't discard

<div class="cols-3 mt-2">

<div class="card" v-click>
<h3>① IDF specificity gating</h3>
<p>Drop tokens too common to attribute - but <strong>only low-context ones</strong>
(bare basenames, project name). Never gate <span class="mono">find_package</span>,
targets, or URLs: a popular <span class="mono">find_package(GTest)</span> is
<em>real</em> dependents, not noise.</p>
</div>

<div class="card" v-click>
<h3>② Corroboration</h3>
<p class="mono text-sm gold" style="margin:0 0 0.3rem">score = strongest + 1.5·(layers−1) + min(log₁₀ hits, 2)</p>
<p>Bonus per <em>independent evidence layer</em> (source · build · registry · binary),
not per repeated hit. <span class="tier-high">high</span> ≥ 5.5,
<span class="tier-med">med</span> ≥ 3.0. An <code>#include</code>
<strong>and</strong> a <code>find_package</code> <strong>and</strong> a
<code>::</code> target &rarr; <span class="tier-high">high</span>; one lone
basename &rarr; <span class="tier-low">low</span>. Prose-only is forced
<span class="tier-low">low</span>.</p>
</div>

<div class="card" v-click>
<h3>③ Relationship, not deletion</h3>
<p>A copy is not a user. Label edges <span class="mono">DEPENDS_ON</span> /
<span class="mono">VENDORED</span> / <span class="mono">MIRROR</span>.
<strong>Keep and label - never drop.</strong></p>
</div>

</div>

<div v-click class="mt-4 lead-in text-center">
Precision comes from <span class="gold">scoring and labeling</span>, not from throwing away recall.
</div>

<!--
The three guards that make a deliberately noisy search trustworthy. The key
insight in #1: frequency-gating a build-system token would penalize a library
for being popular, which is backwards. Popularity there means real usage.
-->

---
clicks: 8
---

# The pipeline, end to end

<PipelineFlow :step="$clicks" />

<div v-click="8" class="mt-5 cols-3 text-sm">
<div class="card"><span class="gold font-600">Observe</span><br/>read provider files → identifiers</div>
<div class="card"><span class="orange font-600">Search</span><br/>one regex, streamed over the corpus</div>
<div class="card" style="border-left:3px solid #6EE7A8"><span style="color:#6EE7A8" class="font-600">Emit</span><br/>graph + SPDX + honesty report</div>
</div>

<!--
Breadth-first crawl: seed the root, find its dependents, optionally recurse to
depth N. Each node runs this ordered pipeline. Everything is one Python file,
one dependency (requests), all over plain HTTP - no database, no cloning.
-->

---

# A partial answer must never look like a complete one

<div class="cols-2 gap-6">
<div>

<v-clicks>

- Two people, same audit, **same graph**: except where live data changed.
- Every dropped request, truncated search, and hit cap is a **structured diagnostic.**
- Bounded steps are **deterministic**: rank *then* truncate, in a fixed order.

</v-clicks>

</div>
<div>

<div v-click>

```json
"completeness": {
  "complete": false,
  "warnings": [
    "discovery: results truncated
       for provider 'boost'",
    "citations: 3 nodes incomplete
       (rate_limited)"
  ]
}
```

</div>

<div v-click class="mt-3 card card-accent text-sm">
A rate-limited crawl is reported as <span class="gold">INCOMPLETE</span> -
never disguised as "no more results."
</div>

</div>
</div>

<!--
This is the integrity spine of the tool. A brute-force search that silently
drops 30% of results under rate limiting would quietly lie. So every truncation
is recorded and rolled up into one honest verdict.
-->

---
layout: section
index: 05
---

<span class="eyebrow">Part five</span>

# Beyond the code

Impact you can't see in a build graph.

---

# Measuring scholarly impact, carefully

<div class="cols-2 gap-6">
<div>

<v-clicks>

- **Seminal DOI**: the project's *own* paper (JOSS, `CITATION.cff`, Zenodo).
- **Citing DOIs**: a bounded reverse-citation crawl: *who cites the paper?*
- Every DOI is **relevance-scored**, not blindly attached.

</v-clicks>

</div>
<div>

<div v-click class="card card-accent">

### The colliding-name trap
`zfp` is also a term in an unrelated science.
A bare keyword hit **can't** clear <span class="tier-low">low</span> on its own -
it needs corroboration: shared **authors**, **venue**, **concepts**, terms.

<div class="faint mt-2 text-sm">How a paper was found is the strongest signal:
a reverse-citation of your own paper ≫ a bare keyword match.</div>

</div>

</div>
</div>

<!--
Same philosophy as the code side: provenance-weighted, corroborated, scored, and
honest about ambiguity. The zfp-is-also-a-protein problem is the citation-world
analog of a colliding header basename.
-->

---

# What comes out

<div class="cols-3 mt-2">

<div class="card" v-click>
<h3>Dependency graph</h3>
<p>One JSON of <strong>nodes</strong> + <strong>edges</strong>. Every edge carries
its evidence, identifiers, provenance, confidence tier, and relationship. Sort,
filter, drill in.</p>
</div>

<div class="card" v-click>
<h3>SPDX 2.3 SBOMs</h3>
<p>One SBOM snippet per edge, pinned to exact commit SHAs. Ingestible by
compliance and security tooling - publishable to GitHub's "used by."</p>
</div>

<div class="card" v-click>
<h3>Completeness verdict</h3>
<p>One <span class="mono">complete</span> flag + sorted warnings. The run tells
you how much of the truth it actually saw.</p>
</div>

</div>

<div v-click class="mt-4 lead-in text-center">
…and a dashboard renders it all. Here it is on a real library. &darr;
</div>

---
clicks: 3
---

# The output, live

<div class="dash-slide-grid">
<div class="center-col">

<DashboardView :step="99" />

</div>
<div>

<div class="lead-in" style="margin-bottom:0.7rem">
<span class="mono gold">zfp</span> - a compression library most people have
never heard of - sits under a remarkable amount of software.
</div>

<v-clicks>

<div class="card" style="padding:0.6rem 0.8rem">
<span class="gold font-700 text-lg">507</span> dependents ·
<span class="gold font-700 text-lg">459</span> orgs ·
<span class="gold font-700 text-lg">69</span> papers
</div>

<div class="card" style="padding:0.6rem 0.8rem">
<strong>Google</strong>, <strong>Microsoft</strong>, <strong>Godot</strong>,
<strong>Blender</strong>, <strong>Open3D</strong> - none of which any registry
would have told <span class="mono">zfp</span> about.
</div>

<div class="card" style="padding:0.6rem 0.8rem">
<span class="gold">Leaf</span> = an end-user app · click any node →
its <strong>SPDX 2.3</strong> snippet, pinned to a commit.
</div>

</v-clicks>

</div>
</div>

<div class="faint text-xs mt-1 text-center">Live: corsa.center/dashboard/explore/dependents</div>

<!--
This is the payoff slide. Real data, recognizable names. The point lands on its
own: a "small" scientific library is load-bearing for engines, DCC tools, and
big-vendor toolchains - none of which any registry would have told zfp about.
-->

---

# The graph behind the list

<div class="dash-slide-grid">
<div class="center-col">

<img src="/zfp-network-graph.png" class="graph-img" alt="zfp dependents network graph" />

</div>
<div>

<div class="lead-in" style="margin-bottom:0.7rem">Same data, drawn as the inverted tree the crawl actually walks.</div>

<v-clicks>

- <span class="legend-dot red" /> <strong>zfp</strong> - the root you searched for
- <span class="legend-dot blue" /> each spoke = a <strong>real dependent</strong> repository
- The far cluster is a dependent that is <em>itself</em> a hub - the crawl went <strong>a level deeper</strong> (depth 2)
- <span class="faint">Exported straight from the dashboard - this is the actual output.</span>

</v-clicks>

</div>
</div>

<!--
The list tab answers "who," this answers "what shape." Point out the second hub:
that's a dependent with its own dependents - the BFS, made visible. Note this PNG
is a real export from the live tool, not a mock-up.
-->

---

# Three ways to run it

<div class="cols-3 mt-2">

<div class="card" v-click>
<h3>① CLI</h3>

```bash
python audit_dependents.py \
  --repo LLNL/zfp --name zfp \
  --depth 1 --out graph.json \
  --sg-token … --gh-token …
```

<p class="faint text-sm mt-1">One file, one dependency (<code>requests</code>).
Plain HTTP - no clone, no DB.</p>
</div>

<div class="card" v-click>
<h3>② GitHub Action</h3>

```yaml
- uses: johnwparent/dependent-audit@v1
  with:
    root_repo: LLNL/zfp
    project_name: zfp
    max_depth: 1
    upload_artifact: true
```

<p class="faint text-sm mt-1">Drop it in CI. Emits the graph + SPDX as build
artifacts on every release.</p>
</div>

<div class="card" v-click>
<h3>③ Microservice</h3>

```http
POST /audit        → { job_id }
GET  /jobs/{id}     → status
GET  /jobs/{id}/graph
GET  /jobs/{id}/spdx
```

<p class="faint text-sm mt-1">Flask + worker in a Docker image. Queue a job,
poll it, pull the graph - this is what feeds the dashboard.</p>
</div>

</div>

<div v-click class="mt-4 lead-in text-center">
Same engine underneath: <span class="gold">a script, a CI step, or a service.</span>
</div>

<!--
The three delivery modes from the OVERVIEW. Note the Action inputs are the real
ones (root_repo, project_name, max_depth, upload_artifact); the service routes
are the real endpoints (POST /audit → poll /jobs/{id} → GET graph & spdx).
-->

---
layout: section
index: 06
---

<span class="eyebrow">Part six</span>

# So, what is this thing?

---

# What the tool actually is

<div class="cols-2 gap-8 mt-2">
<div class="card" v-click>
<div class="m-icon">🔌</div>

### A modular interface to a source scraper
The C++ plugin is one implementation. **Roll your own backend** for a private
corpus (say, your **50k internal repos**) so the dev you've never met doesn't
walk to your desk because you broke payroll.

</div>
<div class="card" v-click>
<div class="m-icon">📚</div>

### An optional publications miner
Attach the scholarly record when it exists: impact in **code and citations**.

</div>
</div>

<div v-click class="mt-6 statement-ish center-col">
<div class="text-2xl font-700">It builds a tree by BFS, but the tree is <span class="gold">conceptually inverted.</span></div>
<div class="lead-in mt-1">We find dependents. Then dependents of dependents.</div>
</div>

<!--
The reusable core is the scraper interface + the identifier/scoring engine. The
C++ ecosystem plugin and the citation engine are swappable modules on top.
Internal-corpus use is a first-class use case, not an afterthought.
-->

---

# Honest limits

<div class="two-col-list">

<v-clicks>

- **Public code only**: no private/internal usage without credentials.
- **Two backends wired up today**: Sourcegraph for the search, GitHub for metadata. The source interface is pluggable, so pointing it at your own internal index or forge is a small adapter, not a rewrite.
- **Intent, not linkage**: a match shows *intent to use*, not a shipped binary.
- **Bounded by the index**: very popular providers can exceed result limits (…and we say so).
- **Thin in, thin out**: unconventional layouts yield fewer identifiers.
- **Confidence, not ground truth**: high-confidence edges are very likely real; low ones are *leads for a human.*

</v-clicks>

</div>

<div v-click class="mt-5 card card-accent">
The design goal is <span class="gold">graceful degradation</span>: no single weak
or missing signal is ever decisive.
</div>

<!--
Say these out loud. Credibility at CppCon comes from naming the boundaries
before the Q&A does. The tool is a confidence engine, not an oracle.
-->

---
layout: statement
transition: fade
---

<span class="eyebrow">Takeaway</span>

# Understand your dependents <br/><span class="gold">and understand your ecosystem impact.</span>

<p>Finding who <span class="mono">#include</span>s you is a search - so search the
world's code, aim it with the structure of C++, and <strong>score what you can't be sure of.</strong></p>

---
layout: statement
---

<span class="eyebrow">Get it</span>

# It's open source.

<div class="mt-6 center-col">
<div class="text-2xl font-700">Run it on your own library.</div>
<a class="mono gold text-3xl mt-3" href="https://github.com/corsa-center/dependent-audit">github.com/corsa-center/dependent-audit</a>
<div class="lead-in mt-2">A GitHub Action, a CLI, and a pluggable source interface.</div>
</div>

<!--
Point people at the repo. Part of the CORSA Center (corsa-center) org. The C++
plugin ships today; the source interface is the extension point for your own corpus.
-->

---
layout: end
---

# Thank you.

<div class="text-xl mt-2">Who Is <span class="gold mono">#include</span>-ing You?</div>
<div class="lead-in mt-1">Measuring the Impact of C++ Libraries</div>

<div class="mt-8 cols-2 gap-8 text-base">
<div>

**John Parent** · Kitware
`john.parent@kitware.com`

</div>
<div>

<span class="faint">Questions welcome - beware of answers</span>

</div>
</div>

<!--
Close on the takeaway and open for questions. Expect: "what about private code?",
"how do you handle header-only libs?", "isn't this just grep?" - yes, gloriously,
at planetary scale, with a scoring model bolted on.
-->
