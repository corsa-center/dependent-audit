# Who Is #include-ing You? · CppCon 2026 slides

Slide deck for the talk *"Who Is #include-ing You? Measuring the Impact of C++
Libraries"* (John Parent, Kitware). Built with [Slidev](https://sli.dev).

Everything the deck needs (fonts included) is bundled locally, so it **runs
fully offline** once `npm install` has been run once (with network).

## Prerequisites

- Node.js 18+ and npm (developed on Node 23 / npm 11).
- A one-time `npm install` **while online**: this downloads Slidev and the
  self-hosted fonts. After that, no network is required.

## Install (do this once, online)

```bash
cd slides
npm install
```

## Present (offline)

The normal way to give the talk. Works with no network connection:

```bash
npm run present        # slidev, no auto-open
# or
npm run dev            # same, but opens the browser automatically
```

Then open <http://localhost:3030> (Slidev's default port).

Useful keys while presenting:

- **→ / Space**: next step (advances click-animations, then next slide)
- **← **: back
- **f**: fullscreen
- **o**: slide overview
- **p**: presenter mode (speaker notes + timer + next-slide preview) at
  <http://localhost:3030/presenter/>. Speaker notes are written under most
  slides in `slides.md`.

> The deck relies on click-driven animations (the tower, the graph flip, the
> identifier ring, the pipeline). Advance with **→ / Space** rather than jumping
> by slide number so the build-ups play.

## Offline static build (backup)

Produces a self-contained static site in `dist/` (handy as a fallback, or to
copy onto a machine that will never see the network):

```bash
npm run build          # outputs dist/ with base "./"
npx serve dist         # or any static file server; then open the printed URL
```

## Export to PDF (optional)

Requires a one-time online step to fetch a headless browser
(`npm i -D playwright-chromium`):

```bash
npm run export         # writes slides-export.pdf
```

## Project layout

```
slides.md              the deck (content + per-slide frontmatter + speaker notes)
styles/
  index.ts             imports the self-hosted fonts, then theme.css
  theme.css            the CppCon navy/orange theme (colors, typography, helpers)
layouts/
  cover.vue            title slide (recreates the official CppCon title art)
  section.vue          part dividers (big outlined numeral)
  statement.vue        full-bleed statement slides
  end.vue              closing slide
components/
  CppConMark.vue       the circular "#" CppCon mark (SVG)
  StackTower.vue       the dependency-tower build (homage to xkcd #2347)
  GraphFlip.vue        dependencies → dependents 3D flip
  IdentifierBag.vue    the radial "identifier set" for zfp
  PipelineFlow.vue     the end-to-end pipeline
  ScopeMeter.vue       recurring "search-space" bar for the shrink-the-haystack series
  DashboardView.vue    in-theme recreation of the live corsa.center dashboard
                       (real zfp data: 507 dependents / 459 orgs)
global-bottom.vue      the persistent footer (title · CppCon 2026 · page)
public/
  cppcon-title-slide.png   reference art the theme is derived from
  zfp-network-graph.png    real radial dependents graph exported from the dashboard
```

## Theming

The palette and type are derived from the official title slide and live as CSS
variables at the top of `styles/theme.css`:

- navy field `#121A30 → #3E5488` (radial), orange `#FF8933`, gold `#FDB040`
- display/heading font **Barlow Semi Condensed**, body **Barlow**, code
  **JetBrains Mono**: all self-hosted via `@fontsource/*` (no Google Fonts, no
  network at present-time).

The illustration on the "tower of dependencies" slide is an **original** drawing
in the spirit of xkcd #2347; the comic itself is not reproduced.
