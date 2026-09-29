<script setup lang="ts">
// Each structural facet of C++, shown as a pair: what the *provider* ships,
// and the exact line a *consumer* writes to reach for it.
const props = defineProps<{ step?: number }>()

const rows = [
  {
    facet: 'Headers', kind: 'source', kc: '#7FA8FF',
    prov: ['zfp/array.hpp'], provTag: 'ships the header',
    cons: ['#include <zfp/array.hpp>'], tier: 'high',
    note: 'bare basename  #include <zfp.h>  drops to low',
  },
  {
    facet: 'C++20 modules', kind: 'source', kc: '#7FA8FF',
    prov: ['export module zfp;'], provTag: 'declares a module',
    cons: ['import zfp;'], tier: 'med',
    note: 'no #include at all, so an include-only search misses it',
  },
  {
    facet: 'CMake', kind: 'build', kc: '#FDB040',
    prov: ['install(EXPORT zfpTargets', '        NAMESPACE zfp::)'], provTag: 'exports a target',
    cons: ['find_package(ZFP)', 'target_link_libraries(app zfp::zfp)'], tier: 'high',
    note: '',
  },
  {
    facet: 'pkg-config', kind: 'build', kc: '#FDB040',
    prov: ['libzfp.pc'], provTag: 'installs a .pc',
    cons: ['pkg_check_modules(ZFP libzfp)', '-lzfp'], tier: 'med',
    note: '',
  },
  {
    facet: 'Repository', kind: 'vcs', kc: '#6EE7A8',
    prov: ['github.com/LLNL/zfp'], provTag: 'is the source',
    cons: ['.gitmodules', 'FetchContent(GIT_REPOSITORY …)'], tier: 'high',
    note: 'the one unambiguous identifier',
  },
]
const on = (i: number) => (props.step ?? rows.length) > i
</script>

<template>
  <div class="fp">
    <div class="fp-head">
      <div />
      <div class="col-tag">Provider ships</div>
      <div />
      <div class="col-tag">Consumer writes</div>
      <div class="col-tag right">Signal</div>
    </div>

    <div v-for="(r, i) in rows" :key="r.facet" class="fp-row" :class="{ show: on(i) }">
      <div class="fp-facet">
        <span class="kbar" :style="{ background: r.kc }" />
        <span>
          <span class="facet-name">{{ r.facet }}</span>
          <span class="facet-kind">{{ r.kind }}</span>
        </span>
      </div>

      <div class="code prov">
        <div v-for="(l, k) in r.prov" :key="k" class="cline">{{ l }}</div>
        <div class="tag">{{ r.provTag }}</div>
      </div>

      <div class="arrow">→</div>

      <div class="code cons">
        <div v-for="(l, k) in r.cons" :key="k" class="cline">{{ l }}</div>
      </div>

      <div class="fp-tier">
        <span class="pill" :class="'t-' + r.tier">{{ r.tier }}</span>
      </div>

      <div v-if="r.note" class="fp-note">{{ r.note }}</div>
    </div>
  </div>
</template>

<style scoped>
.fp { max-width: 980px; margin: 0 auto; font-family: var(--cpp-font-mono); }
.fp-head, .fp-row {
  display: grid;
  grid-template-columns: 148px minmax(180px, 1fr) 24px minmax(230px, 1.15fr) 60px;
  align-items: center;
  column-gap: 0.6rem;
}
.fp-head {
  padding: 0 0.2rem 0.3rem;
  border-bottom: 1px solid var(--cpp-line-strong);
  margin-bottom: 0.2rem;
}
.col-tag {
  font-family: var(--cpp-font-display);
  font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.1em;
  color: var(--cpp-faint);
}
.col-tag.right { text-align: right; }

.fp-row {
  padding: 0.28rem 0.2rem;
  border-bottom: 1px solid var(--cpp-line);
  opacity: 0; transform: translateY(6px);
  transition: opacity 0.35s ease, transform 0.35s ease;
}
.fp-row.show { opacity: 1; transform: translateY(0); }

.fp-facet { display: flex; align-items: center; gap: 0.5rem; }
.kbar { width: 4px; height: 1.7rem; border-radius: 2px; flex: none; }
.facet-name { font-family: var(--cpp-font-display); font-weight: 700; font-size: 0.98rem; color: #fff; display: block; line-height: 1.1; }
.facet-kind { font-size: 0.6rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--cpp-mute); }

.code { font-size: 0.8rem; line-height: 1.35; }
.cline { color: var(--cpp-text); white-space: nowrap; }
.code.prov .cline { color: var(--cpp-mute); }
.code.cons .cline { color: var(--cpp-gold-soft); }
.tag { font-size: 0.62rem; color: var(--cpp-faint); margin-top: 0.05rem; font-family: var(--cpp-font-body); }

.arrow { color: var(--cpp-orange); font-size: 1.1rem; text-align: center; }

.fp-tier { text-align: right; }
.pill {
  font-family: var(--cpp-font-display);
  font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.06em;
  padding: 0.08rem 0.45rem; border-radius: 999px; border: 1px solid currentColor;
}
.t-high { color: #6EE7A8; }
.t-med { color: var(--cpp-gold); }
.t-low { color: #FF8C74; }

.fp-note {
  grid-column: 2 / 6;
  font-family: var(--cpp-font-body);
  font-size: 0.68rem;
  color: var(--cpp-faint);
  margin-top: 0.15rem;
}
</style>
