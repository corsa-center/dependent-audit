<script setup lang="ts">
const props = defineProps<{ step?: number }>()
const stages = [
  { n: '01', t: 'Compile identifier set', d: 'read the provider’s own files', k: 'observe' },
  { n: '02', t: 'Gate for specificity', d: 'IDF drops tokens too common to mean anything', k: 'idf' },
  { n: '03', t: 'Expand to patterns', d: 'each id → the line a consumer writes', k: 'observe' },
  { n: '04', t: 'Stream-search the corpus', d: 'one regex, SSE over Sourcegraph', k: 'search' },
  { n: '05', t: 'Classify each match', d: 'which identifier? which evidence kind?', k: 'observe' },
  { n: '06', t: 'Score & label', d: 'tier + DEPENDS_ON / VENDORED / MIRROR', k: 'score' },
  { n: '07', t: 'Corroborate', d: 'registries · GitHub metadata · citations', k: 'score' },
  { n: '08', t: 'Emit graph + SPDX', d: 'nodes, edges, SBOM, completeness verdict', k: 'out' },
]
const on = (i: number) => (props.step ?? stages.length) > i
// arrow to the right of every card except the end of each visual row (index 3, 7)
const rightArrow = (i: number) => i !== 3 && i !== 7
</script>

<template>
  <div class="pipe">
    <div v-for="(s, i) in stages" :key="i" class="cell">
      <div class="stage" :class="[s.k, { show: on(i) }]">
        <div class="stage-n mono">{{ s.n }}</div>
        <div class="stage-t">{{ s.t }}</div>
        <div class="stage-d">{{ s.d }}</div>
      </div>
      <div v-if="rightArrow(i)" class="arr arr-r" :class="{ show: on(i + 1) }">→</div>
      <div v-else-if="i === 3" class="arr arr-d" :class="{ show: on(i + 1) }">↴</div>
    </div>
  </div>
</template>

<style scoped>
.pipe {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1.5rem 2rem;
  max-width: 940px;
  margin: 0.5rem auto 0;
}
.cell { position: relative; }
.stage {
  height: 100%;
  padding: 0.7rem 0.85rem;
  border-radius: 11px;
  background: rgba(255, 255, 255, 0.035);
  border: 1px solid var(--cpp-line);
  border-top: 3px solid var(--cpp-faint);
  opacity: 0;
  transform: translateY(10px);
  transition: opacity 0.4s ease, transform 0.4s ease;
  min-height: 108px;
}
.stage.show { opacity: 1; transform: translateY(0); }
.stage.observe { border-top-color: #7FA8FF; }
.stage.idf { border-top-color: #FF8C74; }
.stage.search { border-top-color: var(--cpp-orange); }
.stage.score { border-top-color: var(--cpp-gold); }
.stage.out { border-top-color: #6EE7A8; }
.stage-n { font-size: 0.72rem; color: var(--cpp-faint); }
.stage-t { font-family: var(--cpp-font-display); font-weight: 700; font-size: 1rem; color: #fff; margin: 0.12rem 0 0.28rem; line-height: 1.12; }
.stage-d { font-size: 0.76rem; color: var(--cpp-mute); line-height: 1.3; }

.arr {
  position: absolute;
  color: var(--cpp-orange);
  font-size: 1.5rem;
  opacity: 0;
  transition: opacity 0.4s ease;
}
.arr.show { opacity: 0.85; }
.arr-r { right: -1.55rem; top: 50%; transform: translateY(-50%); }
.arr-d { right: -1.35rem; top: 50%; transform: translateY(-50%) rotate(-42deg); }
</style>
