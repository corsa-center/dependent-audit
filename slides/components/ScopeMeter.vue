<script setup lang="ts">
import { ref, onMounted } from 'vue'
// A recurring "how much of the haystack does this method actually reach?" bar.
// `reach` is an illustrative 0–100 of the public-C++ corpus this lens can see.
const props = defineProps<{
  reach: number
  reachLabel: string
  missLabel: string
  verdict: string
}>()
const grow = ref(false)
onMounted(() => requestAnimationFrame(() => (grow.value = true)))
</script>

<template>
  <div class="scope">
    <div class="scope-head">
      <span class="scope-title">Search space · <span class="faint">all public C++</span></span>
      <span class="verdict">{{ verdict }}</span>
    </div>
    <div class="bar">
      <div class="reach" :style="{ width: (grow ? reach : 0) + '%' }" />
    </div>
    <div class="scope-labels">
      <span class="reach-l"><span class="sw reach-sw" /> {{ reachLabel }}</span>
      <span class="miss-l">{{ missLabel }} <span class="sw miss-sw" /></span>
    </div>
  </div>
</template>

<style scoped>
.scope { width: 100%; max-width: 820px; margin: 0 auto; }
.scope-head { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 0.35rem; }
.scope-title { font-family: var(--cpp-font-display); font-weight: 700; font-size: 0.9rem; color: var(--cpp-text); letter-spacing: 0.02em; }
.verdict { font-family: var(--cpp-font-mono); font-size: 0.8rem; color: var(--cpp-gold); }
.bar {
  position: relative;
  height: 26px;
  border-radius: 7px;
  overflow: hidden;
  border: 1px solid var(--cpp-line-strong);
  background-image: repeating-linear-gradient(135deg, rgba(255,255,255,0.05) 0 7px, transparent 7px 14px);
  background-color: rgba(255,255,255,0.02);
}
.reach {
  position: absolute; left: 0; top: 0; bottom: 0;
  background: linear-gradient(90deg, var(--cpp-orange), var(--cpp-gold));
  border-right: 2px solid var(--cpp-gold-soft);
  transition: width 0.9s cubic-bezier(0.5, 0, 0.2, 1);
  box-shadow: 0 0 20px -2px rgba(255, 137, 51, 0.5);
}
.scope-labels { display: flex; justify-content: space-between; margin-top: 0.3rem; font-size: 0.76rem; }
.reach-l { color: var(--cpp-gold-soft); }
.miss-l { color: var(--cpp-mute); }
.sw { display: inline-block; width: 0.7rem; height: 0.7rem; border-radius: 2px; vertical-align: middle; }
.reach-sw { background: var(--cpp-orange); }
.miss-sw { background-image: repeating-linear-gradient(135deg, var(--cpp-faint) 0 3px, transparent 3px 6px); border: 1px solid var(--cpp-line-strong); }
</style>
