<script setup lang="ts">
defineProps<{ index?: string }>()
</script>

<template>
  <div class="slidev-layout cpp-section">
    <div class="sec-corner" />
    <div class="sec-body">
      <div v-if="index" class="sec-index">{{ index }}</div>
      <div class="sec-content">
        <slot />
      </div>
    </div>
  </div>
</template>

<style scoped>
.cpp-section {
  display: flex;
  align-items: center;
  background-image:
    radial-gradient(ellipse 70% 80% at 22% 50%, var(--cpp-navy-glow) 0%, var(--cpp-navy-700) 46%, var(--cpp-navy-900) 100%);
}
.sec-corner {
  position: absolute;
  top: 0; right: 0;
  width: 16%; height: 16%;
  background: var(--cpp-orange);
  clip-path: polygon(46% 0, 100% 0, 100% 54%);
}
.sec-body { display: flex; align-items: center; gap: 1.6rem; max-width: 82%; }
.sec-index {
  font-family: var(--cpp-font-display);
  font-weight: 800;
  font-size: 6.5rem;
  color: transparent;
  -webkit-text-stroke: 2px var(--cpp-orange);
  line-height: 0.8;
  opacity: 0.9;
}
.sec-content :deep(h1) {
  font-size: 3.1rem;
  margin: 0;
}
.sec-content :deep(h1::after) { display: none; }
.sec-content :deep(p) {
  color: var(--cpp-mute);
  font-size: 1.25rem;
  margin-top: 0.6rem;
  max-width: 34ch;
}
.sec-content :deep(.eyebrow) { margin-bottom: 0.4rem; }
</style>
