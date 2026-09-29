<script setup lang="ts">
import { useNav } from '@slidev/client'

const { currentPage, total } = useNav()
</script>

<template>
  <footer v-if="$slidev.nav.currentLayout !== 'cover' && $slidev.nav.currentLayout !== 'section' && $slidev.nav.currentLayout !== 'statement' && $slidev.nav.currentLayout !== 'end'"
          class="cpp-footer">
    <div class="cpp-footer-left">
      <CppConMark :size="20" />
      <span class="cpp-footer-title">Who Is <span class="mono">#include</span>-ing You?</span>
    </div>
    <div class="cpp-footer-right">
      <span class="faint">CppCon 2026</span>
      <span class="cpp-pageno">{{ currentPage }} / {{ total }}</span>
    </div>
  </footer>
</template>

<style>
.cpp-footer {
  position: absolute;
  left: 0; right: 0; bottom: 0;
  height: 2.1rem;
  padding: 0 1.4rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-family: var(--cpp-font-body);
  font-size: 0.7rem;
  color: var(--cpp-faint);
  border-top: 1px solid var(--cpp-line);
  background: linear-gradient(180deg, transparent, rgba(10, 15, 28, 0.35));
  z-index: 5;
}
.cpp-footer-left { display: flex; align-items: center; gap: 0.55rem; }
.cpp-footer-title { color: var(--cpp-mute); letter-spacing: 0.01em; }
.cpp-footer-title .mono { color: var(--cpp-gold); }
.cpp-footer-right { display: flex; align-items: center; gap: 0.9rem; }
.cpp-pageno {
  font-family: var(--cpp-font-mono);
  color: var(--cpp-orange);
  border: 1px solid var(--cpp-line-strong);
  border-radius: 999px;
  padding: 0.05rem 0.5rem;
}
</style>
