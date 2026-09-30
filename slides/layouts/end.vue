<template>
  <div class="slidev-layout cpp-end">
    <div class="end-corner">
      <span class="corner-plus">+</span>
      <span class="corner-26">26</span>
    </div>
    <div class="end-body">
      <slot />
    </div>
    <div class="end-brand">
      <CppConMark :size="40" />
      <span>CppCon 2026 · John Parent · Kitware</span>
    </div>
  </div>
</template>

<style scoped>
.cpp-end {
  display: flex;
  align-items: center;
  background-image:
    radial-gradient(ellipse 80% 70% at 50% 40%, var(--cpp-navy-glow) 0%, var(--cpp-navy-700) 42%, var(--cpp-navy-900) 100%);
}
.end-body { max-width: 80%; padding-left: 2%; }
.end-corner {
  position: absolute;
  top: 0; right: 0;
  width: 20%; height: 20%;
  background: var(--cpp-orange);
  clip-path: polygon(42% 0, 100% 0, 100% 58%);
}
.corner-26 {
  position: absolute; top: 12%; right: 10%;
  font-family: var(--cpp-font-display); font-weight: 800;
  font-size: 2.6rem; color: var(--cpp-navy-900); line-height: 1;
}
.corner-plus {
  position: absolute; top: 26%; right: 48%;
  font-family: var(--cpp-font-display); font-weight: 800;
  font-size: 2.4rem; color: rgba(255,255,255,0.6); line-height: 1;
}
.end-brand {
  position: absolute;
  left: 3%; bottom: 6%;
  display: flex; align-items: center; gap: 0.7rem;
  color: var(--cpp-mute); font-size: 0.9rem;
}
</style>
