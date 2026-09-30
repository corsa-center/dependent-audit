<template>
  <div class="slidev-layout cpp-statement">
    <div class="stmt-body">
      <slot />
    </div>
  </div>
</template>

<style scoped>
.cpp-statement {
  display: flex;
  align-items: center;
  justify-content: center;
  text-align: center;
  background-image:
    radial-gradient(ellipse 70% 70% at 50% 46%, var(--cpp-navy-glow) 0%, var(--cpp-navy-800) 46%, var(--cpp-navy-900) 100%);
}
.stmt-body { max-width: 74%; }
.stmt-body :deep(h1) {
  font-size: 3rem;
  line-height: 1.12;
}
.stmt-body :deep(h1::after) { margin: 0.8rem auto 0; }
.stmt-body :deep(p) {
  color: var(--cpp-mute);
  font-size: 1.3rem;
  margin-top: 1rem;
}
.stmt-body :deep(strong) { color: var(--cpp-gold); }
</style>
