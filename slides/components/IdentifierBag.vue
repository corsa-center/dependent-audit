<script setup lang="ts">
// One library, many names. The "bag" of identifiers a provider exposes -
// each of which a consumer might reference, and which rarely agree.
const props = defineProps<{ step?: number }>()

const ids = [
  { x: 22, y: 14, name: 'find_package(ZFP)', kind: 'cmake package', s: 'med' },
  { x: 50, y: 8,  name: 'zfp::zfp',           kind: 'exported target', s: 'high' },
  { x: 78, y: 14, name: 'import zfp;',        kind: 'C++20 module', s: 'med' },
  { x: 91, y: 50, name: 'LLNL/zfp',           kind: 'repo URL', s: 'high' },
  { x: 78, y: 86, name: 'libzfp',             kind: 'pkg-config / -l', s: 'med' },
  { x: 50, y: 92, name: 'zfp.h',              kind: 'header basename', s: 'low' },
  { x: 22, y: 86, name: 'zfp/array.hpp',      kind: 'header path', s: 'med' },
  { x: 9,  y: 50, name: 'py-zfp',             kind: 'registry alias', s: 'low' },
]
const on = (i: number) => (props.step ?? ids.length) > i
</script>

<template>
  <div class="bag">
    <svg class="spokes" viewBox="0 0 100 100" preserveAspectRatio="none">
      <line v-for="(d, i) in ids" :key="i"
            x1="50" y1="50" :x2="d.x" :y2="d.y"
            :class="['spoke', d.s, { show: on(i) }]" />
    </svg>

    <div class="core">
      <div class="core-name">zfp</div>
      <div class="core-sub">LLNL · compression</div>
    </div>

    <div v-for="(d, i) in ids" :key="i"
         class="idchip" :class="[d.s, { show: on(i) }]"
         :style="{ left: d.x + '%', top: d.y + '%' }">
      <span class="idname mono">{{ d.name }}</span>
      <span class="idkind">{{ d.kind }}</span>
    </div>
  </div>
</template>

<style scoped>
.bag { position: relative; width: 640px; height: 292px; margin: 0.2rem auto; }
.spokes { position: absolute; inset: 0; width: 100%; height: 100%; }
.spoke {
  stroke-width: 0.4;
  stroke-dasharray: 2 2;
  opacity: 0;
  transition: opacity 0.4s ease;
  vector-effect: non-scaling-stroke;
}
.spoke.show { opacity: 0.55; }
.spoke.high { stroke: #6EE7A8; }
.spoke.med { stroke: var(--cpp-gold); }
.spoke.low { stroke: #FF8C74; }

.core {
  position: absolute;
  left: 50%; top: 50%;
  transform: translate(-50%, -50%);
  width: 134px; height: 134px;
  border-radius: 50%;
  background: radial-gradient(circle at 40% 35%, #3A4C7C, #212c49);
  border: 2px solid var(--cpp-orange);
  box-shadow: 0 0 34px -4px rgba(255, 137, 51, 0.5);
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  z-index: 3;
}
.core-name { font-family: var(--cpp-font-display); font-weight: 800; font-size: 2rem; color: #fff; }
.core-sub { font-size: 0.66rem; color: var(--cpp-mute); letter-spacing: 0.04em; }

.idchip {
  position: absolute;
  transform: translate(-50%, -50%) scale(0.9);
  display: flex; flex-direction: column; align-items: center;
  padding: 0.34rem 0.6rem;
  border-radius: 9px;
  background: rgba(16, 24, 44, 0.92);
  border: 1px solid var(--cpp-line-strong);
  opacity: 0;
  transition: opacity 0.45s ease, transform 0.45s ease;
  z-index: 2;
  white-space: nowrap;
}
.idchip.show { opacity: 1; transform: translate(-50%, -50%) scale(1); }
.idname { font-size: 0.82rem; color: #fff; }
.idkind { font-size: 0.6rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--cpp-mute); }
.idchip.high { border-color: #6EE7A8; }
.idchip.high .idname { color: #9defc0; }
.idchip.med { border-color: rgba(253,176,64,0.6); }
.idchip.low { border-color: rgba(255,140,116,0.55); }
</style>
