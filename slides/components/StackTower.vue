<script setup lang="ts">
// A stack of software: your project on top, resting on layer after layer of
// things you depend on, all the way down to the physics at the bottom.
const props = defineProps<{ step?: number }>()
const step = () => props.step ?? 0

// top -> bottom. one middle block is the dependency you forgot you had.
const blocks = [
  { w: 58, label: 'your project', crown: true },
  { w: 71 }, { w: 63 }, { w: 77 },
  { w: 68, dep: true },
  { w: 73 }, { w: 60 }, { w: 69 },
]
</script>

<template>
  <div class="tower" :class="{ wobble: step() >= 3 }">
    <div class="tower-stack">
      <div
        v-for="(b, i) in blocks"
        :key="i"
        class="brick"
        :class="{
          crown: b.crown,
          dep: b.dep,
          hot: b.dep && step() >= 2,
          sad: b.crown && step() >= 3,
        }"
        :style="{
          width: b.w + '%',
          transitionDelay: (i * 55) + 'ms',
          opacity: step() >= 1 ? 1 : 0,
          transform: step() >= 1 ? 'translateY(0)' : 'translateY(-24px)',
        }"
      >
        <span v-if="b.label" class="brick-label">{{ b.label }}</span>

        <span v-if="b.dep && step() >= 1" class="tip tip-id" :class="{ 'hot-line': step() >= 2 }">
          <span class="id-line">the compression library you depend on, and forgot about</span>
          <span v-if="step() >= 2" class="ev-line">ships a breaking change</span>
        </span>
        <span v-if="b.crown && step() >= 3" class="tip tip-sad">and now you are unhappy</span>
      </div>

      <!-- it all bottoms out on physics -->
      <div
        class="brick keystone"
        :style="{
          opacity: step() >= 1 ? 1 : 0,
          transitionDelay: (blocks.length * 55) + 'ms',
        }"
      >
        <span class="tip tip-base">Hardware (below this is not my problem, usually)</span>
      </div>
    </div>
    <div class="tower-ground" />
  </div>
</template>

<style scoped>
.tower {
  display: flex;
  flex-direction: column;
  align-items: center;
  transform-origin: bottom center;
}
.tower.wobble { animation: sway 2.6s ease-in-out infinite; }
@keyframes sway {
  0%, 100% { transform: rotate(-0.7deg); }
  50% { transform: rotate(0.7deg); }
}
.tower-stack {
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 340px;
}
.brick {
  height: 26px;
  margin-bottom: 4px;
  border-radius: 4px;
  background: linear-gradient(180deg, #2E3D66, #25314f);
  border: 1px solid var(--cpp-line-strong);
  display: flex;
  align-items: center;
  justify-content: center;
  transition: opacity 0.4s ease, transform 0.4s ease, box-shadow 0.3s ease, background 0.3s ease, border-color 0.3s ease;
  position: relative;
}
.brick.crown {
  height: 34px;
  background: linear-gradient(180deg, #3A4C7C, #2c3a60);
  border-color: rgba(255,255,255,0.28);
}
.brick.crown.sad {
  background: linear-gradient(180deg, #6E3A44, #4c2732);
  border-color: #FF8C74;
  box-shadow: 0 0 22px 2px rgba(255, 140, 116, 0.4);
}
.brick.dep { border-color: rgba(253, 176, 64, 0.5); }
.brick.dep.hot {
  background: linear-gradient(180deg, var(--cpp-orange), var(--cpp-orange-deep));
  border-color: var(--cpp-gold);
  box-shadow: 0 0 26px 4px rgba(255, 137, 51, 0.55);
}
.brick-label {
  font-family: var(--cpp-font-display);
  font-weight: 700;
  font-size: 0.82rem;
  color: #fff;
  white-space: nowrap;
}
.keystone {
  width: 40px;
  height: 20px;
  background: linear-gradient(180deg, #46567f, #34426a);
}

/* callout tips off the side of a brick */
.tip {
  position: absolute;
  top: 50%;
  transform: translateY(-50%);
  white-space: nowrap;
  font-family: var(--cpp-font-mono);
  font-size: 0.72rem;
  line-height: 1.25;
}
.tip-id {
  right: 128%;
  white-space: normal;
  width: 13rem;
  text-align: right;
  border-right: 2px solid var(--cpp-faint);
  padding-right: 0.5rem;
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 0.15rem;
}
.tip-id .id-line { color: var(--cpp-mute); }
.tip-id.hot-line { border-color: var(--cpp-orange); }
.tip-id .ev-line { color: var(--cpp-gold); font-weight: 600; }
.tip-sad {
  left: 128%;
  color: #FF8C74;
  border-left: 2px solid #FF8C74;
  padding-left: 0.5rem;
  font-weight: 600;
}
.tip-base {
  left: 128%;
  color: var(--cpp-gold);
  border-left: 2px solid var(--cpp-gold);
  padding-left: 0.5rem;
}
.tower-ground {
  width: 200px;
  height: 6px;
  margin-top: 3px;
  border-radius: 3px;
  background: repeating-linear-gradient(90deg, var(--cpp-faint) 0 8px, transparent 8px 14px);
  opacity: 0.5;
}
</style>
