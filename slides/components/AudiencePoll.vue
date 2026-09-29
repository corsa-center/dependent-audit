<script setup lang="ts">
// A live "show of hands" poll. A quiet audience grid; on click the hands that
// would go up shoot up and glow. Used twice, back to back, so the room full of
// raised hands (dependencies) contrasts with near silence (dependents).
const props = defineProps<{
  step?: number
  raised?: number      // fraction of the room that raises a hand (0..1)
  caption?: string     // the punchline revealed after the hands settle
}>()

const COLS = 12
const ROWS = 5
const N = COLS * ROWS
const frac = props.raised ?? 0.5

// Deterministic scatter: hash each seat, raise it if it falls under the target
// fraction. Same seats every render, evenly spread across the room.
const seats = Array.from({ length: N }, (_, i) => {
  const h = Math.abs(Math.sin(i * 12.9898 + 4.1) * 43758.5453) % 1
  return { i, up: h < frac }
})

const on = (i: number) => (props.step ?? 9) > i
</script>

<template>
  <div class="poll">
    <div class="crowd" :class="{ live: on(0) }">
      <span
        v-for="s in seats"
        :key="s.i"
        class="seat"
        :class="{ up: s.up && on(0) }"
      >{{ s.up && on(0) ? '&#9995;' : '&#128100;' }}</span>
    </div>

    <div v-if="caption" class="cap" :class="{ show: on(1) }">
      <span class="cap-mark" />
      <span>{{ caption }}</span>
    </div>
  </div>
</template>

<style scoped>
.poll { margin-top: 1.4rem; }

.crowd {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 0.35rem 0.2rem;
  max-width: 760px;
}
.seat {
  font-size: 1.5rem;
  line-height: 1;
  text-align: center;
  color: var(--cpp-faint);
  opacity: 0.5;
  filter: grayscale(1);
  transform: translateY(4px);
  transition: transform 0.4s cubic-bezier(0.34, 1.56, 0.64, 1), opacity 0.4s ease, color 0.4s ease;
}
.seat.up {
  color: var(--cpp-orange);
  opacity: 1;
  filter: none;
  transform: translateY(-8px);
  text-shadow: 0 0 14px rgba(255, 137, 51, 0.55);
}

.cap {
  display: flex;
  align-items: center;
  gap: 0.7rem;
  margin-top: 1.6rem;
  font-family: var(--cpp-font-display);
  font-weight: 700;
  font-size: 1.5rem;
  color: var(--cpp-gold);
  opacity: 0;
  transform: translateY(8px);
  transition: opacity 0.45s ease, transform 0.45s ease;
}
.cap.show { opacity: 1; transform: translateY(0); }
.cap-mark {
  width: 2.6rem;
  height: 4px;
  border-radius: 3px;
  background: linear-gradient(90deg, var(--cpp-orange), var(--cpp-gold));
  flex: none;
}
</style>
