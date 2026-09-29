<script setup lang="ts">
// The core conceptual move of the talk: a dependency graph, turned upside down,
// becomes a *dependents* graph. Shown as a 3D flip (deps -> dependents), then
// both halves fused into the full bowtie with YOU as the knot in the middle.
const props = defineProps<{ step?: number }>()
const flipped = () => (props.step ?? 0) >= 1
const bowtie = () => (props.step ?? 0) >= 2
</script>

<template>
  <div class="gf-stage">
    <!-- steps 0-1: the flip card -->
    <div class="flip-scene" :class="{ gone: bowtie() }">
      <div class="flip-inner" :class="{ flipped: flipped() }">
        <!-- FRONT: you, and the things you depend on -->
        <div class="face front">
          <div class="face-cap">
            <span class="eyebrow">what you know</span>
            <h3>Your dependencies</h3>
          </div>
          <svg viewBox="0 0 420 250" class="g">
            <defs>
              <marker id="ah" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                <path d="M0 0 L6 3 L0 6 Z" fill="var(--cpp-mute)" />
              </marker>
            </defs>
            <g stroke="var(--cpp-mute)" stroke-width="1.6" marker-end="url(#ah)" fill="none" opacity="0.8">
              <line x1="210" y1="58" x2="90" y2="176" />
              <line x1="210" y1="58" x2="210" y2="176" />
              <line x1="210" y1="58" x2="330" y2="176" />
            </g>
            <g class="node you"><circle cx="210" cy="46" r="26" /><text x="210" y="50">YOU</text></g>
            <g class="node dep"><circle cx="78" cy="196" r="20" /><text x="78" y="200">libpng</text></g>
            <g class="node dep"><circle cx="210" cy="196" r="20" /><text x="210" y="200">zlib</text></g>
            <g class="node dep"><circle cx="342" cy="196" r="20" /><text x="342" y="200">fmt</text></g>
          </svg>
          <div class="face-note">You declared these. You can list them in seconds.</div>
        </div>

        <!-- BACK: the things that depend on you (pre-rotated so it reads upright) -->
        <div class="face back">
          <div class="face-cap">
            <span class="eyebrow gold-eye">the hard question</span>
            <h3>Your <span class="gold">dependents</span></h3>
          </div>
          <svg viewBox="0 0 420 250" class="g">
            <defs>
              <marker id="ah2" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                <path d="M0 0 L6 3 L0 6 Z" fill="var(--cpp-orange)" />
              </marker>
            </defs>
            <g stroke="var(--cpp-orange)" stroke-width="1.6" marker-end="url(#ah2)" fill="none" opacity="0.85">
              <line x1="46" y1="52" x2="196" y2="182" />
              <line x1="140" y1="46" x2="204" y2="182" />
              <line x1="232" y1="46" x2="216" y2="182" />
              <line x1="330" y1="52" x2="224" y2="182" />
              <line x1="384" y1="60" x2="232" y2="182" />
            </g>
            <g class="node root"><circle cx="44" cy="42" r="17" /></g>
            <g class="node root"><circle cx="140" cy="34" r="17" /></g>
            <g class="node root"><circle cx="232" cy="34" r="17" /></g>
            <g class="node root"><circle cx="330" cy="42" r="17" /></g>
            <g class="node root"><circle cx="388" cy="52" r="17" /></g>
            <g class="node you hot"><circle cx="210" cy="200" r="26" /><text x="210" y="204">YOU</text></g>
          </svg>
          <div class="face-note">N roots, one leaf, and nobody handed you the list.</div>
        </div>
      </div>
    </div>

    <!-- step 2: the full bowtie, YOU as the knot -->
    <div class="bowtie" :class="{ show: bowtie() }">
      <div class="face-cap">
        <span class="eyebrow gold-eye">the whole picture</span>
        <h3>You are the <span class="gold">knot</span> in the bowtie</h3>
      </div>
      <svg viewBox="0 0 460 356" class="bg">
        <defs>
          <marker id="bin" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0 0 L6 3 L0 6 Z" fill="var(--cpp-orange)" />
          </marker>
          <marker id="bout" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0 0 L6 3 L0 6 Z" fill="var(--cpp-mute)" />
          </marker>
        </defs>

        <!-- fan-in: dependents point down into YOU -->
        <g stroke="var(--cpp-orange)" stroke-width="1.6" marker-end="url(#bin)" fill="none" opacity="0.85">
          <line x1="44" y1="62" x2="210" y2="150" />
          <line x1="137" y1="56" x2="220" y2="150" />
          <line x1="230" y1="54" x2="230" y2="150" />
          <line x1="323" y1="56" x2="240" y2="150" />
          <line x1="416" y1="62" x2="250" y2="150" />
        </g>
        <!-- fan-out: YOU points down into dependencies -->
        <g stroke="var(--cpp-mute)" stroke-width="1.6" marker-end="url(#bout)" fill="none" opacity="0.8">
          <line x1="224" y1="210" x2="104" y2="292" />
          <line x1="230" y1="210" x2="230" y2="292" />
          <line x1="236" y1="210" x2="356" y2="292" />
        </g>

        <text x="8" y="20" class="lbl in">dependents · who needs you</text>
        <text x="8" y="348" class="lbl out">dependencies · what you need</text>

        <!-- dependents (roots) -->
        <g class="node root"><circle cx="44" cy="46" r="16" /></g>
        <g class="node root"><circle cx="137" cy="40" r="16" /></g>
        <g class="node root"><circle cx="230" cy="38" r="16" /></g>
        <g class="node root"><circle cx="323" cy="40" r="16" /></g>
        <g class="node root"><circle cx="416" cy="46" r="16" /></g>

        <!-- YOU: the pinch point -->
        <g class="node you hot"><circle cx="230" cy="180" r="28" /><text x="230" y="184">YOU</text></g>

        <!-- dependencies -->
        <g class="node dep"><circle cx="96" cy="310" r="18" /><text x="96" y="314">libpng</text></g>
        <g class="node dep"><circle cx="230" cy="310" r="18" /><text x="230" y="314">zlib</text></g>
        <g class="node dep"><circle cx="364" cy="310" r="18" /><text x="364" y="314">fmt</text></g>
      </svg>
      <div class="face-note">Fan-in of dependents, fan-out of dependencies. This talk computes the <span class="gold">top half</span>.</div>
    </div>
  </div>
</template>

<style scoped>
.gf-stage {
  position: relative;
  width: 470px;
  height: 360px;
}
.flip-scene {
  position: absolute;
  inset: 0;
  perspective: 1600px;
  transition: opacity 0.5s ease;
}
.flip-scene.gone { opacity: 0; pointer-events: none; }
.flip-inner {
  position: relative;
  width: 100%; height: 340px;
  transform-style: preserve-3d;
  transition: transform 1.1s cubic-bezier(0.6, 0.02, 0.2, 1);
}
.flip-inner.flipped { transform: rotateX(180deg); }
.face {
  position: absolute;
  inset: 0;
  backface-visibility: hidden;
  display: flex;
  flex-direction: column;
  align-items: center;
  border-radius: 14px;
  border: 1px solid var(--cpp-line);
  background: rgba(255, 255, 255, 0.025);
  padding: 0.8rem 1rem 1rem;
}
.back { transform: rotateX(180deg); }

.bowtie {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  border-radius: 14px;
  border: 1px solid var(--cpp-line);
  background: rgba(255, 255, 255, 0.025);
  padding: 0.8rem 1rem 1rem;
  opacity: 0;
  transform: scale(0.96);
  transition: opacity 0.55s ease, transform 0.55s ease;
  pointer-events: none;
}
.bowtie.show { opacity: 1; transform: scale(1); pointer-events: auto; }

.face-cap { text-align: center; }
.face-cap h3 { margin: 0.1rem 0 0; font-size: 1.25rem; }
.gold-eye { color: var(--cpp-gold); }
.g, .bg { width: 100%; flex: 1; }
.node text {
  font-family: var(--cpp-font-mono);
  font-size: 11px;
  fill: #fff;
  text-anchor: middle;
  font-weight: 600;
}
.node.you circle { fill: #35456F; stroke: #fff; stroke-width: 2; }
.node.you.hot circle { fill: var(--cpp-orange); stroke: var(--cpp-gold); stroke-width: 2.5; filter: drop-shadow(0 0 10px rgba(255,137,51,0.6)); }
.node.dep circle { fill: #26304b; stroke: var(--cpp-mute); stroke-width: 1.5; }
.node.root circle { fill: #2b3a5f; stroke: var(--cpp-orange); stroke-width: 1.5; }
.lbl { font-family: var(--cpp-font-mono); font-size: 10px; letter-spacing: 0.03em; }
.lbl.in { fill: var(--cpp-gold); }
.lbl.out { fill: var(--cpp-mute); }
.face-note {
  font-size: 0.86rem;
  color: var(--cpp-mute);
  text-align: center;
}
</style>
