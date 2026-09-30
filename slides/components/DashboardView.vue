<script setup lang="ts">
// A faithful, in-theme recreation of the live dashboard at
// corsa.center/dashboard/explore/dependents - real zfp data.
const props = defineProps<{ step?: number }>()

const rows = [
  { pkg: 'godot',    owner: 'godotengine', type: 'L1', stars: '107,283' },
  { pkg: 'vcpkg',    owner: 'microsoft',   type: 'L2', stars: '26,696', leaf: true },
  { pkg: 'filament', owner: 'google',      type: 'L1', stars: '19,728' },
  { pkg: 'blender',  owner: 'blender',     type: 'L2', stars: '17,634', leaf: true },
  { pkg: 'bgfx',     owner: 'bkaradzic',   type: 'L2', stars: '16,806', leaf: true },
  { pkg: 'Open3D',   owner: 'isl-org',     type: 'L2', stars: '13,362', leaf: true },
]
const shown = (i: number) => (props.step ?? rows.length) >= i
</script>

<template>
  <div class="dash">
    <!-- faux browser chrome -->
    <div class="chrome">
      <span class="dot r" /><span class="dot y" /><span class="dot g" />
      <div class="url">corsa.center/dashboard/explore/dependents</div>
    </div>

    <div class="dash-body">
      <!-- header -->
      <div class="dash-head">
        <div>
          <div class="dh-name">zfp <span class="dh-i">ⓘ</span></div>
          <div class="dh-sub">Compressed numerical arrays that support high-speed random access</div>
        </div>
        <div class="dash-stats">
          <div class="stat"><div class="stat-n">507</div><div class="stat-l">dependents</div></div>
          <div class="stat"><div class="stat-n">459</div><div class="stat-l">organizations</div></div>
        </div>
      </div>

      <!-- tabs -->
      <div class="tabs">
        <div class="tab active">Dependents List</div>
        <div class="tab">Network Graph</div>
        <div class="tab">Citations</div>
      </div>

      <!-- table -->
      <table class="dtable">
        <thead>
          <tr><th>Package</th><th>Owner</th><th>Type</th><th class="num">Stars</th></tr>
        </thead>
        <tbody>
          <tr v-for="(r, i) in rows" :key="r.pkg" class="drow" :class="{ show: shown(i) }">
            <td>
              <span class="pkg">{{ r.pkg }}</span>
              <span v-if="r.leaf" class="leaf">Leaf</span>
            </td>
            <td class="owner">{{ r.owner }}</td>
            <td><span class="typ">{{ r.type }}</span></td>
            <td class="num">★ {{ r.stars }}</td>
          </tr>
        </tbody>
      </table>
      <div class="more">Showing 6 of 507 dependents · click any row → SPDX 2.3 snippet</div>
    </div>
  </div>
</template>

<style scoped>
.dash {
  width: 560px;
  border-radius: 12px;
  overflow: hidden;
  border: 1px solid var(--cpp-line-strong);
  background: #0C1322;
  box-shadow: 0 24px 60px -28px rgba(0, 0, 0, 0.8);
}
.chrome {
  display: flex; align-items: center; gap: 0.5rem;
  padding: 0.5rem 0.8rem;
  background: #0A0F1B;
  border-bottom: 1px solid var(--cpp-line);
}
.dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
.dot.r { background: #ff6159; } .dot.y { background: #ffbd2e; } .dot.g { background: #28c840; opacity: 0.85; }
.url {
  margin-left: 0.5rem;
  font-family: var(--cpp-font-mono);
  font-size: 0.72rem;
  color: var(--cpp-mute);
  background: #131c30;
  border: 1px solid var(--cpp-line);
  border-radius: 6px;
  padding: 0.12rem 0.7rem;
  flex: 1;
}
.dash-body { padding: 0.9rem 1.1rem 1rem; }
.dash-head { display: flex; align-items: flex-start; justify-content: space-between; }
.dh-name { font-family: var(--cpp-font-display); font-weight: 800; font-size: 1.5rem; color: #fff; }
.dh-i { color: #5b9bff; font-size: 0.9rem; }
.dh-sub { font-size: 0.74rem; color: var(--cpp-mute); margin-top: 0.1rem; }
.dash-stats { display: flex; gap: 1.6rem; text-align: right; }
.stat-n { font-family: var(--cpp-font-display); font-weight: 800; font-size: 1.6rem; color: var(--cpp-orange); line-height: 1; }
.stat-l { font-size: 0.66rem; color: var(--cpp-mute); text-transform: lowercase; }

.tabs { display: flex; gap: 1.3rem; margin: 0.7rem 0 0.2rem; border-bottom: 1px solid var(--cpp-line); }
.tab { font-size: 0.82rem; color: var(--cpp-mute); padding: 0.3rem 0; }
.tab.active { color: #fff; border-bottom: 2px solid var(--cpp-orange); font-weight: 600; }

.dtable { width: 100%; border-collapse: collapse; }
.dtable th {
  text-align: left; font-family: var(--cpp-font-body); font-weight: 600;
  font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--cpp-faint); border-bottom: 1px solid var(--cpp-line);
  padding: 0.4rem 0.4rem;
}
.dtable th.num, .dtable td.num { text-align: right; }
.drow {
  opacity: 0; transform: translateY(6px);
  transition: opacity 0.3s ease, transform 0.3s ease;
}
.drow.show { opacity: 1; transform: translateY(0); }
.dtable td {
  padding: 0.34rem 0.4rem;
  border-bottom: 1px solid rgba(255,255,255,0.05);
  font-size: 0.82rem;
}
.pkg { color: #5b9bff; font-weight: 600; }
.leaf {
  margin-left: 0.4rem; font-size: 0.6rem; color: #6EE7A8;
  border: 1px solid rgba(110,231,168,0.4); border-radius: 4px; padding: 0.02rem 0.28rem;
}
.owner { color: var(--cpp-mute); font-family: var(--cpp-font-mono); font-size: 0.76rem; }
.typ { color: var(--cpp-mute); font-family: var(--cpp-font-mono); font-size: 0.72rem; border: 1px solid var(--cpp-line); border-radius: 4px; padding: 0.02rem 0.3rem; }
.num { color: var(--cpp-gold); font-family: var(--cpp-font-mono); font-size: 0.78rem; }
.more { font-size: 0.68rem; color: var(--cpp-faint); margin-top: 0.5rem; text-align: center; }
</style>
