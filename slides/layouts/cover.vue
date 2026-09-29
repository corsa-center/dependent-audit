<template>
  <div class="slidev-layout cpp-cover">
    <!-- orange geometric corner banner: the "C++26" motif -->
    <div class="cover-corner">
      <span class="corner-plus">+</span>
      <span class="corner-26">26</span>
    </div>

    <div class="cover-body">
      <slot />
    </div>

    <div class="cover-footer">
      <div class="cover-brand">
        <CppConMark :size="52" />
        <div class="cover-brand-txt">
          <div class="cover-brand-name">CppCon</div>
          <div class="cover-brand-sub">The C++ Conference</div>
        </div>
      </div>
      <div class="cover-date">
        <div class="cover-year"><span>20</span><span>26</span></div>
        <div class="cover-date-sep" />
        <div class="cover-mtn">
          <svg width="70" height="40" viewBox="0 0 70 40" fill="none">
            <path d="M2 38 L20 10 L30 24 L44 4 L68 38 Z" fill="#FFFFFF" />
            <path d="M35 16 L44 4 L53 16 Z" fill="#FDB040" />
          </svg>
          <div class="cover-sep-date">September 12 – 18</div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.cpp-cover {
  padding: 0;
  overflow: hidden;
}
.cover-body {
  position: absolute;
  left: 8%;
  top: 30%;
  right: 8%;
}
.cover-corner {
  position: absolute;
  top: 0;
  right: 0;
  width: 26%;
  height: 26%;
  background: var(--cpp-orange);
  clip-path: polygon(38% 0, 100% 0, 100% 62%);
  display: flex;
  align-items: flex-start;
  justify-content: flex-end;
}
.corner-26 {
  position: absolute;
  top: 6%;
  right: 8%;
  font-family: var(--cpp-font-display);
  font-weight: 800;
  font-size: 3.4rem;
  color: var(--cpp-navy-900);
  line-height: 1;
}
.corner-plus {
  position: absolute;
  top: 20%;
  right: 46%;
  font-family: var(--cpp-font-display);
  font-weight: 800;
  font-size: 3.2rem;
  color: rgba(255, 255, 255, 0.6);
  line-height: 1;
}
.cover-footer {
  position: absolute;
  left: 8%;
  right: 6%;
  bottom: 7%;
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
}
.cover-brand { display: flex; align-items: center; gap: 0.9rem; }
.cover-brand-name {
  font-family: var(--cpp-font-display);
  font-weight: 800;
  font-size: 2rem;
  color: #fff;
  line-height: 0.9;
}
.cover-brand-sub {
  font-family: var(--cpp-font-display);
  font-weight: 600;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-size: 0.62rem;
  color: var(--cpp-mute);
}
.cover-date { display: flex; align-items: center; gap: 1rem; }
.cover-year {
  display: flex;
  flex-direction: column;
  font-family: var(--cpp-font-display);
  font-weight: 800;
  font-size: 1.7rem;
  color: #fff;
  line-height: 0.92;
}
.cover-date-sep { width: 2px; height: 3rem; background: var(--cpp-line-strong); }
.cover-mtn { display: flex; flex-direction: column; align-items: center; gap: 0.2rem; }
.cover-sep-date { font-size: 0.72rem; color: var(--cpp-mute); }
</style>
