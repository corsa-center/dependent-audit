<script setup lang="ts">
// Simplified re-creation of the CppCon circular "#" mark for offline use.
defineProps<{ size?: number }>()
</script>

<template>
  <svg :width="size ?? 40" :height="size ?? 40" viewBox="0 0 100 100" fill="none" aria-label="CppCon">
    <circle cx="50" cy="50" r="46" fill="#151E36" stroke="#FFFFFF" stroke-width="5" />
    <g stroke="#FFFFFF" stroke-width="7.5" stroke-linecap="round">
      <line x1="34" y1="30" x2="27" y2="70" />
      <line x1="60" y1="30" x2="53" y2="70" />
      <line x1="26" y1="43" x2="70" y2="43" />
      <line x1="24" y1="58" x2="68" y2="58" />
    </g>
    <circle cx="72" cy="34" r="6.5" fill="#FF8933" />
  </svg>
</template>
