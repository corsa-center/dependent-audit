import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Dev: `npm run dev` serves the SPA and proxies /api to a local Flask app
// (JOBS_DIR=$PWD/.jobs python deploy/service/app.py). SSE streams through the
// proxy unbuffered. Production: nginx serves dist/ and proxies /api itself.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: process.env.API_TARGET ?? "http://localhost:8000", changeOrigin: false },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
