# Front door: nginx serving the built SPA and proxying /api to the web tier.
# Build context is the repo root (see docker-compose.yml) so the frontend can
# read ../udg_schema.json if it regenerates types.

# --- build the SPA -----------------------------------------------------------
FROM node:22-alpine AS ui
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
COPY udg_schema.json /src/udg_schema.json
RUN npm run build

# --- serve -------------------------------------------------------------------
FROM nginx:1.27-alpine
COPY deploy/nginx/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=ui /src/frontend/dist /usr/share/nginx/html
