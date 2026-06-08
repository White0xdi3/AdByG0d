# AdByG0d Web — Production Dockerfile
# Build context must be the repo root (monorepo workspace)

# --- builder: install all deps and build Next.js ---
FROM node:26-alpine AS builder
WORKDIR /workspace

COPY package.json package-lock.json ./
RUN npm ci

COPY apps/web/ ./apps/web/

ENV NEXT_TELEMETRY_DISABLED=1

# NEXT_PUBLIC_* vars are baked into the JS bundle at build time.
# Pass --build-arg NEXT_PUBLIC_API_URL=<url> (or docker compose build.args).
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}

WORKDIR /workspace/apps/web
RUN npm run build

# --- runner: minimal production image ---
FROM node:26-alpine AS runner
WORKDIR /workspace

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 nextjs

COPY --from=builder --chown=nextjs:nodejs /workspace/node_modules ./node_modules
COPY --from=builder --chown=nextjs:nodejs /workspace/apps/web/.next ./apps/web/.next
COPY --from=builder --chown=nextjs:nodejs /workspace/apps/web/public ./apps/web/public
COPY --chown=nextjs:nodejs package.json ./
COPY --chown=nextjs:nodejs apps/web/package.json ./apps/web/

USER nextjs

WORKDIR /workspace/apps/web

ENV PORT=3000
ENV PATH="/workspace/node_modules/.bin:${PATH}"

EXPOSE 3000

CMD ["next", "start"]
