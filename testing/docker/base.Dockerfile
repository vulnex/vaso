# Stage 1: Build VASO
FROM node:20-slim AS builder

WORKDIR /build

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY tsconfig.json tsup.config.ts ./
COPY src/ src/
COPY bin/ bin/

RUN npm run build

# Stage 2: Runtime
FROM node:20-slim

WORKDIR /app

COPY --from=builder /build/dist/ dist/
COPY --from=builder /build/node_modules/ node_modules/
COPY --from=builder /build/package.json package.json
COPY --from=builder /build/bin/ bin/

ENV PATH="/app/bin:${PATH}"

CMD ["node", "dist/cli.js", "scan", "--format", "json"]
