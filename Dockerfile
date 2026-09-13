FROM node:24-bookworm-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:24-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
RUN groupadd --system --gid 10001 proxy && useradd --system --uid 10001 --gid proxy --home-dir /app proxy
COPY --from=build --chown=proxy:proxy /app/package.json ./package.json
COPY --from=build --chown=proxy:proxy /app/node_modules ./node_modules
COPY --from=build --chown=proxy:proxy /app/dist ./dist
RUN mkdir /app/data && chown proxy:proxy /app/data
USER proxy
EXPOSE 3000
VOLUME ["/app/data"]
CMD ["node", "dist/index.js"]
