FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig*.json nest-cli.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
# Trivy pulls images straight from the registry, so no Docker daemon is needed inside the container.
# Pinned so every build scans with the same Trivy version; bump it deliberately.
COPY --from=aquasec/trivy:0.76.2 /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
EXPOSE 3000
CMD ["node", "dist/main"]
