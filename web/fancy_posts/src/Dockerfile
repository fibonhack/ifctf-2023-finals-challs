# == FRONTEND =============================================================
FROM node:18 as build
WORKDIR /app

COPY frontend/package*.json ./
RUN npm ci --omit=dev

COPY /frontend .
RUN npm run build

# === BACKEND ============================================================
FROM node:18 as final

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY db/ db/
COPY src/ src/
COPY index.js .
COPY --from=build /app/build/ /app/public/

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=15s --start-period=5s --retries=3 CMD curl -f http://localhost:3000/health || exit 1
CMD [ "node", "index.js" ]
