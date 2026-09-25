FROM node:22-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force
COPY server.js ./
USER node
EXPOSE 8081
HEALTHCHECK --interval=15s --timeout=3s CMD wget -qO- http://127.0.0.1:8081/_bridge/health || exit 1
CMD ["node", "server.js"]
