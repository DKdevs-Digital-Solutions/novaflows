FROM node:20-alpine

WORKDIR /app

# Instala apenas dependências de produção
COPY package*.json ./
RUN npm ci --omit=dev

# Copia apenas o servidor (frontend é servido separadamente)
COPY server/ ./server/

ENV NODE_ENV=production
ENV PORT=3001

EXPOSE 3001

CMD ["node", "server/index.js"]
