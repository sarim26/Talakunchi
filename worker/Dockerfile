FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache nmap nmap-scripts

COPY package.json package-lock.json* ./
RUN npm install

COPY tsconfig.json ./
COPY src ./src

CMD ["npm","run","dev"]

