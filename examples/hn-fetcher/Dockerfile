FROM node:22-alpine

WORKDIR /usr/src/app

COPY package.json ./
RUN npm install --omit=dev

COPY app.js ./

EXPOSE 8000

CMD ["node", "/usr/src/app/app.js"]
