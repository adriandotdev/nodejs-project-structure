#Pull node latest version, current version 21 as of 11/30/2023
FROM node:21.6.2-alpine3.18 AS build_stage

WORKDIR /app

COPY package*.json .

RUN npm install --production

COPY . .

FROM node:21.6.2-alpine3.18 AS production_build

WORKDIR /var/www/pnc

COPY --from=build_stage /app /app/

# Environment Variables
ENV PORT=4001

#Install PM2
RUN npm install -g pm2@latest

#Image port
EXPOSE 4001

#Script to start apps (specific setup of pm2)
CMD [ "pm2-runtime", "start" , "./ecosystem.config.js" ]
