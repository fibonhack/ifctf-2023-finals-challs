FROM node:18-alpine as base

WORKDIR /src
COPY ./package*.json /
EXPOSE 3000

RUN npm ci
COPY ./. ./
ENTRYPOINT ["./start.sh"]