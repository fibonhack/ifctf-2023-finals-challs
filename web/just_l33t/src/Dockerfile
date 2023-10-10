FROM node:18 as builder_fronted

WORKDIR /app/frontend
COPY frontend/ ./
RUN npm install
RUN npm run build

FROM nginx as final
WORKDIR /davy
COPY ./nginx/nginx.conf /etc/nginx/sites-enabled/default
COPY --from=builder_fronted /app/frontend/build /usr/share/nginx/html/frontend
