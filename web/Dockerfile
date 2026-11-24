# Contexte de build : la racine du dépôt.

FROM node:lts-alpine AS deps
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-fund --no-audit

FROM deps AS test
COPY web ./
CMD ["sh", "-c", "npm run lint && npm run typecheck && npm test"]

FROM deps AS build
COPY web ./
RUN npm run build

# nginx sans privilèges : tourne sous un utilisateur ordinaire et écoute sur 8080.
FROM nginxinc/nginx-unprivileged:stable-alpine AS runtime
COPY web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /web/dist /usr/share/nginx/html
EXPOSE 8080
