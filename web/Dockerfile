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

# nginx fourni par Alpine (suivi et corrigé par la distribution), lancé directement sous
# l'utilisateur « nginx » : aucun processus root, écoute sur 8080.
FROM alpine:3.24 AS runtime
RUN apk add --no-cache nginx \
    && apk upgrade --no-cache
COPY web/nginx.conf /etc/nginx/nginx.conf
COPY --from=build /web/dist /usr/share/nginx/html
USER nginx
EXPOSE 8080
# -e : journal d'erreurs sur la sortie du conteneur dès le démarrage (rien n'est écrit sur disque).
CMD ["nginx", "-e", "/dev/stderr", "-g", "daemon off;"]
