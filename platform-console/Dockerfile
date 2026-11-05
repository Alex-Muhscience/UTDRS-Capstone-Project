# Build the static app.
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
# Empty: the app calls /api on its own origin, which nginx proxies to the gateway.
ARG VITE_API_URL=
ENV VITE_API_URL=${VITE_API_URL}
RUN npm run build

# Serve it with nginx as a non-root user, on port 8080.
FROM nginxinc/nginx-unprivileged:1.30-alpine
ENV GATEWAY_URL=http://api-gateway:8000
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY nginx-security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1
